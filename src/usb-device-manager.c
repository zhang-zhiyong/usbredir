#include "config.h"
#include <glib-object.h>
#include <errno.h>
#include <libusb.h>
#include "channel-usbredir-priv.h"
#include "usbredirhost.h"
#include "usbutil.h"
#include "spice-session-priv.h"
#include "spice-client.h"
#include "spice-marshal.h"
#include "usb-device-manager-priv.h"
#include <glib/gi18n-lib.h>

/*Add cJSON related heads*/
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

#define DEV_ID_FMT "at %u.%u"
extern char *filter_flag;

/**
 * SECTION:usb-device-manager
 * @short_description: USB device management
 * @title: Spice USB Manager
 * @section_id:
 * @see_also:
 * @stability: Stable
 * @include: spice-client.h
 *
 * #SpiceUsbDeviceManager monitors USB redirection channels and USB
 * devices plugging/unplugging. If #SpiceUsbDeviceManager:auto-connect
 * is set to %TRUE, it will automatically connect newly plugged USB
 * devices to available channels.
 *
 * There should always be a 1:1 relation between #SpiceUsbDeviceManager objects
 * and #SpiceSession objects. Therefor there is no
 * spice_usb_device_manager_new, instead there is
 * spice_usb_device_manager_get() which ensures this 1:1 relation.
 */

/* ------------------------------------------------------------------ */
/* gobject glue                                                       */

#define SPICE_USB_DEVICE_MANAGER_GET_PRIVATE(obj)     (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SPICE_TYPE_USB_DEVICE_MANAGER, SpiceUsbDeviceManagerPrivate))

enum {
    PROP_0,
    PROP_SESSION,
    PROP_AUTO_CONNECT,
    PROP_AUTO_CONNECT_FILTER,
    PROP_REDIRECT_ON_CONNECT,
    PROP_FREE_CHANNELS,
};

enum
{
    DEVICE_ADDED,
    DEVICE_REMOVED,
    AUTO_CONNECT_FAILED,
    DEVICE_ERROR,
    LAST_SIGNAL,
};

struct _SpiceUsbDeviceManagerPrivate {
    SpiceSession *session;
    gboolean auto_connect;
    gchar *auto_connect_filter;
    gchar *redirect_on_connect;
    libusb_context *context;
    int event_listeners;
    GThread *event_thread;
    gint event_thread_run;
    struct usbredirfilter_rule *auto_conn_filter_rules;
    struct usbredirfilter_rule *redirect_on_connect_rules;
    int auto_conn_filter_rules_count;
    int redirect_on_connect_rules_count;
    gboolean redirecting; /* Handled by GUdevClient in the gudev case */
    libusb_hotplug_callback_handle hp_handle;
    GPtrArray *devices;
    GPtrArray *channels;
};

enum {
    SPICE_USB_DEVICE_STATE_NONE = 0, /* this is also DISCONNECTED */
    SPICE_USB_DEVICE_STATE_CONNECTING,
    SPICE_USB_DEVICE_STATE_CONNECTED,
    SPICE_USB_DEVICE_STATE_DISCONNECTING,
    SPICE_USB_DEVICE_STATE_INSTALLING,
    SPICE_USB_DEVICE_STATE_UNINSTALLING,
    SPICE_USB_DEVICE_STATE_INSTALLED,
    SPICE_USB_DEVICE_STATE_MAX
};
typedef struct _SpiceUsbDeviceInfo {
    guint8  busnum;
    guint8  devaddr;
    guint16 vid;
    guint16 pid;
    gboolean isochronous;
    libusb_device *libdev;
    gint    ref;
} SpiceUsbDeviceInfo;

static void channel_new(SpiceSession *session, SpiceChannel *channel,gpointer user_data);
static void channel_destroy(SpiceSession *session, SpiceChannel *channel,gpointer user_data);
static int spice_usb_device_manager_hotplug_cb(libusb_context *ctx,libusb_device *device,libusb_hotplug_event  event,void *data);
static void spice_usb_device_manager_check_redir_on_connect(SpiceUsbDeviceManager *self, SpiceChannel *channel);
static SpiceUsbDeviceInfo *spice_usb_device_new(libusb_device *libdev);
static SpiceUsbDevice *spice_usb_device_ref(SpiceUsbDevice *device);
static void spice_usb_device_unref(SpiceUsbDevice *device);
static gboolean spice_usb_manager_device_equal_libdev(SpiceUsbDeviceManager *manager,SpiceUsbDevice *device,libusb_device *libdev);
static libusb_device *spice_usb_device_manager_device_to_libdev(SpiceUsbDeviceManager *self,SpiceUsbDevice *device);
static void _spice_usb_device_manager_connect_device_async(SpiceUsbDeviceManager *self,SpiceUsbDevice *device,GCancellable *cancellable,GAsyncReadyCallback callback,gpointer user_data);
static void _connect_device_async_cb(GObject *gobject,GAsyncResult *channel_res,gpointer user_data);
static void disconnect_device_sync(SpiceUsbDeviceManager *self,SpiceUsbDevice *device);

G_DEFINE_BOXED_TYPE(SpiceUsbDevice, spice_usb_device,(GBoxedCopyFunc)spice_usb_device_ref,(GBoxedFreeFunc)spice_usb_device_unref)

static void _set_redirecting(SpiceUsbDeviceManager *self, gboolean is_redirecting)
{
    self->priv->redirecting = is_redirecting;
}


/**
 * spice_usb_device_manager_is_redirecting:
 * @self: the #SpiceUsbDeviceManager manager
 *
 * Checks whether a device is being redirected
 *
 * Returns: %TRUE if device redirection negotiation flow is in progress
 *
 * Since: 0.32
 */
gboolean spice_usb_device_manager_is_redirecting(SpiceUsbDeviceManager *self)
{
    return self->priv->redirecting;
}

static void spice_usb_device_manager_initable_iface_init(GInitableIface *iface);

static guint signals[LAST_SIGNAL] = { 0, };

G_DEFINE_TYPE_WITH_CODE(SpiceUsbDeviceManager, spice_usb_device_manager, G_TYPE_OBJECT,G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, spice_usb_device_manager_initable_iface_init));

static void spice_usb_device_manager_init(SpiceUsbDeviceManager *self)
{
    SpiceUsbDeviceManagerPrivate *priv;
    priv = SPICE_USB_DEVICE_MANAGER_GET_PRIVATE(self);
    self->priv = priv;
    priv->channels = g_ptr_array_new();
    priv->devices  = g_ptr_array_new_with_free_func((GDestroyNotify)spice_usb_device_unref);
	

}

static gboolean spice_usb_device_manager_initable_init(GInitable  *initable,GCancellable  *cancellable,GError  **err)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(initable);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    GList *list;
    GList *it;
    int rc;
    /* Initialize libusb */
    rc = libusb_init(&priv->context);
    if (rc < 0) {
        const char *desc = spice_usbutil_libusb_strerror(rc);
        g_warning("Error initializing USB support: %s [%i]", desc, rc);
        g_set_error(err, SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,"Error initializing USB support: %s [%i]", desc, rc);
        return FALSE;
    }

    /* Start listening for usb devices plug / unplug */
    rc = libusb_hotplug_register_callback(priv->context,
        LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
        LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
        spice_usb_device_manager_hotplug_cb, self, &priv->hp_handle);
    if (rc < 0) {
        const char *desc = spice_usbutil_libusb_strerror(rc);
        g_warning("Error initializing USB hotplug support: %s [%i]", desc, rc);
        g_set_error(err, SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,
                  "Error initializing USB hotplug support: %s [%i]", desc, rc);
        return FALSE;
    }	
    spice_usb_device_manager_start_event_listening(self, NULL);
    /* Start listening for usb channels connect/disconnect */
    spice_g_signal_connect_object(priv->session, "channel-new", G_CALLBACK(channel_new), self, G_CONNECT_AFTER);
    g_signal_connect(priv->session, "channel-destroy",G_CALLBACK(channel_destroy), self);
    list = spice_session_get_channels(priv->session);
    for (it = g_list_first(list); it != NULL; it = g_list_next(it)) {
        channel_new(priv->session, it->data, (gpointer*)self);
    }
    g_list_free(list);
    return TRUE;
}

static void spice_usb_device_manager_dispose(GObject *gobject)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    if (priv->hp_handle) {
        spice_usb_device_manager_stop_event_listening(self);
        if (g_atomic_int_get(&priv->event_thread_run)) {
            /* Force termination of the event thread even if there were some
             * mismatched spice_usb_device_manager_{start,stop}_event_listening
             * calls. Otherwise, the usb event thread will be leaked, and will
             * try to use the libusb context we destroy in finalize(), which would
             * cause a crash */
             g_warn_if_reached();
             g_atomic_int_set(&priv->event_thread_run, FALSE);
        }
        /* This also wakes up the libusb_handle_events() in the event_thread */
        libusb_hotplug_deregister_callback(priv->context, priv->hp_handle);
        priv->hp_handle = 0;
    }

    if (priv->event_thread) {
        g_warn_if_fail(g_atomic_int_get(&priv->event_thread_run) == FALSE);
        g_thread_join(priv->event_thread);
        priv->event_thread = NULL;
    }
    /* Chain up to the parent class */
    if (G_OBJECT_CLASS(spice_usb_device_manager_parent_class)->dispose)
        G_OBJECT_CLASS(spice_usb_device_manager_parent_class)->dispose(gobject);
}

static void spice_usb_device_manager_finalize(GObject *gobject)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    g_ptr_array_unref(priv->channels);
    if (priv->devices)
        g_ptr_array_unref(priv->devices);
    g_return_if_fail(priv->event_thread == NULL);
    if (priv->context)
        libusb_exit(priv->context);
    free(priv->auto_conn_filter_rules);
    free(priv->redirect_on_connect_rules);
    g_free(priv->auto_connect_filter);
    g_free(priv->redirect_on_connect);
    /* Chain up to the parent class */
    if (G_OBJECT_CLASS(spice_usb_device_manager_parent_class)->finalize)
        G_OBJECT_CLASS(spice_usb_device_manager_parent_class)->finalize(gobject);
}

static void spice_usb_device_manager_initable_iface_init(GInitableIface *iface)
{
    iface->init = spice_usb_device_manager_initable_init;
}

static void spice_usb_device_manager_get_property(GObject     *gobject,
                                                  guint        prop_id,
                                                  GValue      *value,
                                                  GParamSpec  *pspec)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;

    switch (prop_id) {
    case PROP_SESSION:
        g_value_set_object(value, priv->session);
        break;
    case PROP_AUTO_CONNECT:
        g_value_set_boolean(value, priv->auto_connect);
        break;
    case PROP_AUTO_CONNECT_FILTER:
        g_value_set_string(value, priv->auto_connect_filter);
        break;
    case PROP_REDIRECT_ON_CONNECT:
        g_value_set_string(value, priv->redirect_on_connect);
        break;
    case PROP_FREE_CHANNELS: {
        int free_channels = 0;
        int i;
        for (i = 0; i < priv->channels->len; i++) {
            SpiceUsbredirChannel *channel = g_ptr_array_index(priv->channels, i);

            if (!spice_usbredir_channel_get_device(channel))
                free_channels++;
        }
        g_value_set_int(value, free_channels);
        break;
    }
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
        break;
    }
}

static void spice_usb_device_manager_set_property(GObject  *gobject,
                                                  guint          prop_id,
                                                  const GValue  *value,
                                                  GParamSpec    *pspec)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;

    switch (prop_id) {
    case PROP_SESSION:
        priv->session = g_value_get_object(value);
        break;
    case PROP_AUTO_CONNECT:
        priv->auto_connect = g_value_get_boolean(value);
        break;
    case PROP_AUTO_CONNECT_FILTER: {
        const gchar *filter = g_value_get_string(value);
        struct usbredirfilter_rule *rules;
        int r, count;
        r = usbredirfilter_string_to_rules(filter, ",", "|", &rules, &count);
        if (r) {
            if (r == -ENOMEM)
                g_error("Failed to allocate memory for auto-connect-filter");
                g_warning("Error parsing auto-connect-filter string, keeping old filter");
            break;
        }
        SPICE_DEBUG("auto-connect filter set to %s", filter);
        free(priv->auto_conn_filter_rules);
        priv->auto_conn_filter_rules = rules;
        priv->auto_conn_filter_rules_count = count;
        g_free(priv->auto_connect_filter);
        priv->auto_connect_filter = g_strdup(filter);
        break;
    }
    case PROP_REDIRECT_ON_CONNECT: {
        const gchar *filter = g_value_get_string(value);
        struct usbredirfilter_rule *rules = NULL;
        int r = 0, count = 0;
        if (filter)
            r = usbredirfilter_string_to_rules(filter, ",", "|",&rules, &count);
        if (r) {
            if (r == -ENOMEM)
                g_error("Failed to allocate memory for redirect-on-connect");
                g_warning("Error parsing redirect-on-connect string, keeping old filter");
                break;
        }
        SPICE_DEBUG("redirect-on-connect filter set to %s", filter);
        free(priv->redirect_on_connect_rules);
        priv->redirect_on_connect_rules = rules;
        priv->redirect_on_connect_rules_count = count;
        g_free(priv->redirect_on_connect);
        priv->redirect_on_connect = g_strdup(filter);
        break;
    }
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
        break;
    }
}

static void spice_usb_device_manager_class_init(SpiceUsbDeviceManagerClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    GParamSpec *pspec;
    gobject_class->dispose      = spice_usb_device_manager_dispose;
    gobject_class->finalize     = spice_usb_device_manager_finalize;
    gobject_class->get_property = spice_usb_device_manager_get_property;
    gobject_class->set_property = spice_usb_device_manager_set_property;

    g_object_class_install_property
        (gobject_class, PROP_SESSION,
         g_param_spec_object("session",
                             "Session",
                             "SpiceSession",
                             SPICE_TYPE_SESSION,
                             G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE |
                             G_PARAM_STATIC_STRINGS));

    /**
     * SpiceUsbDeviceManager:auto-connect:
     *
     * Set this to TRUE to automatically redirect newly plugged in device.
     *
     * Note when #SpiceGtkSession's auto-usbredir property is TRUE, this
     * property is controlled by #SpiceGtkSession.
     */
    pspec = g_param_spec_boolean("auto-connect", "Auto Connect",
                                 "Auto connect plugged in USB devices",
                                 FALSE,
                                 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
    g_object_class_install_property(gobject_class, PROP_AUTO_CONNECT, pspec);

    /**
     * SpiceUsbDeviceManager:auto-connect-filter:
     *
     * Set a string specifying a filter to use to determine which USB devices
     * to autoconnect when plugged in, a filter consists of one or more rules.
     * Where each rule has the form of:
     *
     * @class,@vendor,@product,@version,@allow
     *
     * Use -1 for @class/@vendor/@product/@version to accept any value.
     *
     * And the rules themselves are concatenated like this:
     *
     * @rule1|@rule2|@rule3
     *
     * The default setting filters out HID (class 0x03) USB devices from auto
     * connect and auto connects anything else. Note the explicit allow rule at
     * the end, this is necessary since by default all devices without a
     * matching filter rule will not auto-connect.
     *
     * Filter strings in this format can be easily created with the RHEV-M
     * USB filter editor tool.
     */
    pspec = g_param_spec_string("auto-connect-filter", "Auto Connect Filter ",
               "Filter determining which USB devices to auto connect",
               "0x03,-1,-1,-1,0|-1,-1,-1,-1,1",
               G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);
    g_object_class_install_property(gobject_class, PROP_AUTO_CONNECT_FILTER,
                                    pspec);

    /**
     * SpiceUsbDeviceManager:redirect-on-connect:
     *
     * Set a string specifying a filter selecting USB devices to automatically
     * redirect after a Spice connection has been established.
     *
     * See #SpiceUsbDeviceManager:auto-connect-filter for the filter string
     * format.
     */
    pspec = g_param_spec_string("redirect-on-connect", "Redirect on connect",
               "Filter selecting USB devices to redirect on connect", NULL,
               G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
    g_object_class_install_property(gobject_class, PROP_REDIRECT_ON_CONNECT,
                                    pspec);

    /**
     * SpiceUsbDeviceManager:free-channels:
     *
     * Get the number of available channels for redirecting USB devices.
     *
     * Since: 0.31
     */
    pspec = g_param_spec_int("free-channels", "Free channels",
               "The number of available channels for redirecting USB devices",
               0,
               G_MAXINT,
               0,
               G_PARAM_READABLE);
    g_object_class_install_property(gobject_class, PROP_FREE_CHANNELS,
                                    pspec);

    /**
     * SpiceUsbDeviceManager::device-added:
     * @manager: the #SpiceUsbDeviceManager that emitted the signal
     * @device: #SpiceUsbDevice boxed object corresponding to the added device
     *
     * The #SpiceUsbDeviceManager::device-added signal is emitted whenever
     * a new USB device has been plugged in.
     **/
    signals[DEVICE_ADDED] =
        g_signal_new("device-added",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceUsbDeviceManagerClass, device_added),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__BOXED,
                     G_TYPE_NONE,
                     1,
                     SPICE_TYPE_USB_DEVICE);

    /**
     * SpiceUsbDeviceManager::device-removed:
     * @manager: the #SpiceUsbDeviceManager that emitted the signal
     * @device: #SpiceUsbDevice boxed object corresponding to the removed device
     *
     * The #SpiceUsbDeviceManager::device-removed signal is emitted whenever
     * an USB device has been removed.
     **/
    signals[DEVICE_REMOVED] =
        g_signal_new("device-removed",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceUsbDeviceManagerClass, device_removed),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__BOXED,
                     G_TYPE_NONE,
                     1,
                     SPICE_TYPE_USB_DEVICE);

    /**
     * SpiceUsbDeviceManager::auto-connect-failed:
     * @manager: the #SpiceUsbDeviceManager that emitted the signal
     * @device: #SpiceUsbDevice boxed object corresponding to the device which failed to auto connect
     * @error: #GError describing the reason why the autoconnect failed
     *
     * The #SpiceUsbDeviceManager::auto-connect-failed signal is emitted
     * whenever the auto-connect property is true, and a newly plugged in
     * device could not be auto-connected.
     **/
    signals[AUTO_CONNECT_FAILED] =
        g_signal_new("auto-connect-failed",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceUsbDeviceManagerClass, auto_connect_failed),
                     NULL, NULL,
                     g_cclosure_user_marshal_VOID__BOXED_BOXED,
                     G_TYPE_NONE,
                     2,
                     SPICE_TYPE_USB_DEVICE,
                     G_TYPE_ERROR);

    /**
     * SpiceUsbDeviceManager::device-error:
     * @manager: #SpiceUsbDeviceManager that emitted the signal
     * @device:  #SpiceUsbDevice boxed object corresponding to the device which has an error
     * @error:   #GError describing the error
     *
     * The #SpiceUsbDeviceManager::device-error signal is emitted whenever an
     * error happens which causes a device to no longer be available to the
     * guest.
     **/
    signals[DEVICE_ERROR] =
        g_signal_new("device-error",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceUsbDeviceManagerClass, device_error),
                     NULL, NULL,
                     g_cclosure_user_marshal_VOID__BOXED_BOXED,
                     G_TYPE_NONE,
                     2,
                     SPICE_TYPE_USB_DEVICE,
                     G_TYPE_ERROR);
    g_type_class_add_private(klass, sizeof(SpiceUsbDeviceManagerPrivate));
	
}

/* ------------------------------------------------------------------ */

static gboolean spice_usb_device_manager_get_device_descriptor(
    libusb_device *libdev,
    struct libusb_device_descriptor *desc)
{
    int errcode;
    const gchar *errstr;
    g_return_val_if_fail(libdev != NULL, FALSE);
    g_return_val_if_fail(desc   != NULL, FALSE);
    errcode = libusb_get_device_descriptor(libdev, desc);
    if (errcode < 0) {
        int bus, addr;
        bus = libusb_get_bus_number(libdev);
        addr = libusb_get_device_address(libdev);
        errstr = spice_usbutil_libusb_strerror(errcode);
        g_warning("cannot get device descriptor for (%p) %d.%d -- %s(%d)",
                  libdev, bus, addr, errstr, errcode);
        return FALSE;
    }

    return TRUE;
}

/**
 * spice_usb_device_get_libusb_device:
 * @device: #SpiceUsbDevice to get the descriptor information of
 *
 * Finds the %libusb_device associated with the @device.
 *
 * Returns: (transfer none): the %libusb_device associated to %SpiceUsbDevice.
 *
 * Since: 0.27
 **/
gconstpointer spice_usb_device_get_libusb_device(const SpiceUsbDevice *device G_GNUC_UNUSED)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;
    g_return_val_if_fail(info != NULL, FALSE);
    return info->libdev;
}

static gboolean spice_usb_device_manager_get_libdev_vid_pid(libusb_device *libdev, int *vid, int *pid)
{
    struct libusb_device_descriptor desc;
    g_return_val_if_fail(libdev != NULL, FALSE);
    g_return_val_if_fail(vid != NULL, FALSE);
    g_return_val_if_fail(pid != NULL, FALSE);
    *vid = *pid = 0;
    if (!spice_usb_device_manager_get_device_descriptor(libdev, &desc)) {
        return FALSE;
    }
    *vid = desc.idVendor;
    *pid = desc.idProduct;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* callbacks                                                          */

static void channel_new(SpiceSession *session, SpiceChannel *channel,gpointer user_data)
{
    SpiceUsbDeviceManager *self = user_data;
    if (!SPICE_IS_USBREDIR_CHANNEL(channel))	
        return;

    spice_usbredir_channel_set_context(SPICE_USBREDIR_CHANNEL(channel),self->priv->context);
    spice_channel_connect(channel);
    g_ptr_array_add(self->priv->channels, channel);
    spice_usb_device_manager_check_redir_on_connect(self, channel);
    /*
     * add a reference to ourself, to make sure the libusb context is
     * alive as long as the channel is.
     * TODO: moving to gusb could help here too.
     */
    g_object_ref(self);
    g_object_weak_ref(G_OBJECT(channel), (GWeakNotify)g_object_unref, self);
}

static void channel_destroy(SpiceSession *session, SpiceChannel *channel,gpointer user_data)
{
    SpiceUsbDeviceManager *self = user_data;
    if (!SPICE_IS_USBREDIR_CHANNEL(channel))
        return;
    g_ptr_array_remove(self->priv->channels, channel);
}

static void spice_usb_device_manager_auto_connect_cb(GObject  *gobject,GAsyncResult *res,gpointer user_data)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    SpiceUsbDevice *device = user_data;
    GError *err = NULL;
    spice_usb_device_manager_connect_device_finish(self, res, &err);
    if (err) {
        gchar *desc = spice_usb_device_get_description(device, NULL);
        g_prefix_error(&err, "Could not auto-redirect %s: ", desc);
        g_free(desc);
        SPICE_DEBUG("%s", err->message);
        g_signal_emit(self, signals[AUTO_CONNECT_FAILED], 0, device, err);
        g_error_free(err);
    }
    spice_usb_device_unref(device);
}

static gboolean spice_usb_device_manager_device_match(SpiceUsbDeviceManager *self, SpiceUsbDevice *device,
                                      const int bus, const int address)
{
    return (spice_usb_device_get_busnum(device) == bus &&spice_usb_device_get_devaddr(device) == address);
}

static SpiceUsbDevice* spice_usb_device_manager_find_device(SpiceUsbDeviceManager *self,const int bus, const int address)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    SpiceUsbDevice *curr, *device = NULL;
    guint i;
    for (i = 0; i < priv->devices->len; i++) {
        curr = g_ptr_array_index(priv->devices, i);
        if (spice_usb_device_manager_device_match(self, curr, bus, address)) {
            device = curr;
            break;
        }
    }
    return device;
}


/*
	pvid filter function 
	return 0 allow this USB device excute USB-Redir
	return 1 don't allow this USB device excute USB-Redir
	return -1 This device's manager is not use pvid
	
*/
static int parse_filter_pvid(char *text,char *desc_pvid)
{
	printf("Enter function  parse_filter_pvid\n");
	fflush(stdout);
	cJSON *json;
	char *rule;
	cJSON *pvid;
	int pvid_len;

	json=cJSON_Parse(text);
	if (!json) {
		printf("String parameter is not JSON string \n");
		fflush(stdout);
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		fflush(stdout);

	}else{
		printf("Parse JSON String Success!!\n");
		fflush(stdout);
		
		rule=cJSON_GetObjectItem(json,"rule")->valuestring;
		printf("rule=%s\n",rule);
		fflush(stdout);
		
		pvid=cJSON_GetObjectItem(json,"pvid");
		pvid_len=cJSON_GetArraySize(pvid);
		printf("pvid_len=%d\n",pvid_len);
		fflush(stdout);
		
		for(int i=0;i<pvid_len;i++)
		{
			printf("pvid[%d]=%s\n",i,(cJSON_GetArrayItem(pvid,i))->valuestring);
			fflush(stdout);
			
			if(!strcmp(desc_pvid,(cJSON_GetArrayItem(pvid,i))->valuestring)){
				if(!strcmp("unfilter",rule)){
					printf("desc_pvid =%s pvid unfilter\n",desc_pvid);
					fflush(stdout);
					return 0;
				}else{
					printf("desc_pvid =%s pvid filter\n",desc_pvid);
					fflush(stdout);
					return 1;
				}
			}
		}
		cJSON_Delete(json);
	}	
	return -1;
}

/*
	usb class filter function
	return 0 allow this usb device class excute USB-Redir
	return 1 don't allow this device class excute USB-Redir
*/

static int parse_filter_class(char *text,int desc_class)
{
	printf("Enter function  parse_filter_class\n");
	fflush(stdout);
	cJSON *json;
	char *rule;
	cJSON *usb_class;
	int usb_class_len;

	json=cJSON_Parse(text);
	if (!json) {
		printf("String parameter is not JSON string \n");
		fflush(stdout);
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		fflush(stdout);

	}else{
		printf("Parse JSON String Success!!\n");
		fflush(stdout);
		
		rule=cJSON_GetObjectItem(json,"rule")->valuestring;
		printf("rule=%s\n",rule);
		fflush(stdout);
		
		usb_class=cJSON_GetObjectItem(json,"class");
		usb_class_len=cJSON_GetArraySize(usb_class);
		printf("usb_class_len=%d\n",usb_class_len);
		fflush(stdout);
		
		for(int i=0;i<usb_class_len;i++)
		{
			printf("usb_class[%d]=%s\n",i,(cJSON_GetArrayItem(usb_class,i))->valuestring);
			fflush(stdout);
			unsigned int usb_class_tmp;
			sscanf(((cJSON_GetArrayItem(usb_class,i))->valuestring),"%x",&usb_class_tmp);
			if(desc_class == usb_class_tmp){
				if(!strcmp("unfilter",rule)){
					printf("desc_class =%d class unfilter\n",desc_class);
					fflush(stdout);
					return 0;
				}else{
					printf("desc_class =%d class filter\n",desc_class);
					fflush(stdout);
					return 1;
				}
			}
		}
	}
	if(!strcmp("unfilter",rule)){
		cJSON_Delete(json);
		return 1;
	}else{
		cJSON_Delete(json);
		return 0;
	}
	
	
}

static void spice_usb_device_manager_add_dev(SpiceUsbDeviceManager  *self,libusb_device *libdev)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    struct libusb_device_descriptor desc;
    SpiceUsbDevice *device;
    if (!spice_usb_device_manager_get_device_descriptor(libdev, &desc))
        return;
    /* Skip hubs */
    if (desc.bDeviceClass == LIBUSB_CLASS_HUB)
        return;

	char pid[10];
	char vid[10];
	sprintf(pid,"%04x",desc.idProduct);
	sprintf(vid,"%04x",desc.idVendor);
	
	/*First filter is pvid */
	char desc_pvid[12];
	strcpy (desc_pvid,"0x");
    strcat (desc_pvid,pid);
	strcat (desc_pvid,vid);
	printf("pvid=%s\n",desc_pvid);
	int pvid_return = -1;
	pvid_return=parse_filter_pvid(filter_flag,desc_pvid);
	if(pvid_return == 0){
		printf("This USB device pvid=%s allow excute USB-Redir\n",desc_pvid);
		fflush(stdout);
		goto pvfilter;
	}else if(pvid_return == 1){
		printf("This USB device pvid=%s don't allow excute USB-Redir\n",desc_pvid);
		fflush(stdout);
		return ;
	}
	
	int i, num_interfaces;
	struct libusb_config_descriptor *config = NULL;
	uint8_t interface_class[32];
	uint8_t interface_subclass[32];
	uint8_t interface_protocol[32];

	/*fix mobile HDD*/
	int res;
	res=libusb_get_active_config_descriptor(libdev, &config);
	if(res!=0){
		printf("+++++++++++++++++Please plug it again+++++++++++++\n");
		fflush(stdout);
		return;
	}
	
	if(config==NULL){
		printf("active config descriptor is null!!\n");
		fflush(stdout);
	}else{
		printf("active config descriptor is not null\n");
		fflush(stdout);
		
		num_interfaces = config->bNumInterfaces;
		int exitflag=0;
		int returnflag=0;
		
		for (i = 0; i < num_interfaces; i++) {
	        const struct libusb_interface_descriptor *intf_desc =config->interface[i].altsetting;
	        interface_class[i] = intf_desc->bInterfaceClass;
	        interface_subclass[i] = intf_desc->bInterfaceSubClass;
	        interface_protocol[i] = intf_desc->bInterfaceProtocol;
			/*skip keyboard and mouse */
			/*
			if((interface_class[i]==3&&interface_subclass[i]==1&&interface_protocol[i]==2)||(interface_class[i]==3&&interface_subclass[i]==1&&interface_protocol[i]==1))
				return;
			*/
			/*
				USB Device class filter
			*/
			int class_parse_return=-1;
			class_parse_return=parse_filter_class(filter_flag,interface_class[i]);

			if(class_parse_return == 0)
			{
				exitflag++;	
			}else if(class_parse_return ==1){
				returnflag++;
			}
		}

		if(returnflag > 0){
			printf("This USB Device class filter don't allow excute USB-Redir\n");
			fflush(stdout);
			return;
		}
		
		if((exitflag > 0) && (returnflag==0) ){
			printf("This USB Device class filter allow excute USB-Redir\n");
			fflush(stdout);
		}	
	}

pvfilter:

	printf("A new usb device begin to usb redirect!!\n");
	fflush(stdout);
	
    device = (SpiceUsbDevice*)spice_usb_device_new(libdev);
    if (!device)
        return;
    g_ptr_array_add(priv->devices, device);
	spice_usb_device_manager_connect_device_async(self,device, NULL,NULL,NULL); 
}

static void spice_usb_device_manager_remove_dev(SpiceUsbDeviceManager *self,guint bus, guint address)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    SpiceUsbDevice *device;
    device = spice_usb_device_manager_find_device(self, bus, address);
    if (!device) {
        return;
    }
   
    disconnect_device_sync(self, device);
    //spice_usb_device_ref(device);
    g_ptr_array_remove(priv->devices, device);
    //spice_usb_device_unref(device);
}

struct hotplug_idle_cb_args {
    SpiceUsbDeviceManager *self;
    libusb_device *device;
    libusb_hotplug_event event;
};

static gboolean spice_usb_device_manager_hotplug_idle_cb(gpointer user_data)
{
    struct hotplug_idle_cb_args *args = user_data;
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(args->self);
    switch (args->event) {
    case LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED:
        spice_usb_device_manager_add_dev(self, args->device);
        break;
    case LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT:
        spice_usb_device_manager_remove_dev(self,libusb_get_bus_number(args->device),libusb_get_device_address(args->device));
        break;
    }
    libusb_unref_device(args->device);
    g_object_unref(self);
    g_free(args);
    return FALSE;
}

/* Can be called from both the main-thread as well as the event_thread */
static int spice_usb_device_manager_hotplug_cb(libusb_context *ctx,libusb_device *device,libusb_hotplug_event  event,void *user_data)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(user_data);
    struct hotplug_idle_cb_args *args = g_malloc0(sizeof(*args));
    args->self = g_object_ref(self);
    args->device = libusb_ref_device(device);
    args->event = event;
    g_idle_add(spice_usb_device_manager_hotplug_idle_cb, args);
    return 0;
}


static void spice_usb_device_manager_channel_connect_cb(GObject *gobject, GAsyncResult *channel_res, gpointer user_data)
{
    SpiceUsbredirChannel *channel = SPICE_USBREDIR_CHANNEL(gobject);
    GTask *task = G_TASK(user_data);
    GError *err = NULL;
    spice_usbredir_channel_connect_device_finish(channel, channel_res, &err);
    if (err)
        g_task_return_error(task, err);
    else
        g_task_return_boolean(task, TRUE);
    g_object_unref(task);
}

/* ------------------------------------------------------------------ */
/* private api                                                        */

static gpointer spice_usb_device_manager_usb_ev_thread(gpointer user_data)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(user_data);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    int rc;
    while (g_atomic_int_get(&priv->event_thread_run)) {
        rc = libusb_handle_events(priv->context);
        if (rc && rc != LIBUSB_ERROR_INTERRUPTED) {
            const char *desc = spice_usbutil_libusb_strerror(rc);
            g_warning("Error handling USB events: %s [%i]", desc, rc);
            break;
        }
    }
    return NULL;
}

gboolean spice_usb_device_manager_start_event_listening(SpiceUsbDeviceManager *self, GError **err)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);
    priv->event_listeners++;
    if (priv->event_listeners > 1)
        return TRUE;
    if (priv->event_thread) {
         g_thread_join(priv->event_thread);
         priv->event_thread = NULL;
    }
    g_atomic_int_set(&priv->event_thread_run, TRUE);
    priv->event_thread = g_thread_new("usb_ev_thread",spice_usb_device_manager_usb_ev_thread,self);
    return priv->event_thread != NULL;
}

void spice_usb_device_manager_stop_event_listening(SpiceUsbDeviceManager *self)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    g_return_if_fail(priv->event_listeners > 0);
    priv->event_listeners--;
    if (priv->event_listeners == 0)
        g_atomic_int_set(&priv->event_thread_run, FALSE);
}

static void spice_usb_device_manager_check_redir_on_connect(SpiceUsbDeviceManager *self, SpiceChannel *channel)
{
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    GTask *task;
    SpiceUsbDevice *device;
    libusb_device *libdev;
    guint i;
    if (priv->redirect_on_connect == NULL)
        return;
    for (i = 0; i < priv->devices->len; i++) {
        device = g_ptr_array_index(priv->devices, i);
        if (spice_usb_device_manager_is_device_connected(self, device))
            continue;
        libdev = spice_usb_device_manager_device_to_libdev(self, device);
        if (usbredirhost_check_device_filter(priv->redirect_on_connect_rules,priv->redirect_on_connect_rules_count,libdev, 0) == 0) {
            /* Note: re-uses spice_usb_device_manager_connect_device_async's
               completion handling code! */
            task = g_task_new(self,NULL,spice_usb_device_manager_auto_connect_cb, spice_usb_device_ref(device));
            spice_usbredir_channel_connect_device_async(SPICE_USBREDIR_CHANNEL(channel),libdev, device, NULL, spice_usb_device_manager_channel_connect_cb,task);
            libusb_unref_device(libdev);
            return; /* We've taken the channel! */
        }
        libusb_unref_device(libdev);
    }
}

void spice_usb_device_manager_device_error(SpiceUsbDeviceManager *self, SpiceUsbDevice *device, GError *err)
{
    g_return_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self));
    g_return_if_fail(device != NULL);
    g_signal_emit(self, signals[DEVICE_ERROR], 0, device, err);
}

static SpiceUsbredirChannel *spice_usb_device_manager_get_channel_for_dev(SpiceUsbDeviceManager *manager, SpiceUsbDevice *device)
{
    SpiceUsbDeviceManagerPrivate *priv = manager->priv;
    guint i;
    for (i = 0; i < priv->channels->len; i++) {
        SpiceUsbredirChannel *channel = g_ptr_array_index(priv->channels, i);
        spice_usbredir_channel_lock(channel);
        libusb_device *libdev = spice_usbredir_channel_get_device(channel);
        if (spice_usb_manager_device_equal_libdev(manager, device, libdev)) {
            spice_usbredir_channel_unlock(channel);
            return channel;
        }
        spice_usbredir_channel_unlock(channel);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* public api                                                         */

/**
 * spice_usb_device_manager_get_devices_with_filter:
 * @manager: the #SpiceUsbDeviceManager manager
 * @filter: (allow-none): filter string for selecting which devices to return,
 *      see #SpiceUsbDeviceManager:auto-connect-filter for the filter
 *      string format
 *
 * Finds devices associated with the @manager complying with the @filter
 *
 * Returns: (element-type SpiceUsbDevice) (transfer full): a
 * %GPtrArray array of %SpiceUsbDevice
 *
 * Since: 0.20
 */
GPtrArray* spice_usb_device_manager_get_devices_with_filter(SpiceUsbDeviceManager *self, const gchar *filter)
{
    GPtrArray *devices_copy = NULL;
    g_return_val_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self), NULL);
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    struct usbredirfilter_rule *rules = NULL;
    int r, count = 0;
    guint i;

    if (filter) {
        r = usbredirfilter_string_to_rules(filter, ",", "|", &rules, &count);
        if (r) {
            if (r == -ENOMEM)
                g_error("Failed to allocate memory for filter");
            g_warning("Error parsing filter, ignoring");
            rules = NULL;
            count = 0;
        }
    }
    devices_copy = g_ptr_array_new_with_free_func((GDestroyNotify) spice_usb_device_unref);
    for (i = 0; i < priv->devices->len; i++) {
        SpiceUsbDevice *device = g_ptr_array_index(priv->devices, i);
        if (rules) {
            libusb_device *libdev =
                spice_usb_device_manager_device_to_libdev(self, device);
            if (usbredirhost_check_device_filter(rules, count, libdev, 0) != 0)
                continue;
        }
        g_ptr_array_add(devices_copy, spice_usb_device_ref(device));
    }
    free(rules);
    return devices_copy;
}

/**
 * spice_usb_device_manager_get_devices:
 * @manager: the #SpiceUsbDeviceManager manager
 *
 * Finds devices associated with the @manager
 *
 * Returns: (element-type SpiceUsbDevice) (transfer full): a %GPtrArray array of %SpiceUsbDevice
 */
GPtrArray* spice_usb_device_manager_get_devices(SpiceUsbDeviceManager *self)
{
    return spice_usb_device_manager_get_devices_with_filter(self, NULL);
}

/**
 * spice_usb_device_manager_is_device_connected:
 * @manager: the #SpiceUsbDeviceManager manager
 * @device: a #SpiceUsbDevice
 *
 * Finds if the @device is connected.
 *
 * Returns: %TRUE if @device has an associated USB redirection channel
 */
gboolean spice_usb_device_manager_is_device_connected(SpiceUsbDeviceManager *self,
                                                      SpiceUsbDevice *device)
{
    g_return_val_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self), FALSE);
    g_return_val_if_fail(device != NULL, FALSE);
    return !!spice_usb_device_manager_get_channel_for_dev(self, device);
}



static gboolean _spice_usb_device_manager_connect_device_finish(SpiceUsbDeviceManager *self,
                                                GAsyncResult *res,
                                                GError **error)
{
    GTask *task = G_TASK(res);
    g_return_val_if_fail(g_task_is_valid(task, G_OBJECT(self)), FALSE);
    return g_task_propagate_boolean(task, error);
}

static void
_spice_usb_device_manager_connect_device_async(SpiceUsbDeviceManager *self,
                                               SpiceUsbDevice *device,
                                               GCancellable *cancellable,
                                               GAsyncReadyCallback callback,
                                               gpointer user_data)
{
    GTask *task;

    g_return_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self));
    g_return_if_fail(device != NULL);

    SPICE_DEBUG("connecting device %p", device);

    task = g_task_new(self, cancellable, callback, user_data);

    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    libusb_device *libdev;
    guint i;

    if (spice_usb_device_manager_is_device_connected(self, device)) {
        g_task_return_new_error(task,SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,"Cannot connect an already connected usb device");
        goto done;
    }

    for (i = 0; i < priv->channels->len; i++) {
        SpiceUsbredirChannel *channel = g_ptr_array_index(priv->channels, i);
        if (spice_usbredir_channel_get_device(channel))
            continue; /* Skip already used channels */
        libdev = spice_usb_device_manager_device_to_libdev(self, device);
        spice_usbredir_channel_connect_device_async(channel,
                                 libdev,
                                 device,
                                 cancellable,
                                 spice_usb_device_manager_channel_connect_cb,
                                 task);
        libusb_unref_device(libdev);
        return;
    }

    g_task_return_new_error(task,
                            SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,
                            _("No free USB channel"));
done:
    g_object_unref(task);
}


/**
 * spice_usb_device_manager_connect_device_async:
 * @self: a #SpiceUsbDeviceManager.
 * @device: a #SpiceUsbDevice to redirect
 * @cancellable: (allow-none): optional #GCancellable object, %NULL to ignore
 * @callback: a #GAsyncReadyCallback to call when the request is satisfied
 * @user_data: the data to pass to callback function
 *
 * Asynchronously connects the @device. When completed, @callback will be called.
 * Then it is possible to call spice_usb_device_manager_connect_device_finish()
 * to get the result of the operation.
 */
void spice_usb_device_manager_connect_device_async(SpiceUsbDeviceManager *self,
                                             SpiceUsbDevice *device,
                                             GCancellable *cancellable,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data)
{
    g_return_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self));
    GTask *task =g_task_new(G_OBJECT(self), cancellable, callback, user_data);
    _set_redirecting(self, TRUE);
    _spice_usb_device_manager_connect_device_async(self,device,cancellable,_connect_device_async_cb,task);
}

/**
 * spice_usb_device_manager_connect_device_finish:
 * @self: a #SpiceUsbDeviceManager.
 * @res: a #GAsyncResult
 * @err: (allow-none): a return location for a #GError, or %NULL.
 *
 * Finishes an async operation. See spice_usb_device_manager_connect_device_async().
 *
 * Returns: %TRUE if connection is successful
 */
gboolean spice_usb_device_manager_connect_device_finish(
    SpiceUsbDeviceManager *self, GAsyncResult *res, GError **err)
{
    GTask *task = G_TASK(res);
    g_return_val_if_fail(g_task_is_valid(task, self),FALSE);
    return g_task_propagate_boolean(task, err);
}

/**
 * spice_usb_device_manager_disconnect_device_finish:
 * @self: a #SpiceUsbDeviceManager.
 * @res: a #GAsyncResult
 * @err: (allow-none): a return location for a #GError, or %NULL.
 *
 * Finishes an async operation. See spice_usb_device_manager_disconnect_device_async().
 *
 * Returns: %TRUE if disconnection is successful
 */
gboolean spice_usb_device_manager_disconnect_device_finish(SpiceUsbDeviceManager *self, GAsyncResult *res, GError **err)
{
    GTask *task = G_TASK(res);
    g_return_val_if_fail(g_task_is_valid(task, G_OBJECT(self)), FALSE);
    return g_task_propagate_boolean(task, err);
}

static void _connect_device_async_cb(GObject *gobject,
                              GAsyncResult *channel_res,
                              gpointer user_data)
{
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(gobject);
    GTask *task = user_data;
    GError *error = NULL;
    _set_redirecting(self, FALSE);
    if (_spice_usb_device_manager_connect_device_finish(self, channel_res, &error))
        g_task_return_boolean(task, TRUE);
    else
        g_task_return_error(task, error);
    g_object_unref(task);
}


static void disconnect_device_sync(SpiceUsbDeviceManager *self,         SpiceUsbDevice *device)
{
    g_return_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self));
    g_return_if_fail(device != NULL);
    SPICE_DEBUG("disconnecting device %p", device);
    SpiceUsbredirChannel *channel;
    channel = spice_usb_device_manager_get_channel_for_dev(self, device);
    if (channel)
        spice_usbredir_channel_disconnect_device(channel);
}

/**
 * spice_usb_device_manager_disconnect_device:
 * @manager: the #SpiceUsbDeviceManager manager
 * @device: a #SpiceUsbDevice to disconnect
 *
 * Disconnects the @device.
 */
void spice_usb_device_manager_disconnect_device(SpiceUsbDeviceManager *self,
                                                SpiceUsbDevice *device)
{
    disconnect_device_sync(self, device);
}

typedef struct _disconnect_cb_data
{
    SpiceUsbDeviceManager  *self;
    SpiceUsbDevice         *device;
} disconnect_cb_data;

static void _disconnect_device_async_cb(GObject *gobject,
                                 GAsyncResult *channel_res,
                                 gpointer user_data)
{
    SpiceUsbredirChannel *channel = SPICE_USBREDIR_CHANNEL(gobject);
    GTask *task = user_data;
    GError *err = NULL;
    disconnect_cb_data *data = g_task_get_task_data(task);
    SpiceUsbDeviceManager *self = SPICE_USB_DEVICE_MANAGER(data->self);

    _set_redirecting(self, FALSE);

    spice_usbredir_channel_disconnect_device_finish(channel, channel_res, &err);
    if (err)
        g_task_return_error(task, err);
    else
        g_task_return_boolean(task, TRUE);

    g_object_unref(task);
}


/**
 * spice_usb_device_manager_disconnect_device_async:
 * @self: the #SpiceUsbDeviceManager manager.
 * @device: a connected #SpiceUsbDevice to disconnect.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: (scope async): a #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: (closure): the data to pass to @callback.
 *
 * Asynchronously disconnects the @device. When completed, @callback will be called.
 * Then it is possible to call spice_usb_device_manager_disconnect_device_finish()
 * to get the result of the operation.
 *
 * Since: 0.32
 */
void spice_usb_device_manager_disconnect_device_async(SpiceUsbDeviceManager *self,
                                                      SpiceUsbDevice *device,
                                                      GCancellable *cancellable,
                                                      GAsyncReadyCallback callback,
                                                      gpointer user_data)
{
    GTask *nested;
    g_return_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self));
    g_return_if_fail(device != NULL);
    g_return_if_fail(spice_usb_device_manager_is_device_connected(self, device));
    SPICE_DEBUG("disconnecting device %p", device);
    SpiceUsbredirChannel *channel;
    _set_redirecting(self, TRUE);
    channel = spice_usb_device_manager_get_channel_for_dev(self, device);
    nested  = g_task_new(G_OBJECT(self), cancellable, callback, user_data);
    disconnect_cb_data *data = g_new(disconnect_cb_data, 1);
    data->self = self;
    data->device = device;
    g_task_set_task_data(nested, data, g_free);
    spice_usbredir_channel_disconnect_device_async(channel, cancellable,_disconnect_device_async_cb,nested);
}

/**
 * spice_usb_device_manager_can_redirect_device:
 * @self: the #SpiceUsbDeviceManager manager
 * @device: a #SpiceUsbDevice to disconnect
 * @err: (allow-none): a return location for a #GError, or %NULL.
 *
 * Checks whether it is possible to redirect the @device.
 *
 * Returns: %TRUE if @device can be redirected
 */
gboolean spice_usb_device_manager_can_redirect_device(SpiceUsbDeviceManager  *self,SpiceUsbDevice*device, GError **err)
{
    const struct usbredirfilter_rule *guest_filter_rules = NULL;
    SpiceUsbDeviceManagerPrivate *priv = self->priv;
    int i, guest_filter_rules_count;
    g_return_val_if_fail(SPICE_IS_USB_DEVICE_MANAGER(self), FALSE);
    g_return_val_if_fail(device != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);
    if (!priv->channels->len) {
        g_set_error_literal(err, SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,
                            _("The connected VM is not configured for USB redirection"));
        return FALSE;
    }
    /* Skip the other checks for already connected devices */
    if (spice_usb_device_manager_is_device_connected(self, device))
        return TRUE;
    /* We assume all channels have the same filter, so we just take the
       filter from the first channel */
    spice_usbredir_channel_get_guest_filter(g_ptr_array_index(priv->channels, 0),&guest_filter_rules, &guest_filter_rules_count);

    if (guest_filter_rules) {
        gboolean filter_ok;
        libusb_device *libdev;
        libdev = spice_usb_device_manager_device_to_libdev(self, device);
        filter_ok = (usbredirhost_check_device_filter(guest_filter_rules, guest_filter_rules_count,libdev, 0) == 0);
        libusb_unref_device(libdev);
        if (!filter_ok) {
            g_set_error_literal(err, SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,
                                _("Some USB devices are blocked by host policy"));
            return FALSE;
        }
    }

    /* Check if there are free channels */
    for (i = 0; i < priv->channels->len; i++) {
        SpiceUsbredirChannel *channel = g_ptr_array_index(priv->channels, i);
        spice_usbredir_channel_lock(channel);

        if (!spice_usbredir_channel_get_device(channel)){
            spice_usbredir_channel_unlock(channel);
            break;
        }
        spice_usbredir_channel_unlock(channel);
    }
    if (i == priv->channels->len) {
        g_set_error_literal(err, SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,_("There are no free USB channels"));
        return FALSE;
    }
    return TRUE;
}

/**
 * spice_usb_device_get_description:
 * @device: #SpiceUsbDevice to get the description of
 * @format: (allow-none): an optional printf() format string with
 * positional parameters
 *
 * Get a string describing the device which is suitable as a description of
 * the device for the end user. The returned string should be freed with
 * g_free() when no longer needed.
 *
 * The @format positional parameters are the following:
 * - '%%1$s' manufacturer
 * - '%%2$s' product
 * - '%%3$s' descriptor (a [vendor_id:product_id] string)
 * - '%%4$d' bus
 * - '%%5$d' address
 *
 * (the default format string is "%%s %%s %%s at %%d-%%d")
 *
 * Returns: a newly-allocated string holding the description, or %NULL if failed
 */
gchar *spice_usb_device_get_description(SpiceUsbDevice *device, const gchar *format)
{
    guint16 bus, address, vid, pid;
    gchar *description, *descriptor, *manufacturer = NULL, *product = NULL;

    g_return_val_if_fail(device != NULL, NULL);

    bus     = spice_usb_device_get_busnum(device);
    address = spice_usb_device_get_devaddr(device);
    vid     = spice_usb_device_get_vid(device);
    pid     = spice_usb_device_get_pid(device);

    if ((vid > 0) && (pid > 0)) {
        descriptor = g_strdup_printf("[%04x:%04x]", vid, pid);
    } else {
        descriptor = g_strdup("");
    }

    spice_usb_util_get_device_strings(bus, address, vid, pid,
                                      &manufacturer, &product);

    if (!format)
        format = _("%s %s %s at %d-%d");

    description = g_strdup_printf(format, manufacturer, product, descriptor, bus, address);

    g_free(manufacturer);
    g_free(descriptor);
    g_free(product);
    return description;
}

static gboolean probe_isochronous_endpoint(libusb_device *libdev)
{
    struct libusb_config_descriptor *conf_desc;
    gboolean isoc_found = FALSE;
    gint i, j, k;
    g_return_val_if_fail(libdev != NULL, FALSE);
    if (libusb_get_active_config_descriptor(libdev, &conf_desc) != 0) {
        g_return_val_if_reached(FALSE);
    }
    for (i = 0; !isoc_found && i < conf_desc->bNumInterfaces; i++) {
        for (j = 0; !isoc_found && j < conf_desc->interface[i].num_altsetting; j++) {
            for (k = 0; !isoc_found && k < conf_desc->interface[i].altsetting[j].bNumEndpoints;k++) {
                gint attributes = conf_desc->interface[i].altsetting[j].endpoint[k].bmAttributes;
                gint type = attributes & LIBUSB_TRANSFER_TYPE_MASK;
                if (type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
                    isoc_found = TRUE;
            }
        }
    }

    libusb_free_config_descriptor(conf_desc);
    return isoc_found;
}

/*
 * SpiceUsbDeviceInfo
 */
static SpiceUsbDeviceInfo *spice_usb_device_new(libusb_device *libdev)
{
    SpiceUsbDeviceInfo *info;
    int vid, pid;
    guint8 bus, addr;
    g_return_val_if_fail(libdev != NULL, NULL);
    bus = libusb_get_bus_number(libdev);
    addr = libusb_get_device_address(libdev);
    if (!spice_usb_device_manager_get_libdev_vid_pid(libdev, &vid, &pid)) {
        return NULL;
    }

    info = g_new0(SpiceUsbDeviceInfo, 1);

    info->busnum  = bus;
    info->devaddr = addr;
    info->vid = vid;
    info->pid = pid;
    info->ref = 1;
    info->isochronous = probe_isochronous_endpoint(libdev);
    info->libdev = libusb_ref_device(libdev);
    return info;
}

guint8 spice_usb_device_get_busnum(const SpiceUsbDevice *device)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;

    g_return_val_if_fail(info != NULL, 0);

    return info->busnum;
}

guint8 spice_usb_device_get_devaddr(const SpiceUsbDevice *device)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;

    g_return_val_if_fail(info != NULL, 0);

    return info->devaddr;
}

guint16 spice_usb_device_get_vid(const SpiceUsbDevice *device)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;
    g_return_val_if_fail(info != NULL, 0);
    return info->vid;
}

guint16 spice_usb_device_get_pid(const SpiceUsbDevice *device)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;
    g_return_val_if_fail(info != NULL, 0);
    return info->pid;
}

gboolean spice_usb_device_is_isochronous(const SpiceUsbDevice *device)
{
    const SpiceUsbDeviceInfo *info = (const SpiceUsbDeviceInfo *)device;
    g_return_val_if_fail(info != NULL, 0);
    return info->isochronous;
}

static SpiceUsbDevice *spice_usb_device_ref(SpiceUsbDevice *device)
{
    SpiceUsbDeviceInfo *info = (SpiceUsbDeviceInfo *)device;

    g_return_val_if_fail(info != NULL, NULL);
    g_atomic_int_inc(&info->ref);
    return device;
}

static void spice_usb_device_unref(SpiceUsbDevice *device)
{
    gboolean ref_count_is_0;
    SpiceUsbDeviceInfo *info = (SpiceUsbDeviceInfo *)device;
    g_return_if_fail(info != NULL);
    ref_count_is_0 = g_atomic_int_dec_and_test(&info->ref);
    if (ref_count_is_0) {
        libusb_unref_device(info->libdev);
        g_free(info);
    }
}

static gboolean spice_usb_manager_device_equal_libdev(SpiceUsbDeviceManager *manager,SpiceUsbDevice *device,libusb_device  *libdev)
{
    SpiceUsbDeviceInfo *info = (SpiceUsbDeviceInfo *)device;
    if ((device == NULL) || (libdev == NULL))
        return FALSE;
    return info->libdev == libdev;
}

/*
 * Caller must libusb_unref_device the libusb_device returned by this function.
 * Returns a libusb_device, or NULL upon failure
 */
static libusb_device *
spice_usb_device_manager_device_to_libdev(SpiceUsbDeviceManager *self,
                                          SpiceUsbDevice *device)
{

    /* Simply return a ref to the cached libdev */
    SpiceUsbDeviceInfo *info = (SpiceUsbDeviceInfo *)device;
    return libusb_ref_device(info->libdev);
}

