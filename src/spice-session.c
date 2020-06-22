#include "config.h"
#include <gio/gio.h>
#include <glib.h>
#include "common/ring.h"
#include "spice-client.h"
#include "spice-common.h"
#include "spice-channel-priv.h"
#include "spice-session-priv.h"
#include "gio-coroutine.h"
struct channel {
    SpiceChannel      *channel;
    RingItem          link;
};

struct _SpiceSessionPrivate {
    char              *host;
    char              *port;
    int               connection_id;
    int               protocol;
    SpiceChannel      *cmain; /* weak reference */
    Ring              channels;
    gboolean          client_provided_sockets;
    guint             disconnecting;
    SpiceUsbDeviceManager *usb_manager;
};

#define SPICE_SESSION_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SPICE_TYPE_SESSION, SpiceSessionPrivate))
G_DEFINE_TYPE (SpiceSession, spice_session, G_TYPE_OBJECT);

/* Properties */
enum {
    PROP_0,
    PROP_HOST,
    PROP_PORT, 
    PROP_PROTOCOL, 
    PROP_CLIENT_SOCKETS,
};

/* signals */
enum {
    SPICE_SESSION_CHANNEL_NEW,
    SPICE_SESSION_CHANNEL_DESTROY, 
    SPICE_SESSION_LAST_SIGNAL,
};

static guint signals[SPICE_SESSION_LAST_SIGNAL];
static void spice_session_channel_destroy(SpiceSession *session, SpiceChannel *channel);
static void spice_session_init(SpiceSession *session)
{
    SpiceSessionPrivate *s;
    s = session->priv = SPICE_SESSION_GET_PRIVATE(session);
    ring_init(&s->channels);	
}

static void session_disconnect(SpiceSession *self, gboolean keep_main)
{
    SpiceSessionPrivate *s;
    struct channel *item;
    RingItem *ring, *next;
    s = self->priv;
    for (ring = ring_get_head(&s->channels); ring != NULL; ring = next) {
        next = ring_next(&s->channels, ring);
        item = SPICE_CONTAINEROF(ring, struct channel, link);
        if (keep_main && item->channel == s->cmain) {
            spice_channel_disconnect(item->channel, SPICE_CHANNEL_NONE);
        } else {
            spice_session_channel_destroy(self, item->channel); 
        }
    }
    s->connection_id = 0;
}

static void spice_session_dispose(GObject *gobject)
{
    SpiceSession *session = SPICE_SESSION(gobject);
    SpiceSessionPrivate *s = session->priv;
    session_disconnect(session, FALSE);
    g_warn_if_fail(s->disconnecting == 0);
    g_clear_object(&s->usb_manager);
    if (G_OBJECT_CLASS(spice_session_parent_class)->dispose)
        G_OBJECT_CLASS(spice_session_parent_class)->dispose(gobject);
}

static void spice_session_finalize(GObject *gobject)
{
    SpiceSession *session = SPICE_SESSION(gobject);
    SpiceSessionPrivate *s = session->priv;
    g_free(s->host);
    g_free(s->port);
    if (G_OBJECT_CLASS(spice_session_parent_class)->finalize)
        G_OBJECT_CLASS(spice_session_parent_class)->finalize(gobject);
}

static void spice_session_get_property(GObject    *gobject,guint prop_id,GValue  *value,GParamSpec *pspec)
{
    SpiceSession *session = SPICE_SESSION(gobject);
    SpiceSessionPrivate *s = session->priv;
    switch (prop_id) {
    case PROP_HOST:
        g_value_set_string(value, s->host);
	break;
    case PROP_PORT:
        g_value_set_string(value, s->port);
	break;
    case PROP_PROTOCOL:
        g_value_set_int(value, s->protocol);
	break;
    case PROP_CLIENT_SOCKETS:
        g_value_set_boolean(value, s->client_provided_sockets);
	break;
    default:
	G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
	break;
    }
}

static void spice_session_set_property(GObject  *gobject,guint prop_id,const GValue *value,GParamSpec   *pspec)
{
    SpiceSession *session = SPICE_SESSION(gobject);
    SpiceSessionPrivate *s = session->priv;
    switch (prop_id) {
    case PROP_HOST:
        g_free(s->host);
        s->host = g_value_dup_string(value);
        break;
    case PROP_PORT:
        g_free(s->port);
        s->port = g_value_dup_string(value);
        break;
    case PROP_PROTOCOL:
        s->protocol = g_value_get_int(value);
        break;
    case PROP_CLIENT_SOCKETS:
        s->client_provided_sockets = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
        break;
    }
}

static void spice_session_class_init(SpiceSessionClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
    gobject_class->dispose      = spice_session_dispose;
    gobject_class->finalize     = spice_session_finalize;
    gobject_class->get_property = spice_session_get_property;
    gobject_class->set_property = spice_session_set_property;
    g_object_class_install_property
        (gobject_class, PROP_HOST,
         g_param_spec_string("host",
                             "Host",
                             "Remote host",
                             "localhost",
                             G_PARAM_READWRITE |
                             G_PARAM_CONSTRUCT |
                             G_PARAM_STATIC_STRINGS));
    g_object_class_install_property
        (gobject_class, PROP_PORT,
         g_param_spec_string("port",
                             "Port",
                             "Remote port (plaintext)",
                             NULL,
                             G_PARAM_READWRITE |
                             G_PARAM_STATIC_STRINGS));
    g_object_class_install_property
        (gobject_class, PROP_PROTOCOL,
         g_param_spec_int("protocol",
                          "Protocol",
                          "Spice protocol major version",
                          1, 2, 2,
                          G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT |
                          G_PARAM_STATIC_STRINGS));
    g_object_class_install_property
        (gobject_class, PROP_CLIENT_SOCKETS,
         g_param_spec_boolean("client-sockets",
                          "Client sockets",
                          "Sockets are provided by the client",
                          FALSE,
                          G_PARAM_READWRITE |
                          G_PARAM_STATIC_STRINGS));
    signals[SPICE_SESSION_CHANNEL_NEW] =
        g_signal_new("channel-new",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceSessionClass, channel_new),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__OBJECT,
                     G_TYPE_NONE,
                     1,
                     SPICE_TYPE_CHANNEL);
    signals[SPICE_SESSION_CHANNEL_DESTROY] =
        g_signal_new("channel-destroy",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceSessionClass, channel_destroy),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__OBJECT,
                     G_TYPE_NONE,
                     1,
                     SPICE_TYPE_CHANNEL);
    g_type_class_add_private(klass, sizeof(SpiceSessionPrivate));
}
                                           

/**
 * spice_session_new:
 *
 * Creates a new Spice session.
 *
 * Returns: a new #SpiceSession
 **/
SpiceSession *spice_session_new(void)
{
    return SPICE_SESSION(g_object_new(SPICE_TYPE_SESSION, NULL));
}

/**
 * spice_session_connect:
 * @session: a #SpiceSession
 *
 * Open the session using the #SpiceSession:host and
 * #SpiceSession:port.
 *
 * Returns: %FALSE if the session state is invalid for connection
 * request. %TRUE if the connection is initiated. To know whether the
 * connection is established, you must watch for channels creation
 * (#SpiceSession::channel-new) and the channels state
 * (#SpiceChannel::channel-event).
 **/
 
gboolean spice_session_connect(SpiceSession *session)
{
    SpiceSessionPrivate *s;
    g_return_val_if_fail(SPICE_IS_SESSION(session), FALSE);
    s = session->priv;
    g_return_val_if_fail(!s->disconnecting, FALSE);
    s->client_provided_sockets = FALSE;
    if (s->cmain == NULL){
        s->cmain = spice_channel_new(session, SPICE_CHANNEL_MAIN, 0);
    	}
    return spice_channel_connect(s->cmain);
}

/**
 * spice_session_open_fd:
 * @session: a #SpiceSession
 * @fd: a file descriptor (socket) or -1
 *
 * Open the session using the provided @fd socket file
 * descriptor. This is useful if you create the fd yourself, for
 * example to setup a SSH tunnel.
 *
 * Note however that additional sockets will be needed by all the channels
 * created for @session so users of this API should hook into
 * SpiceChannel::open-fd signal for each channel they are interested in, and
 * create and pass a new socket to the channel using #spice_channel_open_fd, in
 * the signal callback.
 *
 * If @fd is -1, a valid fd will be requested later via the
 * SpiceChannel::open-fd signal. Typically, you would want to just pass -1 as
 * @fd this call since you will have to hook to SpiceChannel::open-fd signal
 * anyway.
 *
 * Returns: %TRUE on success.
 **/
gboolean spice_session_open_fd(SpiceSession *session, int fd)
{
    SpiceSessionPrivate *s;

    g_return_val_if_fail(SPICE_IS_SESSION(session), FALSE);
    g_return_val_if_fail(fd >= -1, FALSE);
    s = session->priv;
    g_return_val_if_fail(!s->disconnecting, FALSE);
    session_disconnect(session, TRUE);
    s->client_provided_sockets = TRUE;
    if (s->cmain == NULL)
        s->cmain = spice_channel_new(session, SPICE_CHANNEL_MAIN, 0);
    return spice_channel_open_fd(s->cmain, fd);
}

G_GNUC_INTERNAL
gboolean spice_session_get_client_provided_socket(SpiceSession *session)
{
    g_return_val_if_fail(SPICE_IS_SESSION(session), FALSE);
    SpiceSessionPrivate *s = session->priv;
    return s->client_provided_sockets;
}

G_GNUC_INTERNAL
SpiceChannel* spice_session_lookup_channel(SpiceSession *session, gint id, gint type)
{
    g_return_val_if_fail(SPICE_IS_SESSION(session), NULL);
    RingItem *ring, *next;
    SpiceSessionPrivate *s = session->priv;
    struct channel *c;
    for (ring = ring_get_head(&s->channels); ring != NULL; ring = next) {
        next = ring_next(&s->channels, ring);
        c = SPICE_CONTAINEROF(ring, struct channel, link);
	  if (c == NULL || c->channel == NULL) {
            g_warn_if_reached();
            continue;
        } 
        if (id == spice_channel_get_channel_id(c->channel) &&type == spice_channel_get_channel_type(c->channel))
            break;
    }
    g_return_val_if_fail(ring != NULL, NULL);
    return c->channel;
}

static gboolean session_disconnect_idle(SpiceSession *self)
{
    SpiceSessionPrivate *s = self->priv;
    session_disconnect(self, FALSE);
    s->disconnecting = 0;
    g_object_unref(self);
    return FALSE;
}

void spice_session_disconnect(SpiceSession *session)
{
    SpiceSessionPrivate *s;
    g_return_if_fail(SPICE_IS_SESSION(session));
    s = session->priv;
    if (s->disconnecting != 0)
        return;
    g_object_ref(session);
    s->disconnecting = g_idle_add((GSourceFunc)session_disconnect_idle, session);
}

GList *spice_session_get_channels(SpiceSession *session)
{
    SpiceSessionPrivate *s;
    struct channel *item;
    GList *list = NULL;
    RingItem *ring;
    g_return_val_if_fail(SPICE_IS_SESSION(session), NULL);
    g_return_val_if_fail(session->priv != NULL, NULL);
    s = session->priv;
    for (ring = ring_get_head(&s->channels);
         ring != NULL;
         ring = ring_next(&s->channels, ring)) {
        item = SPICE_CONTAINEROF(ring, struct channel, link);
        list = g_list_append(list, item->channel);
    }
    return list;
}

typedef struct spice_open_host spice_open_host;
struct spice_open_host {
    struct coroutine *from;
    SpiceSession *session;
    SpiceChannel *channel;
    int port;
    GCancellable *cancellable;
    GError *error;
    GSocketConnection *connection;
    GSocketClient *client;
};

static void socket_client_connect_ready(GObject *source_object, GAsyncResult *result,gpointer data)
{
    GSocketClient *client = G_SOCKET_CLIENT(source_object);
    spice_open_host *open_host = data;
    GSocketConnection *connection = NULL;
    connection = g_socket_client_connect_finish(client, result, &open_host->error);
    open_host->connection = connection;
    coroutine_yieldto(open_host->from, NULL);
}

/* main context */
static void open_host_connectable_connect(spice_open_host *open_host, GSocketConnectable *connectable)
{
    g_socket_client_connect_async(open_host->client, connectable,open_host->cancellable,socket_client_connect_ready, open_host);
}


static gboolean open_host_idle_cb(gpointer data)
{
    spice_open_host *open_host = data;
    SpiceSessionPrivate *s;
    g_return_val_if_fail(open_host != NULL, FALSE);
    g_return_val_if_fail(open_host->connection == NULL, FALSE);
    if (spice_channel_get_session(open_host->channel) != open_host->session)
        return FALSE;
    s = open_host->session->priv;
    GSocketConnectable *address = NULL;
    address = g_network_address_parse(s->host, open_host->port, &open_host->error);
    open_host_connectable_connect(open_host, address);
    g_object_unref(address);
    return FALSE;
}

#define SOCKET_TIMEOUT 10

/* coroutine context */
G_GNUC_INTERNAL
GSocketConnection* spice_session_channel_open_host(SpiceSession *session, SpiceChannel *channel,gboolean *use_tls, GError **error)
{
    g_return_val_if_fail(SPICE_IS_SESSION(session), NULL);
    SpiceSessionPrivate *s = session->priv;
    spice_open_host open_host = { 0, };
    gchar *port, *endptr;	
    open_host.from = coroutine_self();
    open_host.session = session;
    open_host.channel = channel;
    port = s->port;
    open_host.port = strtol(port, &endptr, 10);
    open_host.client = g_socket_client_new();
    g_socket_client_set_timeout(open_host.client, SOCKET_TIMEOUT);
    g_idle_add(open_host_idle_cb, &open_host);
    coroutine_yield(NULL);
    GSocket *socket;
    socket = g_socket_connection_get_socket(open_host.connection);
	
	if(socket == NULL){
		printf("+++++Usb-redir create socket failed Please check network+++++\n");
		fflush(stdout);
		exit(1);
	};
	
    g_socket_set_timeout(socket, 0);
    g_socket_set_blocking(socket, FALSE);
    g_socket_set_keepalive(socket, TRUE);
    g_clear_object(&open_host.client);
    return open_host.connection;
}


G_GNUC_INTERNAL
void spice_session_channel_new(SpiceSession *session, SpiceChannel *channel)
{
    g_return_if_fail(SPICE_IS_SESSION(session));
    g_return_if_fail(SPICE_IS_CHANNEL(channel));
    SpiceSessionPrivate *s = session->priv;
    struct channel *item;
    item = g_new0(struct channel, 1);
    item->channel = channel;
    ring_add(&s->channels, &item->link);
    g_signal_emit(session, signals[SPICE_SESSION_CHANNEL_NEW], 0, channel);
}


static void spice_session_channel_destroy(SpiceSession *session, SpiceChannel *channel)
{
    g_return_if_fail(SPICE_IS_SESSION(session));
    g_return_if_fail(SPICE_IS_CHANNEL(channel));
    SpiceSessionPrivate *s = session->priv;
    struct channel *item = NULL;
    RingItem *ring;
    for (ring = ring_get_head(&s->channels); ring != NULL;
         ring = ring_next(&s->channels, ring)) {
        item = SPICE_CONTAINEROF(ring, struct channel, link);
        if (item->channel == channel)
            break;
    }
    g_return_if_fail(ring != NULL);
    if (channel == s->cmain) {
        CHANNEL_DEBUG(channel, "the session lost the main channel");
        s->cmain = NULL;
    }
    ring_remove(&item->link);
    free(item);
    g_signal_emit(session, signals[SPICE_SESSION_CHANNEL_DESTROY], 0, channel);
    g_clear_object(&channel->priv->session);
    spice_channel_disconnect(channel, SPICE_CHANNEL_NONE);
    g_object_unref(channel);
}

G_GNUC_INTERNAL
void spice_session_set_connection_id(SpiceSession *session, int id)
{
    g_return_if_fail(SPICE_IS_SESSION(session));
    SpiceSessionPrivate *s = session->priv;
    s->connection_id = id;
}

G_GNUC_INTERNAL
int spice_session_get_connection_id(SpiceSession *session)
{
    g_return_val_if_fail(SPICE_IS_SESSION(session), -1);
    SpiceSessionPrivate *s = session->priv;
    return s->connection_id;
}

SpiceUsbDeviceManager *spice_usb_device_manager_get(SpiceSession *session,GError **err)
{
    SpiceUsbDeviceManager *self;
    static GMutex mutex;
    g_return_val_if_fail(SPICE_IS_SESSION(session), NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);
    g_mutex_lock(&mutex);
    self = session->priv->usb_manager;
    if (self == NULL) {
        self = g_initable_new(SPICE_TYPE_USB_DEVICE_MANAGER, NULL, err,"session", session, NULL);
        session->priv->usb_manager = self;
    } 
    g_mutex_unlock(&mutex);
    return self;
}

