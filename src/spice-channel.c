#include "config.h"

#include "spice-client.h"
#include "spice-common.h"

#include "spice-channel-priv.h"
#include "spice-session-priv.h"
#include "spice-marshal.h"
//#include "bio-gio.h"

#include <glib/gi18n-lib.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_NODELAY
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <ctype.h>

#include "gio-coroutine.h"

static void spice_channel_handle_msg(SpiceChannel *channel, SpiceMsgIn *msg);
static void spice_channel_write_msg(SpiceChannel *channel, SpiceMsgOut *out);
static void spice_channel_send_link(SpiceChannel *channel);
static void channel_reset(SpiceChannel *channel, gboolean migrating);
static void spice_channel_reset_capabilities(SpiceChannel *channel);
static gboolean channel_connect(SpiceChannel *channel, gboolean tls);

#if OPENSSL_VERSION_NUMBER < 0x10100000
static RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA) {
        return NULL;
    }
    return pkey->pkey.rsa;
}
#endif


#define SPICE_CHANNEL_GET_PRIVATE(obj)     (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SPICE_TYPE_CHANNEL, SpiceChannelPrivate))
G_DEFINE_TYPE_WITH_CODE (SpiceChannel, spice_channel, G_TYPE_OBJECT,g_type_add_class_private (g_define_type_id, sizeof (SpiceChannelClassPrivate)));
/* Properties */
enum {
    PROP_0,
    PROP_SESSION,
    PROP_CHANNEL_TYPE,
    PROP_CHANNEL_ID,
    PROP_TOTAL_READ_BYTES,
    PROP_SOCKET,
};

/* Signals */
enum {
    SPICE_CHANNEL_EVENT,
    SPICE_CHANNEL_OPEN_FD,
    SPICE_CHANNEL_LAST_SIGNAL,
};

static guint signals[SPICE_CHANNEL_LAST_SIGNAL];

static void spice_channel_iterate_write(SpiceChannel *channel);
static void spice_channel_iterate_read(SpiceChannel *channel);

static void spice_channel_init(SpiceChannel *channel)
{
    SpiceChannelPrivate *c;
    c = channel->priv = SPICE_CHANNEL_GET_PRIVATE(channel);
    c->out_serial = 1;
    c->in_serial = 1;
    c->fd = -1;
    c->auth_needs_username = FALSE;
    c->auth_needs_password = FALSE;
    strcpy(c->name, "?");
    c->caps = g_array_new(FALSE, TRUE, sizeof(guint32));
    c->common_caps = g_array_new(FALSE, TRUE, sizeof(guint32));
    c->remote_caps = g_array_new(FALSE, TRUE, sizeof(guint32));
    c->remote_common_caps = g_array_new(FALSE, TRUE, sizeof(guint32));
	
    spice_channel_set_common_capability(channel, SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION);
    spice_channel_set_common_capability(channel, SPICE_COMMON_CAP_MINI_HEADER);
    g_queue_init(&c->xmit_queue);
    g_mutex_init(&c->xmit_queue_lock);
  
   
}

static void spice_channel_constructed(GObject *gobject)
{
    SpiceChannel *channel = SPICE_CHANNEL(gobject);
    SpiceChannelPrivate *c = channel->priv;
    const char *desc = spice_channel_type_to_string(c->channel_type);
    snprintf(c->name, sizeof(c->name), "%s-%d:%d",desc, c->channel_type, c->channel_id);
    const char *disabled  = g_getenv("SPICE_DISABLE_CHANNELS");
    if (disabled && strstr(disabled, desc))
        c->disable_channel_msg = TRUE;
    spice_session_channel_new(c->session, channel);

    /* Chain up to the parent class */
    if (G_OBJECT_CLASS(spice_channel_parent_class)->constructed)
        G_OBJECT_CLASS(spice_channel_parent_class)->constructed(gobject);
}

static void spice_channel_dispose(GObject *gobject)
{
    SpiceChannel *channel = SPICE_CHANNEL(gobject);
    SpiceChannelPrivate *c = channel->priv;

    CHANNEL_DEBUG(channel, "%s %p", __FUNCTION__, gobject);

    spice_channel_disconnect(channel, SPICE_CHANNEL_CLOSED);

    g_clear_object(&c->session);

    g_clear_error(&c->error);

    /* Chain up to the parent class */
    if (G_OBJECT_CLASS(spice_channel_parent_class)->dispose)
        G_OBJECT_CLASS(spice_channel_parent_class)->dispose(gobject);
}

static void spice_channel_finalize(GObject *gobject)
{
    SpiceChannel *channel = SPICE_CHANNEL(gobject);
    SpiceChannelPrivate *c = channel->priv;

    CHANNEL_DEBUG(channel, "%s %p", __FUNCTION__, gobject);

    g_idle_remove_by_data(gobject);

    g_mutex_clear(&c->xmit_queue_lock);

    if (c->caps)
        g_array_free(c->caps, TRUE);

    if (c->common_caps)
        g_array_free(c->common_caps, TRUE);

    if (c->remote_caps)
        g_array_free(c->remote_caps, TRUE);

    if (c->remote_common_caps)
        g_array_free(c->remote_common_caps, TRUE);

    g_clear_pointer(&c->peer_msg, g_free);

    /* Chain up to the parent class */
    if (G_OBJECT_CLASS(spice_channel_parent_class)->finalize)
        G_OBJECT_CLASS(spice_channel_parent_class)->finalize(gobject);
}

static void spice_channel_get_property(GObject    *gobject,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{
    SpiceChannel *channel = SPICE_CHANNEL(gobject);
    SpiceChannelPrivate *c = channel->priv;

    switch (prop_id) {
    case PROP_SESSION:
        g_value_set_object(value, c->session);
        break;
    case PROP_CHANNEL_TYPE:
        g_value_set_int(value, c->channel_type);
        break;
    case PROP_CHANNEL_ID:
        g_value_set_int(value, c->channel_id);
        break;
    case PROP_TOTAL_READ_BYTES:
        g_value_set_ulong(value, c->total_read_bytes);
        break;
    case PROP_SOCKET:
        g_value_set_object(value, c->sock);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
        break;
    }
}

G_GNUC_INTERNAL
gint spice_channel_get_channel_id(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;

    g_return_val_if_fail(c != NULL, 0);
    return c->channel_id;
}

G_GNUC_INTERNAL
gint spice_channel_get_channel_type(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;

    g_return_val_if_fail(c != NULL, 0);
    return c->channel_type;
}

static void spice_channel_set_property(GObject      *gobject,
                                       guint         prop_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
    SpiceChannel *channel = SPICE_CHANNEL(gobject);
    SpiceChannelPrivate *c = channel->priv;

    switch (prop_id) {
    case PROP_SESSION:
        c->session = g_value_dup_object(value);
        break;
    case PROP_CHANNEL_TYPE:
        c->channel_type = g_value_get_int(value);
        break;
    case PROP_CHANNEL_ID:
        c->channel_id = g_value_get_int(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(gobject, prop_id, pspec);
        break;
    }
}

static void spice_channel_class_init(SpiceChannelClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

    klass->iterate_write = spice_channel_iterate_write;
    klass->iterate_read  = spice_channel_iterate_read;
    klass->channel_reset = channel_reset;

    gobject_class->constructed  = spice_channel_constructed;
    gobject_class->dispose      = spice_channel_dispose;
    gobject_class->finalize     = spice_channel_finalize;
    gobject_class->get_property = spice_channel_get_property;
    gobject_class->set_property = spice_channel_set_property;
    klass->handle_msg           = spice_channel_handle_msg;

    g_object_class_install_property
        (gobject_class, PROP_SESSION,
         g_param_spec_object("spice-session",
                             "Spice session",
                             "Spice session",
                             SPICE_TYPE_SESSION,
                             G_PARAM_READWRITE |
                             G_PARAM_CONSTRUCT_ONLY |
                             G_PARAM_STATIC_STRINGS));

    g_object_class_install_property
        (gobject_class, PROP_CHANNEL_TYPE,
         g_param_spec_int("channel-type",
                          "Channel type",
                          "Channel type",
                          -1, INT_MAX, -1,
                          G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

    g_object_class_install_property
        (gobject_class, PROP_CHANNEL_ID,
         g_param_spec_int("channel-id",
                          "Channel ID",
                          "Channel ID",
                          -1, INT_MAX, -1,
                          G_PARAM_READWRITE |
                          G_PARAM_CONSTRUCT_ONLY |
                          G_PARAM_STATIC_STRINGS));

    g_object_class_install_property
        (gobject_class, PROP_TOTAL_READ_BYTES,
         g_param_spec_ulong("total-read-bytes",
                            "Total read bytes",
                            "Total read bytes",
                            0, G_MAXULONG, 0,
                            G_PARAM_READABLE |
                            G_PARAM_STATIC_STRINGS));

    /**
     * SpiceChannel:socket:
     *
     * Get the underlying #GSocket. Note that you should not read or
     * write any data to it directly since this will likely corrupt
     * the channel stream.  This property is mainly useful to get some
     * connections details.
     *
     * Since: 0.33
     */
    g_object_class_install_property
        (gobject_class, PROP_SOCKET,
         g_param_spec_object("socket",
                             "Socket",
                             "Underlying GSocket",
                             G_TYPE_SOCKET,
                             G_PARAM_READABLE |
                             G_PARAM_STATIC_STRINGS));

    /**
     * SpiceChannel::channel-event:
     * @channel: the channel that emitted the signal
     * @event: a #SpiceChannelEvent
     *
     * The #SpiceChannel::channel-event signal is emitted when the
     * state of the connection is changed. In case of errors,
     * spice_channel_get_error() may provide additional informations
     * on the source of the error.
     **/
    signals[SPICE_CHANNEL_EVENT] =
        g_signal_new("channel-event",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceChannelClass, channel_event),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__ENUM,
                     G_TYPE_NONE,
                     1,
                     SPICE_TYPE_CHANNEL_EVENT);

    /**
     * SpiceChannel::open-fd:
     * @channel: the channel that emitted the signal
     * @with_tls: wether TLS connection is requested
     *
     * The #SpiceChannel::open-fd signal is emitted when a new
     * connection is requested. This signal is emitted when the
     * connection is made with spice_session_open_fd().
     **/
    signals[SPICE_CHANNEL_OPEN_FD] =
        g_signal_new("open-fd",
                     G_OBJECT_CLASS_TYPE(gobject_class),
                     G_SIGNAL_RUN_FIRST,
                     G_STRUCT_OFFSET(SpiceChannelClass, open_fd),
                     NULL, NULL,
                     g_cclosure_marshal_VOID__INT,
                     G_TYPE_NONE,
                     1,
                     G_TYPE_INT);

    g_type_class_add_private(klass, sizeof(SpiceChannelPrivate));
 
}

/* ---------------------------------------------------------------- */
/* private header api                                               */

static inline void spice_header_set_msg_type(uint8_t *header, gboolean is_mini_header,
                                             uint16_t type)
{
    if (is_mini_header) {
        ((SpiceMiniDataHeader *)header)->type = GUINT16_TO_LE(type);
    } else {
        ((SpiceDataHeader *)header)->type = GUINT16_TO_LE(type);
    }
}

static inline void spice_header_set_msg_size(uint8_t *header, gboolean is_mini_header,
                                             uint32_t size)
{
    if (is_mini_header) {
        ((SpiceMiniDataHeader *)header)->size = GUINT32_TO_LE(size);
    } else {
        ((SpiceDataHeader *)header)->size = GUINT32_TO_LE(size);
    }
}

G_GNUC_INTERNAL
uint16_t spice_header_get_msg_type(uint8_t *header, gboolean is_mini_header)
{
    if (is_mini_header) {
        return GUINT16_FROM_LE(((SpiceMiniDataHeader *)header)->type);
    } else {
        return GUINT16_FROM_LE(((SpiceDataHeader *)header)->type);
    }
}

G_GNUC_INTERNAL
uint32_t spice_header_get_msg_size(uint8_t *header, gboolean is_mini_header)
{
    if (is_mini_header) {
        return GUINT32_FROM_LE(((SpiceMiniDataHeader *)header)->size);
    } else {
        return GUINT32_FROM_LE(((SpiceDataHeader *)header)->size);
    }
}

static inline int spice_header_get_header_size(gboolean is_mini_header)
{
    return is_mini_header ? sizeof(SpiceMiniDataHeader) : sizeof(SpiceDataHeader);
}

static inline void spice_header_set_msg_serial(uint8_t *header, gboolean is_mini_header,
                                               uint64_t serial)
{
    if (!is_mini_header) {
        ((SpiceDataHeader *)header)->serial = GUINT64_TO_LE(serial);
    }
}

static inline void spice_header_reset_msg_sub_list(uint8_t *header, gboolean is_mini_header)
{
    if (!is_mini_header) {
        ((SpiceDataHeader *)header)->sub_list = 0;
    }
}

static inline uint64_t spice_header_get_in_msg_serial(SpiceMsgIn *in)
{
    SpiceChannelPrivate *c = in->channel->priv;
    uint8_t *header = in->header;

    if (c->use_mini_header) {
        return c->in_serial;
    } else {
        return ((SpiceDataHeader *)header)->serial;
    }
}

static inline uint64_t spice_header_get_out_msg_serial(SpiceMsgOut *out)
{
    SpiceChannelPrivate *c = out->channel->priv;

    if (c->use_mini_header) {
        return c->out_serial;
    } else {
        return ((SpiceDataHeader *)out->header)->serial;
    }
}

static inline uint32_t spice_header_get_msg_sub_list(uint8_t *header, gboolean is_mini_header)
{
    if (is_mini_header) {
        return 0;
    } else {
        return GUINT32_FROM_LE(((SpiceDataHeader *)header)->sub_list);
    }
}



G_GNUC_INTERNAL
SpiceMsgIn *spice_msg_in_new(SpiceChannel *channel)
{
    SpiceMsgIn *in;

    g_return_val_if_fail(channel != NULL, NULL);

    in = g_new0(SpiceMsgIn, 1);
    in->refcount = 1;
    in->channel  = channel;

    return in;
}

G_GNUC_INTERNAL
SpiceMsgIn *spice_msg_in_sub_new(SpiceChannel *channel, SpiceMsgIn *parent,
                                   SpiceSubMessage *sub)
{
    SpiceMsgIn *in;

    g_return_val_if_fail(channel != NULL, NULL);

    in = spice_msg_in_new(channel);
    spice_header_set_msg_type(in->header, channel->priv->use_mini_header, sub->type);
    spice_header_set_msg_size(in->header, channel->priv->use_mini_header, sub->size);
    in->data = (uint8_t*)(sub+1);
    in->dpos = sub->size;
    in->parent = parent;
    spice_msg_in_ref(parent);
    return in;
}

G_GNUC_INTERNAL
void spice_msg_in_ref(SpiceMsgIn *in)
{
    g_return_if_fail(in != NULL);

    in->refcount++;
}

G_GNUC_INTERNAL
void spice_msg_in_unref(SpiceMsgIn *in)
{
    g_return_if_fail(in != NULL);

    in->refcount--;
    if (in->refcount > 0)
        return;
    if (in->parsed)
        in->pfree(in->parsed);
    if (in->parent) {
        spice_msg_in_unref(in->parent);
    } else {
        g_free(in->data);
    }
    g_free(in);
}

G_GNUC_INTERNAL
int spice_msg_in_type(SpiceMsgIn *in)
{
    g_return_val_if_fail(in != NULL, -1);
    return spice_header_get_msg_type(in->header, in->channel->priv->use_mini_header);
}

G_GNUC_INTERNAL
void *spice_msg_in_parsed(SpiceMsgIn *in)
{
    g_return_val_if_fail(in != NULL, NULL);
    return in->parsed;
}

G_GNUC_INTERNAL
void *spice_msg_in_raw(SpiceMsgIn *in, int *len)
{
    g_return_val_if_fail(in != NULL, NULL);
    g_return_val_if_fail(len != NULL, NULL);

    *len = in->dpos;
    return in->data;
}

static void hexdump(const char *prefix, unsigned char *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            fprintf(stderr, "%s:", prefix);
        if (i % 4 == 0)
            fprintf(stderr, " ");
        fprintf(stderr, " %02x", data[i]);
        if (i % 16 == 15)
            fprintf(stderr, "\n");
    }
    if (i % 16 != 0)
        fprintf(stderr, "\n");
}

G_GNUC_INTERNAL
void spice_msg_in_hexdump(SpiceMsgIn *in)
{
    SpiceChannelPrivate *c = in->channel->priv;

    fprintf(stderr, "--\n<< hdr: %s serial %" PRIu64 " type %u size %u sub-list %u\n",
            c->name, spice_header_get_in_msg_serial(in),
            spice_header_get_msg_type(in->header, c->use_mini_header),
            spice_header_get_msg_size(in->header, c->use_mini_header),
            spice_header_get_msg_sub_list(in->header, c->use_mini_header));
    hexdump("<< msg", in->data, in->dpos);
}

G_GNUC_INTERNAL
void spice_msg_out_hexdump(SpiceMsgOut *out, unsigned char *data, int len)
{
    SpiceChannelPrivate *c = out->channel->priv;

    fprintf(stderr, "--\n>> hdr: %s serial %" PRIu64 " type %u size %u sub-list %u\n",
            c->name,
            spice_header_get_out_msg_serial(out),
            spice_header_get_msg_type(out->header, c->use_mini_header),
            spice_header_get_msg_size(out->header, c->use_mini_header),
            spice_header_get_msg_sub_list(out->header, c->use_mini_header));
    hexdump(">> msg", data, len);
}

static gboolean msg_check_read_only (int channel_type, int msg_type)
{
    if (msg_type < 100) // those are the common messages
            return FALSE;
    switch (channel_type) {
    case SPICE_CHANNEL_MAIN:
		        switch (msg_type) {
		        case SPICE_MSGC_MAIN_CLIENT_INFO:
		        case SPICE_MSGC_MAIN_ATTACH_CHANNELS:
		        return FALSE;
		        }
		        break;
    }
    return TRUE;
}

G_GNUC_INTERNAL
SpiceMsgOut *spice_msg_out_new(SpiceChannel *channel, int type)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgOut *out;

    g_return_val_if_fail(c != NULL, NULL);

    out = g_new0(SpiceMsgOut, 1);
    out->refcount = 1;
    out->channel  = channel;
    out->ro_check = msg_check_read_only(c->channel_type, type);

    out->marshallers = c->marshallers;
    out->marshaller = spice_marshaller_new();

    out->header = spice_marshaller_reserve_space(out->marshaller,spice_header_get_header_size(c->use_mini_header));
    spice_marshaller_set_base(out->marshaller, spice_header_get_header_size(c->use_mini_header));
    spice_header_set_msg_type(out->header, c->use_mini_header, type);
    spice_header_set_msg_serial(out->header, c->use_mini_header, c->out_serial);
    spice_header_reset_msg_sub_list(out->header, c->use_mini_header);

    c->out_serial++;
    return out;
}

G_GNUC_INTERNAL
void spice_msg_out_ref(SpiceMsgOut *out)
{
    g_return_if_fail(out != NULL);

    out->refcount++;
}

G_GNUC_INTERNAL
void spice_msg_out_unref(SpiceMsgOut *out)
{
    g_return_if_fail(out != NULL);

    out->refcount--;
    if (out->refcount > 0)
        return;
    spice_marshaller_destroy(out->marshaller);
    g_free(out);
}

static gboolean spice_channel_idle_wakeup(gpointer user_data)
{
    SpiceChannel *channel = SPICE_CHANNEL(user_data);
    SpiceChannelPrivate *c = channel->priv;
    g_mutex_lock(&c->xmit_queue_lock);
    c->xmit_queue_wakeup_id = 0;
    g_mutex_unlock(&c->xmit_queue_lock);
    spice_channel_wakeup(channel, FALSE);
    return FALSE;
}

/* any context (system/co-routine/usb-event-thread) */
G_GNUC_INTERNAL
void spice_msg_out_send(SpiceMsgOut *out)
{
    SpiceChannelPrivate *c;
    gboolean was_empty;
    guint32 size;

    g_return_if_fail(out != NULL);
    g_return_if_fail(out->channel != NULL);
    c = out->channel->priv;
    size = spice_marshaller_get_total_size(out->marshaller);

    g_mutex_lock(&c->xmit_queue_lock);
    if (c->xmit_queue_blocked) {
        g_warning("message queue is blocked, dropping message");
        goto end;
    }

    was_empty = g_queue_is_empty(&c->xmit_queue);
    g_queue_push_tail(&c->xmit_queue, out);
    c->xmit_queue_size = (was_empty) ? size : c->xmit_queue_size + size;

    /* One wakeup is enough to empty the entire queue -> only do a wakeup
       if the queue was empty, and there isn't one pending already. */
    if (was_empty && !c->xmit_queue_wakeup_id) {
        c->xmit_queue_wakeup_id =
            /* Use g_timeout_add_full so that can specify the priority */
            g_timeout_add_full(G_PRIORITY_HIGH, 0,
                               spice_channel_idle_wakeup,
                               out->channel, NULL);
    }

end:
    g_mutex_unlock(&c->xmit_queue_lock);
}

/* coroutine context */
G_GNUC_INTERNAL
void spice_msg_out_send_internal(SpiceMsgOut *out)
{
    g_return_if_fail(out != NULL);
    spice_channel_write_msg(out->channel, out);
}


static gint spice_channel_flush_wire_nonblocking(SpiceChannel *channel,
                                                 const gchar *ptr,
                                                 size_t len,
                                                 GIOCondition *cond)
{
    SpiceChannelPrivate *c = channel->priv;
    gssize ret;

    g_assert(cond != NULL);
    *cond = 0;

    if (c->tls) {
        ret = SSL_write(c->ssl, ptr, len);
        if (ret < 0) {
            ret = SSL_get_error(c->ssl, ret);
            if (ret == SSL_ERROR_WANT_READ)
                *cond |= G_IO_IN;
            if (ret == SSL_ERROR_WANT_WRITE)
                *cond |= G_IO_OUT;
            ret = -1;
        }
    } else {
        GError *error = NULL;
        ret = g_pollable_output_stream_write_nonblocking(G_POLLABLE_OUTPUT_STREAM(c->out),
                                                         ptr, len, NULL, &error);
        if (ret < 0) {
            if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                *cond = G_IO_OUT;
            } else {
                CHANNEL_DEBUG(channel, "Send error %s", error->message);
            }
            g_clear_error(&error);
            ret = -1;
        }
    }

    return ret;
}

/*
 * Write all 'data' of length 'datalen' bytes out to
 * the wire
 */
/* coroutine context */
static void spice_channel_flush_wire(SpiceChannel *channel,
                                     const void *data,
                                     size_t datalen)
{
    SpiceChannelPrivate *c = channel->priv;
    const char *ptr = data;
    size_t offset = 0;
    GIOCondition cond;

    while (offset < datalen) {
        gssize ret;

        if (c->has_error) return;

        ret = spice_channel_flush_wire_nonblocking(channel, ptr+offset, datalen-offset, &cond);
        if (ret == -1) {
            if (cond != 0) {
                // TODO: should use g_pollable_input/output_stream_create_source() in 2.28 ?
                g_coroutine_socket_wait(&c->coroutine, c->sock, cond);
                continue;
            } else {
                CHANNEL_DEBUG(channel, "Closing the channel: spice_channel_flush %d", errno);
                c->has_error = TRUE;
                return;
            }
        }
        if (ret == 0) {
            CHANNEL_DEBUG(channel, "Closing the connection: spice_channel_flush");
            c->has_error = TRUE;
            return;
        }
        offset += ret;
    }
}



/* coroutine context */
static void spice_channel_write(SpiceChannel *channel, const void *data, size_t len)
{
        spice_channel_flush_wire(channel, data, len);
}

/* coroutine context */
static void spice_channel_write_msg(SpiceChannel *channel, SpiceMsgOut *out)
{
    uint8_t *data;
    int free_data;
    size_t len;
    uint32_t msg_size;
    g_return_if_fail(channel != NULL);
    g_return_if_fail(out != NULL);
    g_return_if_fail(channel == out->channel);
    spice_marshaller_flush(out->marshaller);
    msg_size = spice_marshaller_get_total_size(out->marshaller) -
               spice_header_get_header_size(channel->priv->use_mini_header);
    spice_header_set_msg_size(out->header, channel->priv->use_mini_header, msg_size);
    data = spice_marshaller_linearize(out->marshaller, 0, &len, &free_data);
    spice_channel_write(channel, data, len);
    if (free_data)
        g_free(data);
    spice_msg_out_unref(out);
}

#ifdef G_OS_UNIX
static ssize_t read_fd(int fd, int *msgfd)
{
    struct msghdr msg = { NULL, };
    struct iovec iov[1];
    union {
        struct cmsghdr cmsg;
        char control[CMSG_SPACE(sizeof(int))];
    } msg_control;
    struct cmsghdr *cmsg;
    ssize_t ret;
    char c;

    iov[0].iov_base = &c;
    iov[0].iov_len = 1;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &msg_control;
    msg.msg_controllen = sizeof(msg_control);

    ret = recvmsg(fd, &msg, 0);
    if (ret > 0) {
        for (cmsg = CMSG_FIRSTHDR(&msg);
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
                cmsg->cmsg_level != SOL_SOCKET ||
                cmsg->cmsg_type != SCM_RIGHTS) {
                continue;
            }

            memcpy(msgfd, CMSG_DATA(cmsg), sizeof(int));
            if (*msgfd < 0) {
                continue;
            }
        }
    }
    return ret;
}

G_GNUC_INTERNAL
gint spice_channel_unix_read_fd(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    gint fd = -1;

    g_return_val_if_fail(g_socket_get_family(c->sock) == G_SOCKET_FAMILY_UNIX, -1);

    while (1) {
     
        if (read_fd(g_socket_get_fd(c->sock), &fd) > 0) {
            break;
        }

        if (errno == EWOULDBLOCK) {
            g_coroutine_socket_wait(&c->coroutine, c->sock, G_IO_IN);
        } else {
            g_warning("failed to get fd: %s", g_strerror(errno));
            return -1;
        }
    }

    return fd;
}
#endif

static int spice_channel_read_wire_nonblocking(SpiceChannel *channel,
                                               void *data,
                                               size_t len,
                                               GIOCondition *cond)
{
    SpiceChannelPrivate *c = channel->priv;
    gssize ret;

    g_assert(cond != NULL);
    *cond = 0;

    if (c->tls) {
        ret = SSL_read(c->ssl, data, len);
        if (ret < 0) {
            ret = SSL_get_error(c->ssl, ret);
            if (ret == SSL_ERROR_WANT_READ)
                *cond |= G_IO_IN;
            if (ret == SSL_ERROR_WANT_WRITE)
                *cond |= G_IO_OUT;
            ret = -1;
        }
    } else {
        GError *error = NULL;
        ret = g_pollable_input_stream_read_nonblocking(G_POLLABLE_INPUT_STREAM(c->in),
                                                       data, len, NULL, &error);
        if (ret < 0) {
            if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                *cond = G_IO_IN;
            } else {
                CHANNEL_DEBUG(channel, "Read error %s", error->message);
            }
            g_clear_error(&error);
            ret = -1;
        }
    }

    return ret;
}

static int spice_channel_read_wire(SpiceChannel *channel, void *data, size_t len)
{
    SpiceChannelPrivate *c = channel->priv;

    while (TRUE) {
        gssize ret;
        GIOCondition cond;
        if (c->has_error) {
            return 0;
        }

        ret = spice_channel_read_wire_nonblocking(channel, data, len, &cond);
        if (ret == -1) {
            if (cond != 0) {
                // TODO: should use g_pollable_input/output_stream_create_source() ?
                g_coroutine_socket_wait(&c->coroutine, c->sock, cond);
                continue;
            } else {
                c->has_error = TRUE;
                return -errno;
            }
        }
        if (ret == 0) {
            CHANNEL_DEBUG(channel, "Closing the connection: spice_channel_read() - ret=0");
            c->has_error = TRUE;
            return 0;
        }

        return ret;
    }
}
 
static int spice_channel_read(SpiceChannel *channel, void *data, size_t length)
{
    SpiceChannelPrivate *c = channel->priv;
    gsize len = length;
    int ret;

    while (len > 0) {
        if (c->has_error) return 0; /* has_error is set by disconnect(), return no error */ 
            ret = spice_channel_read_wire(channel, data, len);
        if (ret < 0)
            return ret;
        g_assert(ret <= len);
        len -= ret;
        data = ((char*)data) + ret; 
    }
    c->total_read_bytes += length;

    return length;
}
 
/* coroutine context */
static SpiceChannelEvent spice_channel_send_spice_ticket(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    EVP_PKEY *pubkey;
    int nRSASize;
    BIO *bioKey;
    RSA *rsa;
    char *password=NULL;
    uint8_t *encrypted;
    int rc;
    SpiceChannelEvent ret = SPICE_CHANNEL_ERROR_LINK;

    bioKey = BIO_new(BIO_s_mem());
    g_return_val_if_fail(bioKey != NULL, ret);

    BIO_write(bioKey, c->peer_msg->pub_key, SPICE_TICKET_PUBKEY_BYTES);
    pubkey = d2i_PUBKEY_bio(bioKey, NULL);
    g_return_val_if_fail(pubkey != NULL, ret);

    rsa = EVP_PKEY_get0_RSA(pubkey);
    nRSASize = RSA_size(rsa);

    encrypted = g_alloca(nRSASize);
    if (password == NULL)
        password = g_strdup("");
    rc = RSA_public_encrypt(strlen(password) + 1, (uint8_t*)password,
                            encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    g_warn_if_fail(rc > 0);

    spice_channel_write(channel, encrypted, nRSASize);
    ret = SPICE_CHANNEL_NONE;
    memset(encrypted, 0, nRSASize);
    EVP_PKEY_free(pubkey);
    BIO_free(bioKey);
    g_free(password);
    return ret;
}

/* coroutine context */
static gboolean spice_channel_recv_auth(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    uint32_t link_res;
    int rc;

    rc = spice_channel_read(channel, &link_res, sizeof(link_res));
    if (rc != sizeof(link_res)) {
        CHANNEL_DEBUG(channel, "incomplete auth reply (%d/%" G_GSIZE_FORMAT ")",
                    rc, sizeof(link_res));
        c->event = SPICE_CHANNEL_ERROR_LINK;
        return FALSE;
    }
    c->state = SPICE_CHANNEL_STATE_READY;

    g_coroutine_signal_emit(channel, signals[SPICE_CHANNEL_EVENT], 0, SPICE_CHANNEL_OPENED);
    if (c->state != SPICE_CHANNEL_STATE_MIGRATING)
        spice_channel_up(channel);

    return TRUE;
}

G_GNUC_INTERNAL
void spice_channel_up(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;

    CHANNEL_DEBUG(channel, "channel up, state %u", c->state);

    if (SPICE_CHANNEL_GET_CLASS(channel)->channel_up)
        SPICE_CHANNEL_GET_CLASS(channel)->channel_up(channel);
}

/* coroutine context */
static void spice_channel_send_link(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    uint8_t *buffer, *p;
    uint32_t *caps;
    int protocol, i;
    SpiceLinkMess link_msg;

    c->link_hdr.magic = SPICE_MAGIC;
    c->link_hdr.size = sizeof(link_msg);
    g_object_get(c->session, "protocol", &protocol, NULL);
  switch (protocol) {
    case 1:
        c->link_hdr.major_version = 1;
        c->link_hdr.minor_version = 3;
        c->parser = spice_get_server_channel_parser1(c->channel_type, NULL);
        c->marshallers = spice_message_marshallers_get1();
        break;
    case SPICE_VERSION_MAJOR: 
	
        c->link_hdr.major_version = SPICE_VERSION_MAJOR;
        c->link_hdr.minor_version = SPICE_VERSION_MINOR;
        c->parser = spice_get_server_channel_parser(c->channel_type, NULL);
        c->marshallers = spice_message_marshallers_get();
       break;
    default:
        g_critical("unknown major %d", protocol);
        return;
    }

    c->link_hdr.major_version = GUINT32_TO_LE(c->link_hdr.major_version);
    c->link_hdr.minor_version = GUINT32_TO_LE(c->link_hdr.minor_version);

    link_msg.connection_id = GUINT32_TO_LE(spice_session_get_connection_id(c->session));
    link_msg.channel_type  = c->channel_type;
    link_msg.channel_id    = c->channel_id;
    link_msg.caps_offset   = GUINT32_TO_LE(sizeof(link_msg));

    link_msg.num_common_caps = GUINT32_TO_LE(c->common_caps->len);
    link_msg.num_channel_caps = GUINT32_TO_LE(c->caps->len);
    c->link_hdr.size += (c->common_caps->len + c->caps->len) * sizeof(uint32_t);

    buffer = g_malloc0(sizeof(c->link_hdr) + c->link_hdr.size);
    p = buffer;

    c->link_hdr.size = GUINT32_TO_LE(c->link_hdr.size);

    memcpy(p, &c->link_hdr, sizeof(c->link_hdr)); p += sizeof(c->link_hdr);
    memcpy(p, &link_msg, sizeof(link_msg)); p += sizeof(link_msg);

    caps = SPICE_UNALIGNED_CAST(uint32_t *,p);
    for (i = 0; i < c->common_caps->len; i++) {
        *caps++ = GUINT32_TO_LE(g_array_index(c->common_caps, uint32_t, i));
    }
    for (i = 0; i < c->caps->len; i++) {
        *caps++ = GUINT32_TO_LE(g_array_index(c->caps, uint32_t, i));
    }
    p = (uint8_t *) caps;
    CHANNEL_DEBUG(channel, "channel type %d id %d num common caps %u num caps %u",
                  c->channel_type,
                  c->channel_id,
                  c->common_caps->len,
                  c->caps->len);
    spice_channel_write(channel, buffer, p - buffer);
    g_free(buffer);
}

/* coroutine context */
static gboolean spice_channel_recv_link_hdr(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    int rc;

    rc = spice_channel_read(channel, &c->peer_hdr, sizeof(c->peer_hdr));
    if (rc != sizeof(c->peer_hdr)) {
        g_warning("incomplete link header (%d/%" G_GSIZE_FORMAT ")",
                  rc, sizeof(c->peer_hdr));
        goto error;
    }
    if (c->peer_hdr.magic != SPICE_MAGIC) {
        g_warning("invalid SPICE_MAGIC!");
        goto error;
    }

    CHANNEL_DEBUG(channel, "Peer version: %u:%u",
                  GUINT32_FROM_LE(c->peer_hdr.major_version),
                  GUINT32_FROM_LE(c->peer_hdr.minor_version));
    if (c->peer_hdr.major_version != c->link_hdr.major_version) {
        g_warning("major mismatch (got %u, expected %u)",
                  c->peer_hdr.major_version, c->link_hdr.major_version);
        goto error;
    }

    c->peer_hdr.major_version = GUINT32_FROM_LE(c->peer_hdr.major_version);
    c->peer_hdr.minor_version = GUINT32_FROM_LE(c->peer_hdr.minor_version);
    c->peer_hdr.size = GUINT32_FROM_LE(c->peer_hdr.size);

    c->peer_msg = g_malloc0(c->peer_hdr.size);
    if (c->peer_msg == NULL) {
        g_warning("invalid peer header size: %u", c->peer_hdr.size);
        goto error;
    }

    return TRUE;

error:
    /* Windows socket seems to give early CONNRESET errors. The server
       does not linger when closing the socket if the protocol is
       incompatible. Try with the oldest protocol in this case: */
    if (c->link_hdr.major_version != 1) {
        SPICE_DEBUG("%s: error, switching to protocol 1 (spice 0.4)", c->name);
        c->state = SPICE_CHANNEL_STATE_RECONNECTING;
        g_object_set(c->session, "protocol", 1, NULL);
        return FALSE;
    }

    c->event = SPICE_CHANNEL_ERROR_LINK;
    return FALSE;
}


/* coroutine context */
static void store_caps(const uint8_t *caps_src, const GArray *caps_dst)
{
    uint32_t *caps;
    guint i;

    caps = &g_array_index(caps_dst, uint32_t, 0);
    memcpy(caps, caps_src, caps_dst->len * sizeof(uint32_t));
    for (i = 0; i < caps_dst->len; i++, caps++) {
        *caps = GUINT32_FROM_LE(*caps);
        SPICE_DEBUG("\t%u:0x%X", i, *caps);
    }
}

/* coroutine context */
static gboolean spice_channel_recv_link_msg(SpiceChannel *channel)
{
    SpiceChannelPrivate *c;
    int rc, num_caps;
    uint32_t num_channel_caps, num_common_caps;
    uint8_t *caps_src;
    SpiceChannelEvent event = SPICE_CHANNEL_ERROR_LINK;

    g_return_val_if_fail(channel != NULL, FALSE);
    g_return_val_if_fail(channel->priv != NULL, FALSE);

    c = channel->priv;

    rc = spice_channel_read(channel, (uint8_t*)c->peer_msg + c->peer_pos,
                            c->peer_hdr.size - c->peer_pos);
    c->peer_pos += rc;
    if (c->peer_pos != c->peer_hdr.size) {
        g_critical("%s: %s: incomplete link reply (%d/%u)",
                  c->name, __FUNCTION__, rc, c->peer_hdr.size);
        goto error;
    }
    switch (c->peer_msg->error) {
    case SPICE_LINK_ERR_OK:
        /* nothing */
        break;
    case SPICE_LINK_ERR_NEED_SECURED:
        c->state = SPICE_CHANNEL_STATE_RECONNECTING;
        CHANNEL_DEBUG(channel, "switching to tls");
        c->tls = TRUE;
        return FALSE;
    default:
        g_warning("%s: %s: unhandled error %u",
                c->name, __FUNCTION__, c->peer_msg->error);
        goto error;
    }

    num_channel_caps = GUINT32_FROM_LE(c->peer_msg->num_channel_caps);
    num_common_caps = GUINT32_FROM_LE(c->peer_msg->num_common_caps);

    num_caps = num_channel_caps + num_common_caps;
    CHANNEL_DEBUG(channel, "%s: %d caps", __FUNCTION__, num_caps);

    /* see original spice/client code: */
    /* g_return_if_fail(c->peer_msg + c->peer_msg->caps_offset * sizeof(uint32_t) > c->peer_msg + c->peer_hdr.size); */

    caps_src = (uint8_t *)c->peer_msg + GUINT32_FROM_LE(c->peer_msg->caps_offset);
    g_array_set_size(c->remote_common_caps, num_common_caps);
    CHANNEL_DEBUG(channel, "got remote common caps:");
    store_caps(caps_src, c->remote_common_caps);

    caps_src += num_common_caps * sizeof(uint32_t);
    g_array_set_size(c->remote_caps, num_channel_caps);
    CHANNEL_DEBUG(channel, "got remote channel caps:");
    store_caps(caps_src, c->remote_caps);

    if (!spice_channel_test_common_capability(channel,
            SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION)) {
        CHANNEL_DEBUG(channel, "Server supports spice ticket auth only");
        if ((event = spice_channel_send_spice_ticket(channel)) != SPICE_CHANNEL_NONE)
            goto error;
    } else {
        SpiceLinkAuthMechanism auth = { 0, };
        if (spice_channel_test_common_capability(channel, SPICE_COMMON_CAP_AUTH_SPICE)) {
            auth.auth_mechanism = SPICE_COMMON_CAP_AUTH_SPICE;
            spice_channel_write(channel, &auth, sizeof(auth));
            if ((event = spice_channel_send_spice_ticket(channel)) != SPICE_CHANNEL_NONE)
                goto error;
        } else {
            g_warning("No compatible AUTH mechanism");
            goto error;
        }
    }
    c->use_mini_header = spice_channel_test_common_capability(channel,
                                                              SPICE_COMMON_CAP_MINI_HEADER);
    CHANNEL_DEBUG(channel, "use mini header: %d", c->use_mini_header);
    return TRUE;

error:
    c->has_error = TRUE;
    c->event = event;
    return FALSE;
}

/* system context */
G_GNUC_INTERNAL
void spice_channel_wakeup(SpiceChannel *channel, gboolean cancel)
{
    GCoroutine *c;
    g_return_if_fail(SPICE_IS_CHANNEL(channel));
    c = &channel->priv->coroutine;
    if (cancel)
        g_coroutine_condition_cancel(c);
    g_coroutine_wakeup(c);
}

/* coroutine context */
G_GNUC_INTERNAL
void spice_channel_recv_msg(SpiceChannel *channel,
                            handler_msg_in msg_handler, gpointer data)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgIn *in;
    int msg_size;
    int msg_type;
    int sub_list_offset = 0;

    in = spice_msg_in_new(channel);

    /* receive message */
    spice_channel_read(channel, in->header,
                       spice_header_get_header_size(c->use_mini_header));
    if (c->has_error)
        goto end;

    msg_size = spice_header_get_msg_size(in->header, c->use_mini_header);
    /* FIXME: do not allow others to take ref on in, and use realloc here?
     * this would avoid malloc/free on each message?
     */
    in->data = g_malloc0(msg_size);
    spice_channel_read(channel, in->data, msg_size);
    if (c->has_error)
        goto end;
    in->dpos = msg_size;

    msg_type = spice_header_get_msg_type(in->header, c->use_mini_header);
    sub_list_offset = spice_header_get_msg_sub_list(in->header, c->use_mini_header);

    if (msg_type == SPICE_MSG_LIST || sub_list_offset) {
        SpiceSubMessageList *sub_list;
        SpiceSubMessage *sub;
        SpiceMsgIn *sub_in;
        int i;

        sub_list = (SpiceSubMessageList *)(in->data + sub_list_offset);
        for (i = 0; i < sub_list->size; i++) {
            sub = (SpiceSubMessage *)(in->data + sub_list->sub_messages[i]);
            sub_in = spice_msg_in_sub_new(channel, in, sub);
            sub_in->parsed = c->parser(sub_in->data, sub_in->data + sub_in->dpos,
                                       spice_header_get_msg_type(sub_in->header,
                                                                 c->use_mini_header),
                                       c->peer_hdr.minor_version,
                                       &sub_in->psize, &sub_in->pfree);
            if (sub_in->parsed == NULL) {
                g_critical("failed to parse sub-message: %s type %d",
                           c->name, spice_header_get_msg_type(sub_in->header, c->use_mini_header));
                goto end;
            }
            msg_handler(channel, sub_in, data);
            spice_msg_in_unref(sub_in);
        }
    }

    /* ack message */
    if (c->message_ack_count) {
        c->message_ack_count--;
        if (!c->message_ack_count) {
            SpiceMsgOut *out = spice_msg_out_new(channel, SPICE_MSGC_ACK);
            spice_msg_out_send_internal(out);
            c->message_ack_count = c->message_ack_window;
        }
    }

    if (msg_type == SPICE_MSG_LIST) {
        goto end;
    }

    /* parse message */
    in->parsed = c->parser(in->data, in->data + msg_size, msg_type,
                           c->peer_hdr.minor_version, &in->psize, &in->pfree);
    if (in->parsed == NULL) {
        g_critical("failed to parse message: %s type %d",
                   c->name, msg_type);
        goto end;
    }

    /* process message */
    /* spice_msg_in_hexdump(in); */
    msg_handler(channel, in, data);

end:
    c->last_message_serial = spice_header_get_in_msg_serial(in);
    c->in_serial++;
    spice_msg_in_unref(in);
}

static const char *to_string[] = {
    NULL,
    [ SPICE_CHANNEL_MAIN ] = "main",
    [ SPICE_CHANNEL_USBREDIR ] = "usbredir",
};

const gchar* spice_channel_type_to_string(gint type)
{
    const char *str = NULL;
    if (type >= 0 && type < G_N_ELEMENTS(to_string)) {
        str = to_string[type];
    }
    return str ? str : "unknown channel type";
}

gint spice_channel_string_to_type(const gchar *str)
{
    int i;

    g_return_val_if_fail(str != NULL, -1);

    for (i = 0; i < G_N_ELEMENTS(to_string); i++)
        if (g_strcmp0(str, to_string[i]) == 0)
            return i;
    return -1;
}

G_GNUC_INTERNAL
gchar *spice_channel_supported_string(void)
{
    return g_strjoin(", ",
                     spice_channel_type_to_string(SPICE_CHANNEL_MAIN),
                     spice_channel_type_to_string(SPICE_CHANNEL_USBREDIR),
                     NULL);
}


/**
 * spice_channel_new:
 * @s: the @SpiceSession the channel is linked to
 * @type: the requested SPICECHANNELPRIVATE type
 * @id: the channel-id
 *
 * Create a new #SpiceChannel of type @type, and channel ID @id.
 *
 * Returns: a weak reference to #SpiceChannel, the session owns the reference
 **/
SpiceChannel *spice_channel_new(SpiceSession *s, int type, int id)
{
    SpiceChannel *channel;
    GType gtype = 0;
    g_return_val_if_fail(s != NULL, NULL);
    switch (type) {
    case SPICE_CHANNEL_MAIN:
        gtype = SPICE_TYPE_MAIN_CHANNEL;
        break;
    case SPICE_CHANNEL_USBREDIR: {
             gtype = SPICE_TYPE_USBREDIR_CHANNEL;
		 break;
    }
    default:
       return NULL;
    }
    channel = SPICE_CHANNEL(g_object_new(gtype,"spice-session", s,"channel-type", type,"channel-id", id,NULL));
    return channel;
}

/**
 * spice_channel_destroy:
 * @channel: a #SpiceChannel
 *
 * Disconnect and unref the @channel.
 *
 * Deprecated: 0.27: this function has been deprecated because it is
 * misleading, the object is not actually destroyed. Instead, it is
 * recommended to call explicitely spice_channel_disconnect() and
 * g_object_unref().
 **/
void spice_channel_destroy(SpiceChannel *channel)
{
    g_return_if_fail(channel != NULL);

    CHANNEL_DEBUG(channel, "channel destroy");
    spice_channel_disconnect(channel, SPICE_CHANNEL_NONE);
    g_object_unref(channel);
}

/* any context */
static void spice_channel_flushed(SpiceChannel *channel, gboolean success)
{
    SpiceChannelPrivate *c = channel->priv;
    GSList *l;

    for (l = c->flushing; l != NULL; l = l->next) {
        g_task_return_boolean(G_TASK(l->data), success);
    }

    g_slist_free_full(c->flushing, g_object_unref);
    c->flushing = NULL;
}

/* coroutine context */
static void spice_channel_iterate_write(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgOut *out;

    do {
        g_mutex_lock(&c->xmit_queue_lock);
        out = g_queue_pop_head(&c->xmit_queue);
        g_mutex_unlock(&c->xmit_queue_lock);
        if (out) {
            guint32 size = spice_marshaller_get_total_size(out->marshaller);
            c->xmit_queue_size = (c->xmit_queue_size < size) ? 0 : c->xmit_queue_size - size;
            spice_channel_write_msg(channel, out);
        }
    } while (out);

    spice_channel_flushed(channel, TRUE);
}

/* coroutine context */
static void spice_channel_iterate_read(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;

    g_coroutine_socket_wait(&c->coroutine, c->sock, G_IO_IN);

    /* treat all incoming data (block on message completion) */
    while (!c->has_error &&c->state != SPICE_CHANNEL_STATE_MIGRATING &&g_pollable_input_stream_is_readable(G_POLLABLE_INPUT_STREAM(c->in))) { 
	   do
            spice_channel_recv_msg(channel,(handler_msg_in)SPICE_CHANNEL_GET_CLASS(channel)->handle_msg, NULL);
        	while (FALSE);
    }

}

/* coroutine context */
static gboolean spice_channel_iterate(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    if (!c->has_error)
        SPICE_CHANNEL_GET_CLASS(channel)->iterate_write(channel);
    if (!c->has_error)
        SPICE_CHANNEL_GET_CLASS(channel)->iterate_read(channel);

    if (c->has_error) {
        GIOCondition ret;

        if (!c->sock)
            return FALSE;

        /* We don't want to report an error if the socket was closed gracefully
         * on the other end (VM shutdown) */
        ret = g_socket_condition_check(c->sock, G_IO_IN | G_IO_ERR);

        if (ret & G_IO_ERR) {
            CHANNEL_DEBUG(channel, "channel got error");

            if (c->state > SPICE_CHANNEL_STATE_CONNECTING) {
                if (c->state == SPICE_CHANNEL_STATE_READY)
                    c->event = SPICE_CHANNEL_ERROR_IO;
                else
                    c->event = SPICE_CHANNEL_ERROR_LINK;
            }
        }
        return FALSE;
    }

    return TRUE;
}

/* we use an idle function to allow the coroutine to exit before we actually
 * unref the object since the coroutine's state is part of the object */
static gboolean spice_channel_delayed_unref(gpointer data)
{
    SpiceChannel *channel = SPICE_CHANNEL(data);
    SpiceChannelPrivate *c = channel->priv;
    gboolean was_ready = c->state == SPICE_CHANNEL_STATE_READY;
    g_return_val_if_fail(c->coroutine.coroutine.exited == TRUE, FALSE);
    c->state = SPICE_CHANNEL_STATE_UNCONNECTED;
    if (c->event != SPICE_CHANNEL_NONE) {
        g_coroutine_signal_emit(channel, signals[SPICE_CHANNEL_EVENT], 0, c->event);
        c->event = SPICE_CHANNEL_NONE;
        g_clear_error(&c->error);
    }
    if (was_ready)
        g_coroutine_signal_emit(channel, signals[SPICE_CHANNEL_EVENT], 0, SPICE_CHANNEL_CLOSED);
    g_object_unref(G_OBJECT(data));
    return FALSE;
}

const GError* spice_channel_get_error(SpiceChannel *self)
{
    SpiceChannelPrivate *c;
    g_return_val_if_fail(SPICE_IS_CHANNEL(self), NULL);
    c = self->priv;
    return c->error;
}

static void *spice_channel_coroutine(void *data)
{
    SpiceChannel *channel = SPICE_CHANNEL(data);
    SpiceChannelPrivate *c = channel->priv;
    int rc, delay_val = 1;
    c->conn = spice_session_channel_open_host(c->session, channel, &c->tls, &c->error);
    c->sock = g_object_ref(g_socket_connection_get_socket(c->conn));
    c->has_error = FALSE;
    c->in = g_io_stream_get_input_stream(G_IO_STREAM(c->conn));
    c->out = g_io_stream_get_output_stream(G_IO_STREAM(c->conn));
    rc = setsockopt(g_socket_get_fd(c->sock), IPPROTO_TCP, TCP_NODELAY,(const char*)&delay_val, sizeof(delay_val));
    if ((rc != 0)) {
        g_warning("%s: could not set sockopt TCP_NODELAY: %s", c->name,strerror(errno));
    }
    spice_channel_send_link(channel);
    if (!spice_channel_recv_link_hdr(channel) ||!spice_channel_recv_link_msg(channel) ||!spice_channel_recv_auth(channel))
        goto cleanup;
    while (spice_channel_iterate(channel)) ;
cleanup:
        spice_channel_reset(channel, FALSE);
        g_idle_add(spice_channel_delayed_unref, data);
    return NULL;
}

static gboolean connect_delayed(gpointer data)
{
    SpiceChannel *channel = data;
    SpiceChannelPrivate *c = channel->priv;
    struct coroutine *co;
    CHANNEL_DEBUG(channel, "Open coroutine starting %p", channel);
    c->connect_delayed_id = 0;
    co = &c->coroutine.coroutine;
    co->stack_size = 16 << 20; /* 16Mb */
	co->entry = spice_channel_coroutine;
    co->release = NULL;

    coroutine_init(co);
    coroutine_yieldto(co, channel);

    return FALSE;
}

/* any context */
static gboolean channel_connect(SpiceChannel *channel, gboolean tls)
{
    SpiceChannelPrivate *c = channel->priv;
    g_return_val_if_fail(c != NULL, FALSE);
    if (c->session == NULL || c->channel_type == -1 || c->channel_id == -1) {
        /* unset properties or unknown channel type */
        g_warning("%s: channel setup incomplete", __FUNCTION__);
        return false;
    }
    c->state = SPICE_CHANNEL_STATE_CONNECTING;
    c->tls = tls;
	
    if (spice_session_get_client_provided_socket(c->session)) {
        if (c->fd == -1) {
            CHANNEL_DEBUG(channel, "requesting fd");
            g_signal_emit(channel, signals[SPICE_CHANNEL_OPEN_FD], 0, c->tls);
			return true;
        }
		
    }
    c->xmit_queue_blocked = FALSE;
    g_return_val_if_fail(c->sock == NULL, FALSE);
    g_object_ref(G_OBJECT(channel)); /* Unref'd when co-routine exits */
    /* we connect in idle, to let previous coroutine exit, if present */
    c->connect_delayed_id = g_idle_add(connect_delayed, channel);
    return true;
}

/**
 * spice_channel_connect:
 * @channel: a #SpiceChannel
 *
 * Connect the channel, using #SpiceSession connection informations
 *
 * Returns: %TRUE on success.
 **/
gboolean spice_channel_connect(SpiceChannel *channel)
{
    g_return_val_if_fail(SPICE_IS_CHANNEL(channel), FALSE);
    SpiceChannelPrivate *c = channel->priv;
    if (c->state >= SPICE_CHANNEL_STATE_CONNECTING){
				return TRUE;
    	}
    g_return_val_if_fail(channel->priv->fd == -1, FALSE);
    return channel_connect(channel, FALSE);
}

/**
 * spice_channel_open_fd:
 * @channel: a #SpiceChannel
 * @fd: a file descriptor (socket) or -1.
 * request mechanism
 *
 * Connect the channel using @fd socket.
 *
 * If @fd is -1, a valid fd will be requested later via the
 * SpiceChannel::open-fd signal.
 *
 * Returns: %TRUE on success.
 **/
gboolean spice_channel_open_fd(SpiceChannel *channel, int fd)
{
    SpiceChannelPrivate *c;

    g_return_val_if_fail(SPICE_IS_CHANNEL(channel), FALSE);
    g_return_val_if_fail(channel->priv != NULL, FALSE);
    g_return_val_if_fail(channel->priv->fd == -1, FALSE);
    g_return_val_if_fail(fd >= -1, FALSE);
    c = channel->priv;
    if (c->state > SPICE_CHANNEL_STATE_CONNECTING) {
        g_warning("Invalid channel_connect state: %u", c->state);
        return true;
    }
    c->fd = fd;
    return channel_connect(channel, FALSE);
}

/* system or coroutine context */
static void channel_reset(SpiceChannel *channel, gboolean migrating)
{
    SpiceChannelPrivate *c = channel->priv;

    CHANNEL_DEBUG(channel, "channel reset");
    if (c->connect_delayed_id) {
        g_source_remove(c->connect_delayed_id);
        c->connect_delayed_id = 0;
    }
    g_clear_pointer(&c->sslverify, spice_openssl_verify_free);
    g_clear_pointer(&c->ssl, SSL_free);
    g_clear_pointer(&c->ctx, SSL_CTX_free);
    g_clear_object(&c->conn);
    g_clear_object(&c->sock);

    c->fd = -1;

    c->auth_needs_username = FALSE;
    c->auth_needs_password = FALSE;

    g_clear_pointer(&c->peer_msg, g_free);
    c->peer_pos = 0;

    g_mutex_lock(&c->xmit_queue_lock);
    c->xmit_queue_blocked = TRUE; /* Disallow queuing new messages */
    gboolean was_empty = g_queue_is_empty(&c->xmit_queue);
    g_queue_foreach(&c->xmit_queue, (GFunc)spice_msg_out_unref, NULL);
    g_queue_clear(&c->xmit_queue);
    if (c->xmit_queue_wakeup_id) {
        g_source_remove(c->xmit_queue_wakeup_id);
        c->xmit_queue_wakeup_id = 0;
    }
    g_mutex_unlock(&c->xmit_queue_lock);
    spice_channel_flushed(channel, was_empty);

    g_array_set_size(c->remote_common_caps, 0);
    g_array_set_size(c->remote_caps, 0);
    g_array_set_size(c->common_caps, 0);
    /* Restore our default capabilities in case the channel gets re-used */
    spice_channel_set_common_capability(channel, SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION);
    spice_channel_set_common_capability(channel, SPICE_COMMON_CAP_MINI_HEADER);
    spice_channel_reset_capabilities(channel);
}

/* system or coroutine context */
G_GNUC_INTERNAL
void spice_channel_reset(SpiceChannel *channel, gboolean migrating)
{
    CHANNEL_DEBUG(channel, "reset %s", migrating ? "migrating" : "");
    SPICE_CHANNEL_GET_CLASS(channel)->channel_reset(channel, migrating);
}

/**
 * spice_channel_disconnect:
 * @channel: a #SpiceChannel
 * @reason: a channel event emitted on main context (or #SPICE_CHANNEL_NONE)
 *
 * Close the socket and reset connection specific data. Finally, emit
 * @reason #SpiceChannel::channel-event on main context if not
 * #SPICE_CHANNEL_NONE.
 **/
void spice_channel_disconnect(SpiceChannel *channel, SpiceChannelEvent reason)
{
    SpiceChannelPrivate *c;
    CHANNEL_DEBUG(channel, "channel disconnect %u", reason);
    g_return_if_fail(SPICE_IS_CHANNEL(channel));
    g_return_if_fail(channel->priv != NULL);
    c = channel->priv;
    if (c->state == SPICE_CHANNEL_STATE_UNCONNECTED)
        return;
    if (reason == SPICE_CHANNEL_SWITCHING)
        c->state = SPICE_CHANNEL_STATE_SWITCHING;
    c->has_error = TRUE; /* break the loop */
	
    if (c->state == SPICE_CHANNEL_STATE_MIGRATING) {
        c->state = SPICE_CHANNEL_STATE_READY;
    } else
        spice_channel_wakeup(channel, TRUE);
    if (reason != SPICE_CHANNEL_NONE)
        g_signal_emit(G_OBJECT(channel), signals[SPICE_CHANNEL_EVENT], 0, reason);
}

static gboolean test_capability(GArray *caps, guint32 cap)
{
    guint32 c, word_index = cap / 32;
    gboolean ret;
    if (caps == NULL)
        return FALSE;
    if (caps->len < word_index + 1)
        return FALSE;
    c = g_array_index(caps, guint32, word_index);
    ret = (c & (1 << (cap % 32))) != 0;

    SPICE_DEBUG("test cap %u in 0x%X: %s", cap, c, ret ? "yes" : "no");
    return ret;
}

/**
 * spice_channel_test_capability:
 * @channel: a #SpiceChannel
 * @cap: a capability
 *
 * Test availability of remote "channel kind capability".
 *
 * Returns: %TRUE if @cap (channel kind capability) is available.
 **/
gboolean spice_channel_test_capability(SpiceChannel *self, guint32 cap)
{
    SpiceChannelPrivate *c;
    g_return_val_if_fail(SPICE_IS_CHANNEL(self), FALSE);
    c = self->priv;
    return test_capability(c->remote_caps, cap);
}

/**
 * spice_channel_test_common_capability:
 * @channel: a #SpiceChannel
 * @cap: a capability
 *
 * Test availability of remote "common channel capability".
 *
 * Returns: %TRUE if @cap (common channel capability) is available.
 **/
gboolean spice_channel_test_common_capability(SpiceChannel *self, guint32 cap)
{
    SpiceChannelPrivate *c;

    g_return_val_if_fail(SPICE_IS_CHANNEL(self), FALSE);

    c = self->priv;
    return test_capability(c->remote_common_caps, cap);
}

static void set_capability(GArray *caps, guint32 cap)
{
    guint word_index = cap / 32;
    g_return_if_fail(caps != NULL);
    if (caps->len <= word_index)
        g_array_set_size(caps, word_index + 1);
        g_array_index(caps, guint32, word_index) =
        g_array_index(caps, guint32, word_index) | (1 << (cap % 32));
}

#undef spice_channel_set_capability
void spice_channel_set_capability(SpiceChannel *channel, guint32 cap)
{
    SpiceChannelPrivate *c;
    g_return_if_fail(SPICE_IS_CHANNEL(channel));
    c = channel->priv;
    set_capability(c->caps, cap);
}

G_GNUC_INTERNAL
void spice_caps_set(GArray *caps, guint32 cap, const gchar *desc)
{
    g_return_if_fail(caps != NULL);
    g_return_if_fail(desc != NULL);

    if (g_strcmp0(g_getenv(desc), "0") == 0)
        return;

    set_capability(caps, cap);
}

G_GNUC_INTERNAL
SpiceSession* spice_channel_get_session(SpiceChannel *channel)
{
    g_return_val_if_fail(SPICE_IS_CHANNEL(channel), NULL);

    return channel->priv->session;
}

G_GNUC_INTERNAL
enum spice_channel_state spice_channel_get_state(SpiceChannel *channel)
{
    g_return_val_if_fail(SPICE_IS_CHANNEL(channel),
                         SPICE_CHANNEL_STATE_UNCONNECTED);

    return channel->priv->state;
}

G_GNUC_INTERNAL
guint64 spice_channel_get_queue_size (SpiceChannel *channel)
{
    guint64 size;
    SpiceChannelPrivate *c = channel->priv;
    g_mutex_lock(&c->xmit_queue_lock);
    size = c->xmit_queue_size;
    g_mutex_unlock(&c->xmit_queue_lock);
    return size;
}

G_GNUC_INTERNAL
void spice_channel_swap(SpiceChannel *channel, SpiceChannel *swap, gboolean swap_msgs)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceChannelPrivate *s = swap->priv;

    g_return_if_fail(c != NULL);
    g_return_if_fail(s != NULL);

    g_return_if_fail(s->session != NULL);
    g_return_if_fail(s->sock != NULL);

#define SWAP(Field) ({                          \
    typeof (c->Field) Field = c->Field;         \
    c->Field = s->Field;                        \
    s->Field = Field;                           \
})

    SWAP(sock);
    SWAP(conn);
    SWAP(in);
    SWAP(out);
    SWAP(ctx);
    SWAP(ssl);
    SWAP(sslverify);
    SWAP(tls);
    SWAP(use_mini_header);
    if (swap_msgs) {
        SWAP(xmit_queue);
        SWAP(xmit_queue_blocked);
        SWAP(in_serial);
        SWAP(out_serial);
    }
    SWAP(caps);
    SWAP(common_caps);
    SWAP(remote_caps);
    SWAP(remote_common_caps);
}

/* coroutine context */
static void spice_channel_handle_msg(SpiceChannel *channel, SpiceMsgIn *msg)
{
    SpiceChannelClass *klass = SPICE_CHANNEL_GET_CLASS(channel);
    int type = spice_msg_in_type(msg);
    spice_msg_handler handler;

    g_return_if_fail(type < klass->priv->handlers->len);
	
    if (type > SPICE_MSG_BASE_LAST && channel->priv->disable_channel_msg)
        return;

    handler = g_array_index(klass->priv->handlers, spice_msg_handler, type);
    g_return_if_fail(handler != NULL);
    handler(channel, msg);
}

static void spice_channel_reset_capabilities(SpiceChannel *channel)
{
    SpiceChannelPrivate *c = channel->priv;
    g_array_set_size(c->caps, 0);
    if (SPICE_CHANNEL_GET_CLASS(channel)->channel_reset_capabilities) {
        SPICE_CHANNEL_GET_CLASS(channel)->channel_reset_capabilities(channel);
    }
}

void spice_channel_flush_async(SpiceChannel *self, GCancellable *cancellable,
                               GAsyncReadyCallback callback, gpointer user_data)
{
    GTask *task;
    SpiceChannelPrivate *c;
    gboolean was_empty;

    g_return_if_fail(SPICE_IS_CHANNEL(self));
    c = self->priv;

    if (c->state != SPICE_CHANNEL_STATE_READY) {
        g_task_report_new_error(self, callback, user_data,
            spice_channel_flush_async,
            SPICE_CLIENT_ERROR, SPICE_CLIENT_ERROR_FAILED,
            "The channel is not ready yet");
        return;
    }
    task = g_task_new(self, cancellable, callback, user_data);
    g_mutex_lock(&c->xmit_queue_lock);
    was_empty = g_queue_is_empty(&c->xmit_queue);
    g_mutex_unlock(&c->xmit_queue_lock);
    if (was_empty) {
        g_task_return_boolean(task, TRUE);
        g_object_unref(task);
        return;
    }

    c->flushing = g_slist_append(c->flushing, task);
}

gboolean spice_channel_flush_finish(SpiceChannel *self, GAsyncResult *result,
                                    GError **error)
{
    GTask *task;
    g_return_val_if_fail(SPICE_IS_CHANNEL(self), FALSE);
    g_return_val_if_fail(result != NULL, FALSE);
    task = G_TASK(result);
    g_return_val_if_fail(g_task_is_valid(task, self), FALSE);
    return g_task_propagate_boolean(task, error);
}
