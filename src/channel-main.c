#include "config.h"
#include <math.h>
#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>
#include "spice-client.h"
#include "spice-common.h"
#include "spice-marshal.h"
#include "spice-util-priv.h"
#include "spice-channel-priv.h"
#include "spice-session-priv.h"
#include <glib.h>
#include <sys/stat.h>




#define SPICE_MAIN_CHANNEL_GET_PRIVATE(obj)   (G_TYPE_INSTANCE_GET_PRIVATE((obj), SPICE_TYPE_MAIN_CHANNEL, SpiceMainChannelPrivate))


G_DEFINE_TYPE(SpiceMainChannel, spice_main_channel, SPICE_TYPE_CHANNEL)

static void channel_set_handlers(SpiceChannelClass *klass);

static void spice_main_channel_init(SpiceMainChannel *channel)
{
}

static void spice_main_channel_class_init(SpiceMainChannelClass *klass)
{
    channel_set_handlers(SPICE_CHANNEL_CLASS(klass));
}
static void main_handle_init(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceMsgMainInit *init = spice_msg_in_parsed(in);
    SpiceSession *session;
    SpiceMsgOut *out;
    session = spice_channel_get_session(channel);
    spice_session_set_connection_id(session, init->session_id);
    out = spice_msg_out_new(SPICE_CHANNEL(channel), SPICE_MSGC_MAIN_ATTACH_CHANNELS);
    spice_msg_out_send_internal(out);
}

typedef struct channel_new {
    SpiceSession *session;
    int type;
    int id;
} channel_new_t;


static gboolean _channel_new(channel_new_t *c)
{
    g_return_val_if_fail(c != NULL, FALSE);
    spice_channel_new(c->session, c->type, c->id);
    g_object_unref(c->session);
    g_free(c);
    return FALSE;
}

static void usb_connect_failed(GObject *object,SpiceUsbDevice *device,GError *error,gpointer   data)
{
   return;
}



static void main_handle_channels_list(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceMsgChannels *msg = spice_msg_in_parsed(in);
    SpiceSession *session;
	SpiceUsbDeviceManager *manager;
    int i;
    session = spice_channel_get_session(channel);
    for (i = 0; i < msg->num_of_channels; i++) {
        channel_new_t *c;
        c = g_new(channel_new_t, 1);
        c->session = g_object_ref(session);
        c->type = msg->channels[i].type;
        c->id = msg->channels[i].id;
	 if(c->type == 9)
        g_idle_add((GSourceFunc)_channel_new, c);
     }

	manager = spice_usb_device_manager_get(session, NULL);
    if (manager) {
        g_signal_connect(manager, "auto-connect-failed",G_CALLBACK(usb_connect_failed), NULL);
        g_signal_connect(manager, "device-error",G_CALLBACK(usb_connect_failed), NULL);
    }

}

static void channel_set_handlers(SpiceChannelClass *klass)
{
    static const spice_msg_handler handlers[] = {
        [ SPICE_MSG_MAIN_INIT ]                = main_handle_init,
        [ SPICE_MSG_MAIN_CHANNELS_LIST ]       = main_handle_channels_list, };
   	 spice_channel_set_handlers(klass, handlers, G_N_ELEMENTS(handlers));
}

