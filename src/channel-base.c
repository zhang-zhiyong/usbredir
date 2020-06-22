/* -*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
   Copyright (C) 2010 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "config.h"

#include "spice-client.h"
#include "spice-common.h"

#include "spice-session-priv.h"
#include "spice-channel-priv.h"

/* coroutine context */
static void
spice_channel_handle_set_ack(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgSetAck* ack = spice_msg_in_parsed(in);
    SpiceMsgOut *out = spice_msg_out_new(channel, SPICE_MSGC_ACK_SYNC);
    SpiceMsgcAckSync sync = {
        .generation = ack->generation,
    };

    c->message_ack_window = c->message_ack_count = ack->window;
    c->marshallers->msgc_ack_sync(out->marshaller, &sync);
    spice_msg_out_send_internal(out);
}

/* coroutine context */
static void
spice_channel_handle_ping(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgPing *ping = spice_msg_in_parsed(in);
    SpiceMsgOut *pong = spice_msg_out_new(channel, SPICE_MSGC_PONG);

    c->marshallers->msgc_pong(pong->marshaller, ping);
    spice_msg_out_send_internal(pong);
}

/* coroutine context */
static void
spice_channel_handle_notify(SpiceChannel *channel, SpiceMsgIn *in)
{
    static const char* severity_strings[] = {"info", "warn", "error"};
    static const char* visibility_strings[] = {"!", "!!", "!!!"};

    SpiceMsgNotify *notify = spice_msg_in_parsed(in);
    const char *severity   = "?";
    const char *visibility = "?";
    const char *message_str = NULL;

    if (notify->severity <= SPICE_NOTIFY_SEVERITY_ERROR) {
        severity = severity_strings[notify->severity];
    }
    if (notify->visibilty <= SPICE_NOTIFY_VISIBILITY_HIGH) {
        visibility = visibility_strings[notify->visibilty];
    }

    if (notify->message_len &&
        notify->message_len <= in->dpos - sizeof(*notify)) {
        message_str = (char*)notify->message;
    }

    CHANNEL_DEBUG(channel, "%s -- %s%s #%u%s%.*s", __FUNCTION__,
            severity, visibility, notify->what,
            message_str ? ": " : "", (int)notify->message_len,
            message_str ? message_str : "");
}

/* coroutine context */
static void
spice_channel_handle_disconnect(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceMsgDisconnect *disconnect = spice_msg_in_parsed(in);

    CHANNEL_DEBUG(channel, "%s: ts: %" PRIu64", reason: %u", __FUNCTION__,
                  disconnect->time_stamp, disconnect->reason);
}

typedef struct WaitForChannelData
{
    SpiceWaitForChannel *wait;
    SpiceChannel *channel;
} WaitForChannelData;

/* coroutine and main context */
static gboolean wait_for_channel(gpointer data)
{
    WaitForChannelData *wfc = data;
    SpiceChannelPrivate *c = wfc->channel->priv;
    SpiceChannel *wait_channel;

    wait_channel = spice_session_lookup_channel(c->session, wfc->wait->channel_id, wfc->wait->channel_type);
    g_return_val_if_fail(wait_channel != NULL, TRUE);

    if (wait_channel->priv->last_message_serial >= wfc->wait->message_serial)
        return TRUE;

    return FALSE;
}

/* coroutine context */
G_GNUC_INTERNAL
void spice_channel_handle_wait_for_channels(SpiceChannel *channel, SpiceMsgIn *in)
{
    SpiceChannelPrivate *c = channel->priv;
    SpiceMsgWaitForChannels *wfc = spice_msg_in_parsed(in);
    int i;

    for (i = 0; i < wfc->wait_count; ++i) {
        WaitForChannelData data = {
            .wait = wfc->wait_list + i,
            .channel = channel
        };

        CHANNEL_DEBUG(channel, "waiting for serial %" PRIu64 " (%d/%d)", data.wait->message_serial, i + 1, wfc->wait_count);
        if (g_coroutine_condition_wait(&c->coroutine, wait_for_channel, &data))
            CHANNEL_DEBUG(channel, "waiting for serial %"  PRIu64 ", done", data.wait->message_serial);
        else
            CHANNEL_DEBUG(channel, "waiting for serial %" PRIu64 ", cancelled", data.wait->message_serial);
    }
}


static void set_handlers(SpiceChannelClassPrivate *klass,
                         const spice_msg_handler* handlers, const int n)
{
    int i;

    g_array_set_size(klass->handlers, MAX(klass->handlers->len, n));
    for (i = 0; i < n; i++) {
        if (handlers[i])
            g_array_index(klass->handlers, spice_msg_handler, i) = handlers[i];
    }
}

static void spice_channel_add_base_handlers(SpiceChannelClassPrivate *klass)
{
    static const spice_msg_handler handlers[] = {
        [ SPICE_MSG_SET_ACK ]                  = spice_channel_handle_set_ack,
        [ SPICE_MSG_PING ]                     = spice_channel_handle_ping,
        [ SPICE_MSG_NOTIFY ]                   = spice_channel_handle_notify,
        [ SPICE_MSG_DISCONNECTING ]            = spice_channel_handle_disconnect,
        [ SPICE_MSG_WAIT_FOR_CHANNELS ]        = spice_channel_handle_wait_for_channels,
    };

    set_handlers(klass, handlers, G_N_ELEMENTS(handlers));
}

G_GNUC_INTERNAL void spice_channel_set_handlers(SpiceChannelClass *klass,const spice_msg_handler* handlers, const int n)
{
    klass->priv =G_TYPE_CLASS_GET_PRIVATE (klass, spice_channel_get_type (), SpiceChannelClassPrivate);
    g_return_if_fail(klass->priv->handlers == NULL);
    klass->priv->handlers = g_array_sized_new(FALSE, TRUE, sizeof(spice_msg_handler), n);
    spice_channel_add_base_handlers(klass->priv);
    set_handlers(klass->priv, handlers, n);
}

static void vmc_write_free_cb(uint8_t *data, void *user_data)
{
    GTask *task = user_data;
    gsize count = GPOINTER_TO_SIZE(g_task_get_task_data(task));
    g_task_return_int(task, count);
    g_object_unref(task);
}

G_GNUC_INTERNAL
void spice_vmc_write_async(SpiceChannel *self,
                           const void *buffer, gsize count,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
    SpiceMsgOut *msg;
    GTask *task;

    task = g_task_new(self, cancellable, callback, user_data);
    g_task_set_task_data(task, GSIZE_TO_POINTER(count), NULL);

    msg = spice_msg_out_new(SPICE_CHANNEL(self), SPICE_MSGC_SPICEVMC_DATA);
    spice_marshaller_add_by_ref_full(msg->marshaller, (uint8_t*)buffer, count,
                                     vmc_write_free_cb, task);
    spice_msg_out_send(msg);
}

G_GNUC_INTERNAL
gssize spice_vmc_write_finish(SpiceChannel *self,
                              GAsyncResult *result, GError **error)
{
    GTask *task;

    g_return_val_if_fail(result != NULL, -1);

    task = G_TASK(result);

    g_return_val_if_fail(g_task_is_valid(task, self), -1);

    return g_task_propagate_int(task, error);
}
