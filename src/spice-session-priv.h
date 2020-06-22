#ifndef __SPICE_CLIENT_SESSION_PRIV_H__
#define __SPICE_CLIENT_SESSION_PRIV_H__
#include "config.h"
#include <glib.h>
#include <gio/gio.h>
#include "spice-session.h"
#include "spice-channel-cache.h"
G_BEGIN_DECLS
void spice_session_set_connection_id(SpiceSession *session, int id);
int spice_session_get_connection_id(SpiceSession *session);
gboolean spice_session_get_client_provided_socket(SpiceSession *session);
GSocketConnection* spice_session_channel_open_host(SpiceSession *session, SpiceChannel *channel,gboolean *use_tls, GError **error);
void spice_session_channel_new(SpiceSession *session, SpiceChannel *channel);
SpiceChannel* spice_session_lookup_channel(SpiceSession *session, gint id, gint type);
G_END_DECLS
#endif 
