#ifndef __SPICE_CLIENT_SESSION_H__
#define __SPICE_CLIENT_SESSION_H__

#if !defined(__SPICE_CLIENT_H_INSIDE__) && !defined(SPICE_COMPILATION)
#warning "Only <spice-client.h> can be included directly"
#endif

#include <glib-object.h>
#include "spice-types.h" 
#include "spice-glib-enums.h"
#include "spice-util.h"

G_BEGIN_DECLS
#define SPICE_TYPE_SESSION            (spice_session_get_type ())
#define SPICE_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SPICE_TYPE_SESSION, SpiceSession))
#define SPICE_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SPICE_TYPE_SESSION, SpiceSessionClass))
#define SPICE_IS_SESSION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SPICE_TYPE_SESSION))
#define SPICE_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SPICE_TYPE_SESSION))
#define SPICE_SESSION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SPICE_TYPE_SESSION, SpiceSessionClass))
struct _SpiceSession
{
    GObject parent;
    SpiceSessionPrivate *priv; 
};
struct _SpiceSessionClass
{
    GObjectClass parent_class; 
    void (*channel_new)(SpiceSession *session, SpiceChannel *channel);
    void (*channel_destroy)(SpiceSession *session, SpiceChannel *channel);  
};
GType spice_session_get_type(void);
SpiceSession *spice_session_new(void);
gboolean spice_session_connect(SpiceSession *session);
gboolean spice_session_open_fd(SpiceSession *session, int fd);
void spice_session_disconnect(SpiceSession *session);
GList *spice_session_get_channels(SpiceSession *session); 
G_END_DECLS

#endif /* __SPICE_CLIENT_SESSION_H__ */
