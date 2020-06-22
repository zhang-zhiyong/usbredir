
#ifndef __SPICE_CLIENT_MAIN_CHANNEL_H__
#define __SPICE_CLIENT_MAIN_CHANNEL_H__
#if !defined(__SPICE_CLIENT_H_INSIDE__) && !defined(SPICE_COMPILATION)
#warning "Only <spice-client.h> can be included directly"
#endif

G_BEGIN_DECLS
#define SPICE_TYPE_MAIN_CHANNEL            (spice_main_channel_get_type())
#define SPICE_MAIN_CHANNEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), SPICE_TYPE_MAIN_CHANNEL, SpiceMainChannel))
#define SPICE_MAIN_CHANNEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), SPICE_TYPE_MAIN_CHANNEL, SpiceMainChannelClass))
#define SPICE_IS_MAIN_CHANNEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), SPICE_TYPE_MAIN_CHANNEL))
#define SPICE_IS_MAIN_CHANNEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), SPICE_TYPE_MAIN_CHANNEL))
#define SPICE_MAIN_CHANNEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), SPICE_TYPE_MAIN_CHANNEL, SpiceMainChannelClass))

typedef struct _SpiceMainChannel SpiceMainChannel;
typedef struct _SpiceMainChannelClass SpiceMainChannelClass;
struct _SpiceMainChannel {
    SpiceChannel parent;
};
struct _SpiceMainChannelClass {
    SpiceChannelClass parent_class;
};
GType spice_main_channel_get_type(void);
G_END_DECLS
#endif /* __SPICE_CLIENT_MAIN_CHANNEL_H__ */
