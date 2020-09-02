#include <string.h>

#include <glib.h>
#include <sys/stat.h>
#include "spice-client.h"
#include "spice-common.h"
#include "spice-cmdline.h"

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include <glib/gprintf.h>
#include <unistd.h>
#include <sys/syscall.h>



typedef struct spice_connection spice_connection;
struct spice_connection {
    SpiceSession     *session;
    SpiceMainChannel *main;
    int              channels;
    int              disconnecting;
};

static spice_connection *connection_new(void);
static char * connection_connect(spice_connection *conn);
static void connection_disconnect(spice_connection *conn);
static GMainLoop     *mainloop = NULL;
static int           connections = 0;

static void main_channel_event(SpiceChannel *channel, SpiceChannelEvent event,gpointer data)
{
    const GError *error = NULL;
    spice_connection *conn = data;
    switch (event) {
    case SPICE_CHANNEL_OPENED:
        g_message("main channel: opened");
        break;
    case SPICE_CHANNEL_SWITCHING:
        g_message("main channel: switching host");
        break;
    case SPICE_CHANNEL_CLOSED:
        g_message("main channel: closed");
        connection_disconnect(conn);
        break;
    case SPICE_CHANNEL_ERROR_IO:
        connection_disconnect(conn);
        break;
    case SPICE_CHANNEL_ERROR_TLS:
    case SPICE_CHANNEL_ERROR_LINK:
    case SPICE_CHANNEL_ERROR_CONNECT:
        error = spice_channel_get_error(channel);
        g_message("main channel: failed to connect");
        if (error) {
            g_message("channel error: %s", error->message);
        }
        connection_disconnect(conn);
        break;
    case SPICE_CHANNEL_ERROR_AUTH:
        g_warning("main channel: auth failure (wrong password?)");
            connection_disconnect(conn);
        break;
    default:
        g_warning("unknown main channel event: %u", event);
        break;
    }
}

static void channel_new(SpiceSession *s, SpiceChannel *channel, gpointer data)
{
    spice_connection *conn = data;
    int id;
    g_object_get(channel, "channel-id", &id, NULL);
    conn->channels++;
    if (SPICE_IS_MAIN_CHANNEL(channel)) {
        conn->main = SPICE_MAIN_CHANNEL(channel);
        g_signal_connect(channel, "channel-event",G_CALLBACK(main_channel_event), conn);
    }
}

static void channel_destroy(SpiceSession *s, SpiceChannel *channel, gpointer data)
{
    spice_connection *conn = data;
    int id;
    g_object_get(channel, "channel-id", &id, NULL);
    if (SPICE_IS_MAIN_CHANNEL(channel)) {
        conn->main = NULL;
    }
    conn->channels--;
    if (conn->channels > 0) {
        return;
    }
}

static spice_connection *connection_new(void)
{
    spice_connection *conn;
    conn = g_new0(spice_connection, 1);
    conn->session = spice_session_new();
    g_signal_connect(conn->session, "channel-new",G_CALLBACK(channel_new), conn);
    g_signal_connect(conn->session, "channel-destroy",G_CALLBACK(channel_destroy), conn);
    connections++;
    return conn;
}

static char * connection_connect(spice_connection *conn)
{
    conn->disconnecting = false;
    if(spice_session_connect(conn->session)){
		return "success";
    }else{
		return "failed";
    }
}




static void connection_disconnect(spice_connection *conn)
{
    if (conn->disconnecting)
        return;
    conn->disconnecting = true;
    spice_session_disconnect(conn->session);
}

//zhangzhiyong add filter_flag
char *filter_flag=NULL;
static gpointer usbredirgthread(gpointer data)
{
	printf("Start Usb-redir Gthread success!!!!!!!\n");
	fflush(stdout);
	int fd;
	int len;
	char buf[1024];
	spice_connection * conn = NULL;
	char *status=NULL,*spiceip,*spiceport;
	int configfd;
	int reflag;
	reflag=access("/tmp/usbredir_config.txt",0);
	if(reflag==0){
		 if((configfd = open("/tmp/usbredir_config.txt", O_RDONLY)) < 0){
		  printf("Open /tmp/usbredir_config.txt Failed\n");
		  fflush(stdout);
		  return NULL;
	   	}
		len = read(configfd, buf, 1024);
		if(len>0){
			conn= connection_new();
			status=strtok(buf," ");
			spiceip=strtok(NULL," ");
			filter_flag=strtok(NULL," ");
			printf("read /tmp/usbredir_config.txt get filter_flag=%s!!!!!!!\n",filter_flag);
	        fflush(stdout);
			spiceport=strtok(NULL," ");
			g_object_set(conn->session, "host", spiceip, NULL);
			g_object_set(conn->session, "port", spiceport, NULL);
			char* bstatus;
			bstatus=connection_connect(conn);
			if(!strcmp("success",bstatus)){
				printf("Start  usb-redir success /tmp/usbredir_config.txt !!\n");
				fflush(stdout);
			}
			if(!strcmp("failed",bstatus)){
				printf("Start usb-redir failed /tmp/usbredir_config.txt!!\n");
				fflush(stdout);
			}
	
		} 	
	}

	int flag;
	flag=access("/tmp/usbredir",0);
	if(flag !=0){
		if(mkfifo("/tmp/usbredir", 0666) < 0 && errno!=EEXIST){
			printf("Create usbredir FIFO Failed\n");
			fflush(stdout);
		}
	}
		
	if((fd = open("/tmp/usbredir", O_RDONLY)) < 0){
		 printf("Open FIFO Failed\n");
		 fflush(stdout);
	}
	
	while(true){
		len = read(fd, buf, 1024);
		if(len > 0){
			if(!strcmp("stop",buf)){
					printf("Recive stop usb-redir command!\n");
					fflush(stdout);
					if(status){
						status=NULL;
						connection_disconnect(conn);
						filter_flag=NULL;
						printf("Stop usb-redir success!!\n");
						fflush(stdout);
					}else{
						printf("Usb-redir not start\n");
						fflush(stdout);
					}
					
	
			}else{
					printf("Recive start usb-redir command!\n");
					fflush(stdout);
					conn= connection_new();
					status=strtok(buf," ");
					spiceip=strtok(NULL," ");
					filter_flag=strtok(NULL," ");
					printf(" get form command filter_flag=%s\n",filter_flag);
	      			fflush(stdout);
					spiceport=strtok(NULL," ");
					g_object_set(conn->session, "host", spiceip, NULL);
					g_object_set(conn->session, "port", spiceport, NULL);

					if(!strcmp("start",status)){
    					char* cstatus;
						cstatus=connection_connect(conn);
						if(!strcmp("success",cstatus)){
							printf("Start usb-redir success!!\n");
							fflush(stdout);
						}
						if(!strcmp("failed",cstatus)){
							printf("Start usb-redir failed!!\n");
							fflush(stdout);
						}
					}
			}
			
		}
		usleep(50000);
	}

  return NULL;
}

int main(int argc, char *argv[])
{

	mainloop = g_main_loop_new(NULL, false);
	
	GThread *usbgthread = NULL;
	usbgthread = g_thread_new("usbredirgthread", usbredirgthread, NULL);
	if(usbgthread == NULL){
		printf("Create USB-Redir Gthread error\n");
		fflush(stdout);
		return -1;
	}else{
		printf("Create Usb-redir Gthread success\n");
		fflush(stdout);
	}
	g_main_loop_run(mainloop);
	
    return 0;
}


