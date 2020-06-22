#include "usbredirapi.h"
#include <unistd.h>
#include <errno.h>
#include<stdlib.h>   
#include<fcntl.h>    
#include<sys/stat.h>
#include<time.h>  
#include <stdio.h>
#include <string.h>



int start_usbredir(char *spiceip,int spiceport,char *filter_flag)
{
	char str[1024]={'\0'};
	char str1[8]={'\0'};
	sprintf( str1, "%d\n",spiceport); 
    
	strcpy (str,"start ");
    strcat (str,spiceip);
    strcat (str," ");

	strcat (str,filter_flag);
    strcat (str," ");
	
    strcat (str,str1);
	strcat (str," ");
    int str_len=strlen(str);
	
	int flag;
	flag=access("/tmp/usbredir",0);
	if(flag != 0){
		if(mkfifo("/tmp/usbredir", 0666) < 0 && errno!=EEXIST){
			printf("Create usbredir FIFO Failed");
			fflush(stdout);
		}
	}
	
	int fd; 
    if((fd = open("/tmp/usbredir", O_WRONLY|O_NONBLOCK)) < 0) 
    {
        printf("Open usbredir FIFO Failed");
		fflush(stdout);
        return 1;
    }
 
	if(write(fd, str,str_len) < 0) 
	{
	    printf("Write usbredir FIFO Failed");
		fflush(stdout);
	    close(fd);
	    return 1;
	}    
    close(fd);



	int reflag;
	reflag=access("/tmp/usbredir_config.txt",0);
	if(reflag==0){
		int re;
		re=remove("/tmp/usbredir_config.txt");
		if(re!=0){
			printf("remove /tmp/usbredir_config.txt failed!\n");
		}
	}

	int con_file;
	if((con_file=open("/tmp/usbredir_config.txt",O_RDWR|O_CREAT,0666)) < 0){

		printf("Create config file failed\n");
		fflush(stdout);
		return 1;
	}
	if(write(con_file, str,str_len) < 0) 
	{
	    printf("Write usbredir_config.txt failed\n");
		fflush(stdout);
	    close(con_file);
	    return 1;
	}    
	close(con_file);
	
	
    return 0;
}


int stop_usbredir(void)
{
	int fd; 
	
    if((fd = open("/tmp/usbredir", O_WRONLY|O_NONBLOCK)) < 0) 
    {
        printf("Open usbredir FIFO Failed");
		fflush(stdout);
        return 1;
    }
 
	if(write(fd, "stop",5) < 0) 
	{
	    printf("Write usbredir FIFO Failed");
		fflush(stdout);
	    close(fd);
	    return 1;
	}    
    close(fd);

	int reflag;
	reflag=access("/tmp/usbredir_config.txt",0);
	if(reflag !=0)
		return 0;

	int re;
	re=remove("/tmp/usbredir_config.txt");
	if(re!=0){
		printf("remove /tmp/usbredir_config.txt failed!\n");
	}
	
    return 0;
}

