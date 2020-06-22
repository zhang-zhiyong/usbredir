#include <stdio.h>
#include "usbredirapi.h"
# include <stdlib.h>
int main(int argc,char** argv)
{
	char *spiceip;
	spiceip=argv[1];

	
	int  spiceport; 
	spiceport=atoi(argv[2]);

	char * op;
	op = argv[3];

	
	char * filter_flag;
	filter_flag=argv[4];
	

	if(!strcmp("start",op))
	{
		printf("\nbegin start usbredir...\n");
		start_usbredir(spiceip,spiceport,filter_flag);
		printf("\nalready start usbredir...\n");
	}
	//sleep(300);
	
	if(!strcmp("stop",op)){
		printf("\nbegin stop usbredir...\n");
		stop_usbredir();
		printf("\nalready stop usbredir...\n");
	}
	
	return 0;
	
}


























