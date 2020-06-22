#include <iostream>
#include <unistd.h>
# include <stdlib.h>
#include "usbredirapi.h"
using namespace std;
int main(int argc,char **argv)
{
    cout << "Hello, world!" << endl;
	
	int spiceport; 
	char *spiceip;
	
	spiceip=argv[1];
	spiceport=atoi(argv[2]);
	
	cout << "begin start usbredir..." << endl;
	start_usbredir(spiceip,spiceport);
	cout << "already start usbredir..." << endl;
	sleep(120);
	
	cout << "begin stop usbredir..." << endl;
	stop_usbredir();
	cout << "already stop usbredir..." << endl;
	
	
    return 0;
}

