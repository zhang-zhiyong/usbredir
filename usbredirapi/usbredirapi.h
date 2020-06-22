#ifndef USB_REDIR_API_H
#define USB_REDIR_API_H

	#ifdef __cplusplus
	extern "C" {
	#endif

		int stop_usbredir(void);
		int start_usbredir(char *spiceip,int spiceport,char * filter_flag);

	#ifdef __cplusplus
	}
	#endif

#endif



