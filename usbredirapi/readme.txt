usbredir功能的开启与关闭接口
头文件：
	usbredirapi.h
库文件：
	libusbredirapi.so
接口说明：
int start_usbredir(char *spiceip,int spiceport，char * filter_flagchar)
	功能：开启USB重定向功能
	参数：
		spiceip：虚拟机所在宿主机的ip地址
		spiceport：用于usb重定向的spice端口号,对于workstation此端口为固定（3241）
		filter_flag:USB设备的过滤过滤规则，对于WORKStation此参数没有意义可以为空
	返回值：如果开启成功返回0

int stop_usbredir(void);
	功能：关闭USB重定向功能
	参数：无
	返回值：关闭成功返回0
	


