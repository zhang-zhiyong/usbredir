all:
	aarch64-rockchip-linux-gnu-cc  usbredirapi.c -fPIC -g -shared -o libusbredirapi.so
	aarch64-rockchip-linux-gnu-cc   usbredirapi_test.c -g  -L. -lusbredirapi -o usbredirapi_test
	#aarch64-rockchip-linux-gnu-g++   usbredirapi_test.cpp -g -L. -lusbredirapi -o usbredirapicpp_test
clean:
	rm -rf libusbredirapi.so usbredirapi_test usbredirapicpp_test
