obj-m += cryptomodule.o

all:
	make -C /lib/modules/4.15.0evandro01/build M=$(PWD) modules
	$(CC) cryptouser.c -o crypto
clean:
	make -C /lib/modules/4.15.0evandro01/build M=$(PWD) clean
	rm -f other/ioctl other/cat_noblock *.plist
