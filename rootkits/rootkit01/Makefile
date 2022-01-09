
obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

compile-v2:
	make -C /lib/modules/5.11.0-22-generic/build M=$(PWD) modules

compile-v2-clean:
	make -C /lib/modules/5.11.0-22-generic/build M=$(PWD) clean
