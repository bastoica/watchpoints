obj-m += watchpoints.o
CFLAGS_watchpoints.o := -Wall -W -Werror -Wextra -Wno-unused-parameter

watchpoints:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) ARC=x86_64 modules;
	sudo insmod watchpoints.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean;
	sudo rmmod watchpoints.ko
