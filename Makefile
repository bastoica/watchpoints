obj-m += watchpoints.o
DEBUG_CFLAGS += -g -DDEBUG
CFLAGS_watchpoints.o += -Wall -W -Werror -Wextra -Wno-unused-parameter
ccflags-y += ${DEBUG_CFLAGS}
CC += ${DEBUG_CFLAGS}

release:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules;
	sudo insmod watchpoints.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean;
	sudo rmmod watchpoints.ko

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules;
	EXTRA_CFLAGS="$(DEBUG_CFLAGS)";
	sudo insmod watchpoints.ko
