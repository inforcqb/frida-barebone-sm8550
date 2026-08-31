# panic_capture - kernel die/panic capture module (DDK build)

obj-m += panic_capture.o

KDIR ?= /lib/modules/$(shell uname -r)/build

ccflags-y := -Wall -Wno-unused-parameter

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
