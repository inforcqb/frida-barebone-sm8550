obj-m += rwtest.o

KDIR ?= /opt/ddk/kdir/android13-5.15
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
