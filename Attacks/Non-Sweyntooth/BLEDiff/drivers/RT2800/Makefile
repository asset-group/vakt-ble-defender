# SPDX-License-Identifier: GPL-2.0
KERNEL_MODULE_NAME = rt2800usb
rt2x00lib-y				+= rt2x00dev.o
rt2x00lib-y				+= rt2x00mac.o
rt2x00lib-y				+= rt2x00config.o
rt2x00lib-y				+= rt2x00queue.o
rt2x00lib-y				+= rt2x00link.o
rt2x00lib-$(CONFIG_RT2X00_LIB_DEBUGFS)	+= rt2x00debug.o
rt2x00lib-y	+= rt2x00crypto.o
rt2x00lib-y	+= rt2x00firmware.o
rt2x00lib-y	+= rt2x00leds.o

obj-m							+= rt2x00lib.o
obj-m							+= rt2x00mmio.o
obj-m							+= rt2x00pci.o
obj-m							+= rt2x00soc.o
obj-m							+= rt2x00usb.o
obj-m							+= rt2800lib.o
obj-m							+= rt2800mmio.o
obj-$(CONFIG_RT2400PCI)			+= rt2400pci.o
obj-$(CONFIG_RT2500PCI)			+= rt2500pci.o
obj-$(CONFIG_RT61PCI)			+= rt61pci.o
obj-m							+= rt2800pci.o
obj-$(CONFIG_RT2500USB)			+= rt2500usb.o
obj-$(CONFIG_RT73USB)			+= rt73usb.o
obj-m			+= rt2800usb.o
obj-$(CONFIG_RT2800SOC)			+= rt2800soc.o

KERNEL_NAME := $(shell uname -r)
KBUILD_OUTPUT := $(PWD)/build
DEFAULT_CHANNEL := 9
WIFI_INTERFACE := wlan1

all:
	#recover build files if they exist
	find . \( -name \*.ko -o -name \*.order -o -name \*.symvers -o -name \*.d -o -name \*.o -o -name \*.cmd -o -name \*.mod.c \) -exec mv {} $(PWD) \;
	#build module
	make -C /lib/modules/$(KERNEL_NAME)/build M=$(PWD) modules -j9
	#move module files to build folder
	find . \( -name \*.ko -o -name \*.order -o -name \*.symvers -o -name \*.d -o -name \*.o -o -name \*.cmd -o -name \*.mod.c \) -exec mv -f {} $(KBUILD_OUTPUT) \;

install:
ifneq ($(wildcard /usr/lib/modules/.*),)
	# Debian
	sudo find . -name \*.ko -exec cp -rf {} /usr/lib/modules/$(KERNEL_NAME)/kernel/drivers/net/wireless/ralink/rt2x00/ \;
else
	# Ubuntu
	sudo find . -name \*.ko -exec cp -rf {} /lib/modules/$(KERNEL_NAME)/kernel/drivers/net/wireless/ralink/rt2x00/ \;
endif
	
	
insert:
	#unload module
	-rmmod rt2800usb
	-rmmod rt2x00usb
	-rmmod rt2800lib
	-rmmod rt2x00lib
	#start module
	-modprobe rt2800usb
	#sleep 3
	#-airmon-ng start $(WIFI_INTERFACE)
	#-iwconfig wlan1mon channel $(DEFAULT_CHANNEL)

clean:
	find ./ \( -name \*.d -o -name \*.cmd -o -name \*.o -o -name \*.mod.c \) -exec rm {} \;
