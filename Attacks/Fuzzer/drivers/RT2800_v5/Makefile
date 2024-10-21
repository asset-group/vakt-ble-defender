# SPDX-License-Identifier: GPL-2.0
rt2x00lib-y				+= rt2x00dev.o
rt2x00lib-y				+= rt2x00mac.o
rt2x00lib-y				+= rt2x00config.o
rt2x00lib-y				+= rt2x00queue.o
rt2x00lib-y				+= rt2x00link.o
rt2x00lib-$(CONFIG_RT2X00_LIB_DEBUGFS)	+= rt2x00debug.o
rt2x00lib-$(CONFIG_RT2X00_LIB_CRYPTO)	+= rt2x00crypto.o
rt2x00lib-$(CONFIG_RT2X00_LIB_FIRMWARE)	+= rt2x00firmware.o
rt2x00lib-$(CONFIG_RT2X00_LIB_LEDS)	+= rt2x00leds.o

obj-$(CONFIG_RT2X00_LIB)		+= rt2x00lib.o
obj-$(CONFIG_RT2X00_LIB_MMIO)		+= rt2x00mmio.o
obj-$(CONFIG_RT2X00_LIB_PCI)		+= rt2x00pci.o
obj-$(CONFIG_RT2X00_LIB_SOC)		+= rt2x00soc.o
obj-$(CONFIG_RT2X00_LIB_USB)		+= rt2x00usb.o
obj-$(CONFIG_RT2800_LIB)		+= rt2800lib.o
obj-$(CONFIG_RT2800_LIB_MMIO)		+= rt2800mmio.o
obj-$(CONFIG_RT2400PCI)			+= rt2400pci.o
obj-$(CONFIG_RT2500PCI)			+= rt2500pci.o
obj-$(CONFIG_RT61PCI)			+= rt61pci.o
obj-$(CONFIG_RT2800PCI)			+= rt2800pci.o
obj-$(CONFIG_RT2500USB)			+= rt2500usb.o
obj-$(CONFIG_RT73USB)			+= rt73usb.o
obj-$(CONFIG_RT2800USB)			+= rt2800usb.o
obj-$(CONFIG_RT2800SOC)			+= rt2800soc.o


PROCESSORS_NUMBER := $(shell nproc)
KERNEL_NAME := $(shell uname -r)
KERNEL_MODULE_DIR := /lib/modules/$(KERNEL_NAME)/
DRIVER_PATH := $(KERNEL_MODULE_DIR)/kernel/drivers/net/wireless/ralink/rt2x00/
WORKING_DIR := $(shell pwd)

DEFAULT_CHANNEL := 9
WIFI_INTERFACE := wlan1

C_CYAN=\033[0;36m
C_YELLOW=\033[0;33m
C_BLUE=\033[0;34m
C_GREEN=\033[0;32m
C_RED=\033[0;31m
C_NC=\033[0m # No Color

all:
	# Build module
	make -C $(KERNEL_MODULE_DIR)/build M=$(WORKING_DIR) modules -j$(PROCESSORS_NUMBER)
	@echo "$(C_GREEN)Module build successfully $(C_NC)"
	@echo "$(C_YELLOW)You can run $(C_BLUE)sudo make install insert$(C_YELLOW) to install and load the module $(C_NC)"

install: all
	# Install module to system
	find . -name '*.ko'
	sudo find . -name '*.ko' -exec cp -rf {} $(DRIVER_PATH) \;

	@echo "$(C_GREEN)Module installed to $(DRIVER_PATH) $(C_NC)"
	@echo "$(C_YELLOW)You can run $(C_BLUE)sudo make install insert$(C_YELLOW) to install and load the module $(C_NC)"
	
insert: install
	# Unload current module
	@echo "$(C_YELLOW)Unloading current driver...$(C_NC)"
	@echo "$(C_YELLOW)Unloading rt2800usb...$(C_NC)"
	@-sudo rmmod rt2800usb &> /dev/null
	@sleep 0.5
	@echo "$(C_YELLOW)Unloading rt2x00usb...$(C_NC)"
	@-sudo rmmod rt2x00usb &> /dev/null
	@sleep 0.5
	@echo "$(C_YELLOW)Unloading rt2800lib...$(C_NC)"
	@-sudo rmmod rt2800lib &> /dev/null
	@sleep 0.5
	@echo "$(C_YELLOW)Unloading rt2x00lib...$(C_NC)"
	@-sudo rmmod rt2x00lib &> /dev/null
	@sleep 1
	# Load compiled module
	@echo "$(C_YELLOW)Loading this driver...$(C_NC)"
	sudo dmesg -C
	sudo modprobe rt2800usb
	@sleep 3
	make check-driver

check-driver:
	# Check if driver was loaded correctly
	@if [ -z "$(shell dmesg | grep "Netlink: Started on port 31")" ]; then \
		echo "$(C_RED)[ERROR] Module not running. Please make sure that the driver was installed correctly.$(C_NC)"; \
		echo "$(C_RED)You can check if the folder $(DRIVER_PATH) contains this compiled driver.$(C_NC)"; \
	else \
		echo "$(C_GREEN)[OK] Module is running. Netlink Server detected.$(C_NC)"; \
	fi

test-airmon:
	-airmon-ng start $(WIFI_INTERFACE)
	-iwconfig wlan1mon channel $(DEFAULT_CHANNEL)

clean:
	# Clean module
	make -C $(KERNEL_MODULE_DIR)/build M=$(WORKING_DIR) clean