# SPDX-License-Identifier: ISC
# Out-of-tree Kbuild Makefile for Rdamicro 802.11 USB wireless driver

ccflags-y += \
	-I$(src) \
	-I$(src)/include

ccflags-y += -D__CHECK_ENDIAN__
ccflags-$(CONFIG_RDAWDBG) += -DDEBUG

obj-m += rdawfmac.o
rdawfmac-objs += \
	wland_p2p.o \
	wland_d11.o \
	wland_nvram.o \
	wland_utils.o \
	wland_trap.o \
	wland_bus.o \
	wland_cmds.o \
	wland_fwsmgr.o \
	wland_wid.o \
	wland_fweh.o \
	wland_linux.o \
	wland_cfg80211.o \
	wland_rx.o \
	wland_rf.o \
	wland_usb.o
