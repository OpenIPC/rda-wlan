# rda-wlan

Rdamicro's `rdawfmac` FullMAC driver for the RDA5995 802.11b/g/n chip
(USB `1e04:8888`, or SDIO). The firmware and `power_config.txt` are compiled
into the module from the `rdawlan/*.bin.hex` arrays (`WLAND_DOWNLOAD_FIRMWARE_FROM_HEX`
in `rdawlan/wland_defs.h`); nothing is read from the filesystem. The RF test-mode
images are left out.

## Source

`drivers/net/wireless/rdaw80211` of
[realme-kernel-opensource/realme_TechLife_Robot_Vacuum-kernel-source](https://github.com/realme-kernel-opensource/realme_TechLife_Robot_Vacuum-kernel-source)
at `ef379d496bc0cd4b7bbeced783245f5e450a506d` (Linux 4.9.118). The first
commit here is that directory unmodified; every change since is a commit of
its own.

The source files carry Rdamicro's permission notice; the module declares
`MODULE_LICENSE("GPL v2")`.

## Build

Out of tree, against a configured kernel with `CONFIG_CFG80211`:

    make -C <kernel> M=$PWD/rdawlan ARCH=arm CROSS_COMPILE=<prefix> modules

The bus defaults to USB. For SDIO:

    make ... CONFIG_RDAWFMAC_USB= CONFIG_RDAWFMAC_SDIO=y
