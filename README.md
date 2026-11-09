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

## rdawlan-rda5995

A separate copy of Rdamicro's `rdaw80211` driver, USB only, maintained for
the RDA5995 on FH8626V100 cameras with Linux 4.19. Unlike `rdawlan/`, it
compiles no firmware in: it loads the chip firmware through the firmware
loader from `/lib/firmware`. With the default `firmware_path=sta`:

- `rda5995_usb_code_p2p.bin`
- `rda5995_usb_code1_p2p.bin`
- `rda5995_usb_code2_p2p.bin`
- `rda5995_usb_data_p2p.bin`

`firmware_path=ap` loads `rda5995_usb_code_ap.bin` and
`rda5995_usb_data_ap.bin` instead. It builds on its own:

    make -C <kernel> M=$PWD/rdawlan-rda5995 ARCH=arm CROSS_COMPILE=<prefix> modules

`rdawlan-rda5995/firmware/` holds these files as they were on the flash of
an FH8626V100 camera with this chip, where the vendor driver loaded them.
They are a different build from the arrays in `rdawlan/`, which this driver
does not load: the STA profile has a fourth, 40-byte `code2` segment. No
licence for the firmware came with them.
