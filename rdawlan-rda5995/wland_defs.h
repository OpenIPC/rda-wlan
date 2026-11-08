/* SPDX-License-Identifier: ISC */
/*
 * Copyright (c) 2014 Rdamicro Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _WLAND_DEFS_H_
#define _WLAND_DEFS_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/bits.h>
#include <linux/jiffies.h>

#define WLAND_VER_MAJ			1
#define WLAND_VER_MIN			5
#define WLAND_VER_BLD			0

/* Alignment slack added to the control receive buffer */
#define WLAND_RXCTL_ALIGN		BIT(2)

enum WLAND_CHIP_VERSION {
	WLAND_VER_91_H = 7,
};

#define WLAND_DEFAULT_COUNTRY_CODE	SITE_SURVEY_EU_CH

/* Number of entries in the rate table: 4 11b, 8 11g and 8 11n rates */
#define ALL_RATE_NUM			20

/* Firmware images per mode and their load addresses */
#define RDA5991H_USB_CODE_STA		"rda5995_usb_code_p2p.bin"
#define RDA5991H_USB_DATA_STA		"rda5995_usb_data_p2p.bin"

#define RDA5991H_USB_CODE_AP		"rda5995_usb_code_ap.bin"
#define RDA5991H_USB_DATA_AP		"rda5995_usb_data_ap.bin"

#define RDA5991H_USB_CODE_P2P		"rda5995_usb_code_p2p.bin"
#define RDA5991H_USB_DATA_P2P		"rda5995_usb_data_p2p.bin"

#define RDA5991H_USB_CODE_RF		"rda5995_usb_code_rf.bin"
#define RDA5991H_USB_DATA_RF		"rda5995_usb_data_rf.bin"

#define RDA5991H_CODE_ADDR		0x100000
#define RDA5991H_DATA_ADDR_STA_AP	0x180000
#define RDA5991H_DATA_ADDR_P2P		0x184000

/* STA mode uses three code regions and one data region. */
#define RDA5995_USB_STA_CODE1		"rda5995_usb_code1_p2p.bin"
#define RDA5995_USB_STA_CODE2		"rda5995_usb_code2_p2p.bin"
#define RDA5995_USB_STA_CODE1_ADDR	0x180000
#define RDA5995_USB_STA_CODE2_ADDR	0x190000
#define RDA5995_USB_STA_DATA_ADDR	0x1880e0

#define USB_VENDOR_ID_RDAMICRO		0x1E04
#define USB_DEVICE_ID_RDA599X		0x8888

#define BIT7				BIT(7)
#define BIT2				BIT(2)
#define BIT1				BIT(1)
#define BIT0				BIT(0)

#define DEFAULT_SCAN			0

/* Status values reported with firmware events */
#define STATUS_SUCCESS			1
#define STATUS_TIMEOUT			2
#define STATUS_FAILED			4
#define STATUS_NO_NETWORKS		5

/* WID_STATUS values */
#define MAC_DISCONNECTED		0
#define MAC_CONNECTED			1
#define P2P_MAC_DISCONNECTED		2
#define P2P_MAC_CONNECTED		3

/* WID_SCAN_CONNECT_RESULT values */
#define RESULT_SCAN_COMP		0x00
#define RESULT_CONN_FAIL		0x10
#define RESULT_P2P_CONN_FAIL		0x20

#define WLAND_BAND_AUTO			0
#define WLAND_BAND_5G			1
#define WLAND_BAND_2G			2
#define WLAND_BAND_ALL			3

#define IOCTL_RESP_TIMEOUT		(5 * 1000)	/* ms */
#define SCAN_CMP_TIMEOUT		(2 * 1000)	/* ms */

/* Scan dwell times (ms) */
#define SCAN_CHANNEL_TIME		20
#define SCAN_ACTIVE_TIME		20
#define SCAN_PASSIVE_TIME		20

/* WID packet header: bits 0-11 length, bits 12-15 packet type */
#define CDC_DCMD_LEN_MASK		0x0FFF
#define CDC_DCMD_LEN_SHIFT		12

#define MOD_PARAM_PATHLEN		100
extern char rdawlan_firmware_path[MOD_PARAM_PATHLEN];
extern unsigned char WifiMac[6];
extern int n_WifiMac;

#define WIFI_LISTEN_INTERVAL		0x1
#define WIFI_LINK_LOSS_THRESHOLD_91H	0x40

/* Length of the WID header on TX, and of the RX data header */
#define WID_HEADER_LEN			2
#define WID_HEADER_LEN_RX		6

#define WLAND_TID_NUM			4

#endif /* _WLAND_DEFS_H_ */
