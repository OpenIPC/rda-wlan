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
#ifndef _802_11_H_
#define _802_11_H_

#include <linux/bits.h>

#define MAC_HDR_LEN			24	/* No Address4 - non-ESS */
#define MAX_SSID_LEN			33
#define FCS_LEN				4
#define TIME_STAMP_LEN			8
#define BEACON_INTERVAL_LEN		2
#define CAP_INFO_LEN			2
#define LISTEN_INTERVAL_LEN		2
#define STATUS_CODE_LEN			2
#define AID_LEN				2
#define IE_HDR_LEN			2
#define MAC_HDR_ADDR2_OFFSET		10

/* Size of the HT/VHT Control field in the MAC header */
#define HT_CTRL_HDR_LEN			4

/* True if the HT Control field is present in a management frame. */
#define IS_MGMT_HTC_PRESENT(pu1_msa)		(!!((pu1_msa)[1] & BIT(7)))

/* Length of the MAC header of a management frame. */
#define GET_MGMT_HDR_LEN(pu1_msa) \
	((IS_MGMT_HTC_PRESENT(pu1_msa)) ? \
	 (MAC_HDR_LEN + HT_CTRL_HDR_LEN) : (MAC_HDR_LEN))

#define DOT11_BCN_PRB_FIXED_LEN		12
#define DOT11_MGMT_HDR_LEN		24
#define DOT11_MAX_SSID_LEN		32

/* WPA / WPS / RSN / WME vendor IE identifiers */
#define WPA_OUI				"\x00\x50\xF2"
#define WPA_OUI_TYPE			1
#define WPS_OUI_TYPE			4
#define RSN_OUI				"\x00\x0F\xAC"
#define WME_OUI_TYPE			2

#define WPA_IE_SUITE_COUNT_LEN		2

/* WPA cipher suites */
#define WPA_CIPHER_NONE			0
#define WPA_CIPHER_WEP_40		1
#define WPA_CIPHER_TKIP			2
#define WPA_CIPHER_AES_CCM		4
#define WPA_CIPHER_WEP_104		5

/* Element IDs of information elements */
enum ELEMENTID_T {
	IDSPARMS	= 3,	/* DS parameter set */
	ITIM		= 5,	/* Traffic Information Map */
};

/* Frame type and subtype codes (6-bit) */
enum TYPESUBTYPE_T {
	ASSOC_REQ	= 0x00,
	ASSOC_RSP	= 0x10,
	PROBE_RSP	= 0x50,
	BEACON		= 0x80,
	ACTION		= 0xD0,
};

/* Bitfield map used by firmware to determine 11i mode */
#define NO_ENCRYPT			0
#define ENCRYPT_ENABLED			BIT(0)
#define WEP				BIT(1)
#define WEP_EXTENDED			BIT(2)
#define WPA				BIT(3)
#define WPA2				BIT(4)
#define AES				BIT(5)
#define TKIP				BIT(6)

enum SECURITY_T {
	WPA_AES		= 0x29,
	WPA_TKIP	= 0x49,
	WPA2_AES	= 0x31,
	WPA2_TKIP	= 0x51,
};

enum AUTHTYPE_T {
	OPEN_SYSTEM	= 1,
	SHARED_KEY	= 2,
	ANY		= 3,
};

#endif /* _802_11_H_ */
