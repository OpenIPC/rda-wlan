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

#ifndef _WLAND_RF_H_
#define _WLAND_RF_H_

#include <linux/netdevice.h>
#include <linux/types.h>

#define WLAND_TXP_NUM			2

#define WLAND_TXP_11F_BASE		0x25	/* n_mode */
#define WLAND_TXP_11F_END		0x64	/* n_mode */
#define WLAND_TXP_120_BASE		0x15
#define WLAND_TXP_120_END		0x54

int wland_read_txpower_from_efuse(struct net_device *net, char *data, int len,
				  u8 *tx_power);
int wland_read_efuse_xtal_cal_val(struct net_device *net, char *data, int len,
				  u8 *cal_val);
int wland_set_hardware_param(struct net_device *net, char *data, int len,
			     int func_num, u16 value_set);
int wland_efuse_get_mac_addr(struct net_device *net, char *data, int len,
			     u8 *mac_from_efuse);

#endif /* _WLAND_RF_H_ */
