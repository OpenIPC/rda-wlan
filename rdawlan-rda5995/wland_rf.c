// SPDX-License-Identifier: ISC
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/types.h>
#include <asm/unaligned.h>

#include "wland_defs.h"
#include "wland_dev.h"
#include "wland_wid.h"
#include "wland_rf.h"

static bool wland_is_old_efuse(const u8 *value)
{
	if (!value)
		return false;

	return value[16] == 0x4e && value[17] == 0x46;
}

static int wland_read_efuse(struct wland_if *ifp, u8 *value)
{
	struct device *dev = ifp->drvr->bus_if->dev;
	int ret;

	ret = wland_fil_get_cmd_data(ifp, WID_GET_EFUSE_ALL_PAGE, value, 28);
	if (ret < 0) {
		dev_err(dev, "failed to read eFuse: %d\n", ret);
		return ret;
	}
	if (ret != 28) {
		dev_err(dev, "short eFuse response: %d bytes (expected 28)\n",
			ret);
		return -EPROTO;
	}

	return 0;
}

static bool wland_buf_equals(const u8 *data, u8 len, u8 comp)
{
	int i;

	for (i = 0; i < len; i++) {
		if (data[i] != comp)
			return false;
	}

	return true;
}

int wland_read_efuse_xtal_cal_val(struct net_device *net,
				  char *data, int len, u8 *cal_val)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};
	int i;

	if (!cal_val)
		return -EINVAL;
	*cal_val = 0;
	ret = wland_read_efuse(ifp, efuse_value);
	if (ret)
		return ret;

	/* Raw trim bytes sit at the end of the eFuse dump; the newest non-zero
	 * entry wins. The old layout reserves bytes 16/17 for a format marker.
	 */
	for (i = 19; i >= (wland_is_old_efuse(efuse_value) ? 18 : 16); i--) {
		if (efuse_value[i]) {
			*cal_val = efuse_value[i];
			break;
		}
	}
	if (!*cal_val)
		return -ENODATA;
	if (data)
		ret = snprintf(data, len,
			       "frequency offset calibration value:0x%02x\n",
			       *cal_val);

	return ret;
}

int wland_efuse_get_mac_addr(struct net_device *net,
			     char *data, int len, u8 *mac_from_efuse)
{
	int ret = 0;
	u8 mac[ETH_ALEN];
	u8 mac_efuse[2 * ETH_ALEN];
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(mac_efuse, &efuse_value[4], 2 * ETH_ALEN);

	if (wland_is_old_efuse(efuse_value)) {
		mac[0] = mac_efuse[1];
		mac[1] = mac_efuse[0];
		mac[2] = mac_efuse[3];
		mac[3] = mac_efuse[2];
		mac[4] = mac_efuse[5];
		mac[5] = mac_efuse[4];
	} else {
		if (wland_buf_equals(&mac_efuse[6], ETH_ALEN, 0) ||
		    wland_buf_equals(&mac_efuse[6], ETH_ALEN, 0xFF))
			memcpy(mac, mac_efuse, ETH_ALEN);
		else
			memcpy(mac, &mac_efuse[6], ETH_ALEN);
	}
	if (data)
		ret = snprintf(data, len,
			       "mac addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
			       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	memcpy(mac_from_efuse, mac, ETH_ALEN);
	return ret;
}

int wland_set_hardware_param(struct net_device *net,
			     char *data, int len, int func_num, u16 value_set)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct device *dev = drvr->bus_if->dev;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u16 function = 0, value = 0;
	u8 send[4] = {0};
	u8 phy_reg = 0;

	if (data && len > 0) {
		char *c = data;

		while (*c && !isspace(*c))
			c++;
		c = skip_spaces(c);
		ret = kstrtou16(c, 10, &function);
		if (ret)
			return ret;
		while (*c && !isspace(*c))
			c++;
		c = skip_spaces(c);
		ret = kstrtou16(c, 16, &value);
		if (ret)
			return ret;
	} else {
		function = func_num;
		value = value_set;
	}

	if (function > 2) {
		dev_err(dev, "invalid RF function: %u\n", function);
		return -EINVAL;
	}

	if (value == 0) {
		dev_err(dev, "invalid RF parameter value 0\n");
		return -EINVAL;
	} else if (function == 0 && value >= 0xFF) {
		dev_err(dev, "invalid xtal value: 0x%x\n", value);
		return -EINVAL;
	} else if (function == 1) {
		int offset = drvr->power_g_n_offset;

		if (drvr->current_mode == WLAND_N_MODE &&
		    (value < WLAND_TXP_11F_BASE || value > WLAND_TXP_11F_END)) {
			dev_err(dev,
				"invalid 11n TX power 0x%02x (valid 0x%02x..0x%02x)\n",
				value, WLAND_TXP_11F_BASE, WLAND_TXP_11F_END);
			return -EINVAL;
		} else if (drvr->current_mode == WLAND_G_MODE &&
			   (value < (WLAND_TXP_11F_BASE + offset) ||
			    value > (WLAND_TXP_11F_END + offset))) {
			dev_err(dev,
				"invalid 11g TX power 0x%02x (valid 0x%02x..0x%02x)\n",
				value,
				WLAND_TXP_11F_BASE + offset,
				WLAND_TXP_11F_END + offset);
			return -EINVAL;
		} else if (drvr->current_mode == WLAND_B_MODE) {
			dev_err(dev, "cannot set 11f TX power in 11b mode\n");
			return -EINVAL;
		}
	} else if (function == 2 &&
		   (value < WLAND_TXP_120_BASE || value > WLAND_TXP_120_END)) {
		dev_err(dev, "invalid 11b TX power: 0x%02x\n", value);
		return -EINVAL;
	}

	if (function == 0) {
		value = (((value & 0xFE) << 8) | 0x00CF);
		put_unaligned_le16(value, &send[0]);
		put_unaligned_le16(0x10DA, &send[2]);

		return wland_fil_set_cmd_data(ifp, WID_PHY_RF_REG_VAL, send, 4);
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	phy_reg = 0xFF;
	ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
	if (ret < 0)
		goto phy_done;
	buf += ret;

	memset(send, 0, 4);
	send[0] = 0x01;
	ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
	if (ret < 0)
		goto phy_done;
	buf += ret;

	if (function == 1)
		phy_reg = 0x1F;
	else if (function == 2)
		phy_reg = 0x20;
	ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
	if (ret < 0)
		goto phy_done;
	buf += ret;

	memset(send, 0, 4);
	put_unaligned_le16(value, &send[0]);
	ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
	if (ret < 0)
		goto phy_done;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);

phy_done:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

int wland_read_txpower_from_efuse(struct net_device *net,
				  char *data, int len, u8 *tx_power)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 value[WLAND_TXP_NUM] = {0};
	u8 efuse_value[28] = {0};
	u8 tx_power_efuse[8] = {0};
	int i = 0;
	u16 efuse_comp = 0;
	bool find = false;

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 8);

	for (i = 3; i >= 0; i--) {
		efuse_comp = (MAKE_WORD16(tx_power_efuse[2 * i],
					  tx_power_efuse[2 * i + 1])) & 0xFFF;
		if (efuse_comp != 0) {
			find = true;
			break;
		}
	}

	if (!find)
		return -1;

	value[0] = (efuse_comp & 0x003F) + WLAND_TXP_11F_BASE;
	value[1] = ((efuse_comp & 0x0FC0) >> 6) + WLAND_TXP_120_BASE;

	if ((value[0] < WLAND_TXP_11F_BASE || value[0] > WLAND_TXP_11F_END) ||
	    (value[1] < WLAND_TXP_120_BASE || value[1] > WLAND_TXP_120_END)) {
		dev_err(ifp->drvr->bus_if->dev,
			"invalid TX power in eFuse: 0x%02x, 0x%02x\n",
			value[0], value[1]);
		return -1;
	}

	if (data)
		ret = snprintf(data, len, "tx power value: 0x%02x,0x%02x\n",
			       value[0], value[1]);

	memcpy(tx_power, value, WLAND_TXP_NUM);

	return ret;
}
