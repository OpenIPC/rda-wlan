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
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_trap.h"
#include "wland_p2p.h"
#include "wland_cfg80211.h"
#include "wland_usb.h"

int wland_proto_hdrpush(struct wland_private *drvr, s32 ifidx,
			struct sk_buff *pktbuf)
{
	return 0;
}

int wland_proto_hdrpull(struct wland_private *drvr, s32 *ifidx,
			struct sk_buff *pktbuf)
{
	if (pktbuf->len == 0)
		return -ENODATA;

	return 0;
}

/* Initial WID batch sent after the firmware is running. */
int wland_preinit_cmds_91h(struct wland_if *ifp)
{
	s32 ret;
	u32 mem_addr = 0xffffffff;
	u8 val;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u8 mode = ifp->vif->profile.mode;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &mem_addr,
			     sizeof(mem_addr), false);
	if (ret < 0)
		goto done;
	buf += ret;

	ret = wland_push_wid(buf, WID_MAC_ADDR, ifp->mac_addr, ETH_ALEN, false);
	if (ret < 0)
		goto done;
	buf += ret;

	if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0) {
		val = WLAND_TID_NUM;
		ret = wland_push_wid(buf, WID_SET_TID, &val, sizeof(val),
				     false);
		if (ret < 0)
			goto done;
		buf += ret;
	}

	val = 1;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &val, sizeof(val), false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_11N_IMMEDIATE_BA_ENABLED, &val,
			     sizeof(val), false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = WIFI_LISTEN_INTERVAL;
	ret = wland_push_wid(buf, WID_LISTEN_INTERVAL, &val, sizeof(val),
			     false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = WIFI_LINK_LOSS_THRESHOLD_91H;
	ret = wland_push_wid(buf, WID_LINK_LOSS_THRESHOLD, &val, sizeof(val),
			     false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_11N_SHORT_GI_ENABLE, &val, sizeof(val),
			     false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_RIFS_MODE, &val, sizeof(val), false);
	if (ret < 0)
		goto done;
	buf += ret;

	if (mode == WLAND_B_MODE) {
		val = B_ONLY_MODE;
		ret = wland_push_wid(buf, WID_11G_OPERATING_MODE, &val,
				     sizeof(val), false);
		if (ret < 0)
			goto done;
		buf += ret;
	}

	val = 1;
	ret = wland_push_wid(buf, WID_2040_ENABLE, &val, sizeof(val), false);
	if (ret < 0)
		goto done;
	buf += ret;

	val = 15;
	ret = wland_push_wid(buf, WID_WDT_TIMEOUT, &val, sizeof(val), false);
	if (ret < 0)
		goto done;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
done:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

int wland_stop_chip(struct net_device *ndev)
{
	int err = -ENODEV;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr;
	u8 val = 0;

	if (!ifp)
		return -ENODEV;

	drvr = ifp->drvr;

	if (!drvr->bus_if->chip_ready)
		return 0;

	err = wland_fil_set_cmd_data_without_rsp(ifp, WID_WDT_TIMEOUT, &val, 1);
	if (err < 0)
		netdev_err(ndev, "failed to reset firmware: %d\n", err);
	else
		drvr->bus_if->chip_ready = 0;

	return err;
}

int wland_start_chip(struct net_device *ndev)
{
	int err = -ENODEV;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr;
	u32 memory_address = 0;
	char firmware_version[20];

	if (!ifp)
		return -ENODEV;

	drvr = ifp->drvr;

	if (drvr->bus_if->chip_ready)
		return 0;

	err = wland_bus_active(drvr->bus_if);
	if (err < 0) {
		netdev_err(ndev, "failed to activate bus: %d\n", err);
		goto fail;
	}

	if (strncasecmp(rdawlan_firmware_path, "rf", strlen("rf")) == 0) {
		netdev_info(ndev, "RF test mode enabled\n");
		wland_set_test_mode(1);
	} else {
		wland_set_test_mode(0);
	}

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		err = wland_fil_get_cmd_data(ifp, WID_MEMORY_ADDRESS,
					     &memory_address, 4);
		if (err < 0) {
			netdev_err(ndev, "failed to get firmware state: %d\n", err);
			goto fail;
		} else if (memory_address == 0xffffffff) {
			netdev_info(ndev, "firmware already running, skipping download\n");
			goto preinit;
		}

		err = wland_download_codefile(ifp);
		if (err < 0) {
			netdev_err(ndev, "failed to download firmware: %d\n", err);
			goto fail;
		}

		err = wland_download_datafile(ifp);
		if (err < 0) {
			netdev_err(ndev, "failed to download data file: %d\n", err);
			goto fail;
		}

		err = wland_run_firmware(ifp, RDA5991H_CODE_ADDR);
		if (err < 0) {
			netdev_err(ndev, "failed to run firmware: %d\n", err);
			goto fail;
		}
preinit:
		if (wland_check_test_mode() == 0) {
			if (drvr->bus_if->up_data_mac) {
				err = wland_cfg80211_updata_mac(drvr->config);
				if (err < 0)
					netdev_warn(ndev,
						    "factory MAC unavailable (%d); using temporary address, provision WifiMac or /etc/WLANMAC\n",
						    err);
			}

			if (strcasecmp(rdawlan_firmware_path, "ap") != 0) {
				/* The first WID write must be the preinit batch. */
				err = wland_preinit_cmds_91h(ifp);
				if (err < 0) {
					netdev_err(ndev, "failed to send preinit commands: %d\n", err);
					goto fail;
				}

				err = wland_set_scan_timeout(ifp);
				if (err < 0) {
					netdev_err(ndev, "failed to set scan timeout: %d\n", err);
					goto fail;
				}
			}
		}

		if (strcasecmp(rdawlan_firmware_path, "ap") != 0)
			wland_config_and_efuse(ifp);
	}

	drvr->bus_if->chip_ready = 1;

	err = wland_fil_get_cmd_data(ifp, WID_CHIP_VERSION,
				     &drvr->bus_if->chip_version, 1);
	if (err < 0) {
		netdev_warn(ndev,
			    "failed to get chip version (%d), defaulting to u04\n",
			    err);
		drvr->bus_if->chip_version = 4;
		err = 0;
	} else {
		netdev_info(ndev, "chip version: u%02d\n",
			    drvr->bus_if->chip_version);
	}

	memset(firmware_version, 0, sizeof(firmware_version));
	err = wland_fil_get_cmd_data(ifp, WID_FIRMWARE_VERSION,
				     firmware_version, 20);
	if (err < 0) {
		netdev_warn(ndev, "failed to get firmware version: %d\n", err);
		err = 0;
	} else {
		firmware_version[19] = '\0';
		netdev_info(ndev, "firmware version: %s\n", firmware_version);
	}

fail:
	return err >= 0 ? 0 : err;
}
