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
#include <linux/slab.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <linux/firmware.h>

#include "wland_defs.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_utils.h"
#include "wland_wid.h"
#include "wland_trap.h"

s32 wland_set_phy_timeout(struct wland_private *priv,
			  u32 cipher_pairwise, u32 cipher_group)
{
	return 0;
}

s32 wland_run_firmware(struct wland_if *ifp, u32 addr)
{
	struct wland_private *drvr = ifp->drvr;
	struct device *dev = drvr->bus_if->dev;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 result = 0;

	/* Make sure the bootrom is in the expected state. */
	ret = wland_fil_get_cmd_data(ifp, WID_BOOTROM_START_APP, &result, 1);
	if (ret != sizeof(result)) {
		dev_err(dev, "failed to query firmware state: %d\n", ret);
		return ret < 0 ? ret : -EPROTO;
	}
	if (result != 1)
		dev_warn(dev, "unexpected bootrom state: %u\n", result);

	mutex_lock(&drvr->proto_block);
	prot->reqid = 0;
	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr,
			     sizeof(addr), false);
	if (ret < 0)
		goto out;
	buf += ret;

	result = 1;
	ret = wland_push_wid(buf, WID_BOOTROM_START_APP, &result,
			     sizeof(u8), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

static s32 wland_bootrom_send_bulk(struct wland_if *ifp,
				   u32 addr, const void *buffer, u32 buflen)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;

	mutex_lock(&drvr->proto_block);

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr,
			     sizeof(addr), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_LENGTH, &buflen,
			     sizeof(u32), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_ACCESS, buffer, buflen, false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

static s32 wland_write_firmware(const struct firmware *fw_entry,
				struct wland_if *ifp, u32 addr)
{
	s32 err = 0;
	u32 sent = 0, dllen = fw_entry->size;
	u32 sendlen;
	const void *dlpos = fw_entry->data;
	u16 bulkchunk = 1518 - 25;

	bulkchunk -= bulkchunk % 4;

	while (sent != dllen) {
		sendlen = min_t(u32, dllen - sent, bulkchunk);

		err = wland_bootrom_send_bulk(ifp, addr, dlpos, sendlen);
		if (err < 0)
			break;

		addr += sendlen;
		dlpos += sendlen;
		sent += sendlen;
	}

	return err;
}

/* Decrypt the complete image after all chunks have been acknowledged. */
static s32 wland_bootrom_decrypt_image(struct wland_if *ifp, u32 addr, u32 len)
{
	struct wland_private *drvr = ifp->drvr;
	struct device *dev = drvr->bus_if->dev;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u8 decrypt = 1;
	s32 ret;

	mutex_lock(&drvr->proto_block);
	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, sizeof(addr),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_LENGTH, &len, sizeof(len), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_BOOTROM_DECRYPT, &decrypt,
			     sizeof(decrypt), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	if (ret < 0)
		dev_err(dev, "failed to decrypt firmware image at 0x%08x: %d\n",
			addr, ret);
	mutex_unlock(&drvr->proto_block);
	return ret;
}

static s32 wland_download_image(struct wland_if *ifp, const char *filename,
				u32 addr)
{
	struct wland_private *drvr = ifp->drvr;
	const struct firmware *fw_entry;
	s32 ret;

	ret = request_firmware(&fw_entry, filename, drvr->bus_if->dev);
	if (ret) {
		dev_err(drvr->bus_if->dev,
			"failed to request firmware %s: %d\n",
			filename, ret);
		return ret;
	}

	dev_info(drvr->bus_if->dev, "loading %s (%zu bytes) at 0x%08x\n",
		 filename, fw_entry->size, addr);
	ret = wland_write_firmware(fw_entry, ifp, addr);
	if (ret < 0)
		dev_err(drvr->bus_if->dev, "failed to write firmware %s: %d\n",
			filename, ret);
	else
		ret = wland_bootrom_decrypt_image(ifp, addr,
						  (u32)fw_entry->size);

	release_firmware(fw_entry);
	return ret;
}

s32 wland_download_codefile(struct wland_if *ifp)
{
	const char *filename = RDA5991H_USB_CODE_P2P;
	struct wland_private *drvr = ifp->drvr;

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		/*
		 * STA firmware has three code regions despite the "p2p" file
		 * name suffix: code@100000, code1@180000, code2@190000.
		 */
		if (!strcasecmp(rdawlan_firmware_path, "sta")) {
			s32 ret;

			ret = wland_download_image(ifp, RDA5991H_USB_CODE_P2P,
						   RDA5991H_CODE_ADDR);
			if (ret < 0)
				return ret;
			ret = wland_download_image(ifp, RDA5995_USB_STA_CODE1,
						   RDA5995_USB_STA_CODE1_ADDR);
			if (ret < 0)
				return ret;
			return wland_download_image(ifp, RDA5995_USB_STA_CODE2,
						    RDA5995_USB_STA_CODE2_ADDR);
		} else if (!strcasecmp(rdawlan_firmware_path, "ap")) {
			filename = RDA5991H_USB_CODE_AP;
		} else if (!strcasecmp(rdawlan_firmware_path, "rf")) {
			filename = RDA5991H_USB_CODE_RF;
		}
	}

	return wland_download_image(ifp, filename, RDA5991H_CODE_ADDR);
}

s32 wland_download_datafile(struct wland_if *ifp)
{
	const char *filename = RDA5991H_USB_DATA_P2P;
	struct wland_private *drvr = ifp->drvr;

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		if (!strcasecmp(rdawlan_firmware_path, "sta"))
			return wland_download_image(ifp, RDA5991H_USB_DATA_P2P,
						    RDA5995_USB_STA_DATA_ADDR);
		else if (!strcasecmp(rdawlan_firmware_path, "ap"))
			filename = RDA5991H_USB_DATA_AP;
		else if (!strcasecmp(rdawlan_firmware_path, "rf"))
			filename = RDA5991H_USB_DATA_RF;
	}

	return wland_download_image(ifp, filename, RDA5991H_DATA_ADDR_STA_AP);
}

