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
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/firmware.h>
#include <asm/unaligned.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_p2p.h"
#include "wland_cfg80211.h"
#include "wland_usb.h"
#include "wland_rf.h"

/* retries to retrieve matching dcmd response */
#define RETRIES                             2

static inline void put_le16(u8 *p, u16 v)
{
	put_unaligned_le16(v, p);
}

static inline u16 get_le16(const u8 *p)
{
	return get_unaligned_le16(p);
}

static inline void put_le32(u8 *p, u32 v)
{
	put_unaligned_le32(v, p);
}

/*
 * Encode one WID into @buf and return the encoded length, or -1.
 * @data_len is 1, 2 or 4 for char/short/int WIDs and n for string or
 * binary WIDs. A query carries no data, so @data may then be NULL.
 */
s32 wland_push_wid(u8 *buf, u16 WID, const void *data, u16 data_len,
		   bool is_query)
{
	u8 *offset = buf;
	enum wid_type type = wland_get_wid_type(WID);
	u16 wid_length = wland_get_wid_size(type, data_len);
	u8 checksum = 0;

	if (!buf || (!is_query && !data)) {
		pr_err("NULL buffer or data for WID 0x%04x\n", WID);
		return -1;
	}

	if (!is_query && wid_length != data_len) {
		pr_err("WID 0x%04x (type %d) length mismatch: expected %u, got %u\n",
		       WID, type, wid_length, data_len);
		return -1;
	}

	put_le16(buf, WID);
	buf += 2;

	if (is_query)
		return buf - offset;

	switch (type) {
	case WID_CHAR:
		*buf = (u8)wid_length;
		*(buf + 1) = *(u8 *)data;
		buf += 2;
		break;
	case WID_SHORT:
		*buf = (u8)wid_length;
		put_le16(buf + 1, *(u16 *)data);
		buf += 3;
		break;
	case WID_INT:
		*buf = (u8)wid_length;
		put_le32(buf + 1, *(u32 *)data);
		buf += 5;
		break;
	case WID_STR:
		*buf = (u8)wid_length;
		memcpy(buf + 1, data, wid_length);
		buf += (1 + wid_length);
		break;
	case WID_BIN:
		put_le16(buf, wid_length);
		memcpy(buf + 2, data, wid_length);
		while (data_len--)
			checksum += *(buf + 2 + data_len);
		*(buf + 2 + wid_length) = checksum;
		buf += (2 + 1 + wid_length);
		break;
	case WID_UNKNOW:
	default:
		pr_err("unknown WID 0x%04x\n", WID);
		return -1;
	}

	return buf - offset;
}

/*
 * Decode one WID from @buf into @WID, @data and @data_len (all non-NULL)
 * and return the decoded length, or a negative value on error.
 */
s32 wland_pull_wid(const u8 *buf, u16 buf_len, u16 *WID, const u8 **data,
		   u16 *data_len)
{
	const u8 *offset = buf;
	enum wid_type type;
	u16 wid_length;
	u8 checksum = 0;

	if (!buf || !WID || !data || !data_len) {
		pr_err("invalid WID pull arguments\n");
		return -1;
	}
	*WID = 0;
	*data_len = 0;
	*data = NULL;

	*WID = get_le16(buf);
	buf += 2;
	type = wland_get_wid_type(*WID);

	if (buf > offset + buf_len) {
		pr_err("WID buffer overrun\n");
		return (offset + buf_len) - buf;
	} else if (buf == offset + buf_len) {
		return buf_len;
	}

	switch (type) {
	case WID_CHAR:
		wid_length = (u16)(*buf);
		if (wid_length != 1) {
			pr_err("WID 0x%04x invalid length %u\n",
			       *WID, wid_length);
			return -1;
		}
		*data_len = wid_length;
		*data = buf + 1;
		buf += 2;
		break;
	case WID_SHORT:
		wid_length = (u16)(*buf);
		if (wid_length != 1) {
			pr_err("WID 0x%04x invalid length %u\n",
			       *WID, wid_length);
			return -1;
		}
		*data_len = wid_length;
		*data = buf + 1;
		buf += 3;
		break;
	case WID_INT:
		wid_length = (u16)(*buf);
		*data_len = wid_length;
		if (wid_length != 4) {
			pr_err("WID 0x%04x invalid length %u\n",
			       *WID, wid_length);
			return -1;
		}
		*data = buf + 1;
		buf += 5;
		break;
	case WID_STR:
		wid_length = (u16)(*buf);
		*data_len = wid_length;
		*data = buf + 1;
		buf += (1 + wid_length);
		break;
	case WID_BIN:
		wid_length = get_le16(buf) & 0x3fff;
		*data_len = wid_length;
		*data = buf + 2;
		if (buf - offset + 2 + 1 + wid_length > buf_len) {
			pr_err("WID 0x%04x buffer overrun\n", *WID);
			return buf_len - (buf - offset + 2 + 1 + wid_length);
		}

		while (wid_length--)
			checksum += *(buf + 2 + wid_length);
		wid_length = *data_len;
		if (*(buf + 2 + wid_length) != checksum) {
			pr_err("WID 0x%04x checksum mismatch (fw 0x%02x, calc 0x%02x)\n",
			       *WID, *(buf + 2 + wid_length), checksum);
			return -1;
		}
		buf += (2 + 1 + wid_length);
		break;
	case WID_UNKNOW:
	default:
		return -1;
	}

	if (buf > offset + buf_len) {
		pr_err("WID 0x%04x buffer overrun\n", *WID);
		return (offset + buf_len) - buf;
	}

	return buf - offset;
}

/* Build a single-WID request; used by wland_fil_{set,get}_cmd_data(). */
static int wland_wid_hdrpush(struct wland_private *drvr, u16 wid, bool rw,
			     const u8 *val, u16 val_len)
{
	enum wid_type type = wland_get_wid_type(wid);
	u16 size = wland_get_wid_size(type, val_len);
	u16 wid_msg_len = FMW_HEADER_LEN, wid_pkt_len = 0;
	struct wland_proto *prot = drvr->prot;
	u8 *wid_msg = prot->buf;

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		dev_err(drvr->bus_if->dev, "bus is down\n");
		return -EINVAL;
	}

	/* Only binary WIDs have a 16-bit length; all must fit the buffer. */
	if (rw && ((type != WID_BIN && size > U8_MAX) ||
		   size + 5 > WLAND_DCMD_MEDLEN)) {
		dev_err(drvr->bus_if->dev, "WID 0x%04x: %u bytes do not fit\n",
			wid, size);
		return -EINVAL;
	}

	prot->cmd = wid;
	prot->offset = 0;
	prot->rsplen = 0;

	prot->msg.wid_msg_id = wland_get_seqidx(drvr);

	if (rw) {
		prot->msg.wid_msg_type = WLAND_WID_MSG_WRITE;

		wid_msg[0] = (u8)wid;
		wid_msg[1] = (u8)(wid >> 8);
		if (type == WID_BIN) {
			wid_msg[2] = size & 0xff;
			wid_msg[3] = (size & 0xff00) >> 8;
			memcpy(&wid_msg[4], val, size);
			wid_msg_len += (size + 4);
			wid_msg += (size + 4);
			wid_msg_len += 1;
		} else {
			wid_msg[2] = (u8)size;
			memcpy(&wid_msg[3], val, size);
			wid_msg_len += (size + 3);
			wid_msg += (size + 3);
		}
	} else {
		prot->msg.wid_msg_type = WLAND_WID_MSG_QUERY;

		wid_msg[0] = (u8)wid;
		wid_msg[1] = (u8)(wid >> 8);
		wid_msg_len += 2;
		wid_msg += 2;
	}

	wid_pkt_len = wid_msg_len + WID_HEADER_LEN;

	prot->msg.wid_msg_length = cpu_to_le16(wid_msg_len);
	prot->msg.wid_pkg_length =
		cpu_to_le16((wid_pkt_len & CDC_DCMD_LEN_MASK) |
		(PKT_TYPE_CFG_REQ << CDC_DCMD_LEN_SHIFT));

	return wid_msg_len - FMW_HEADER_LEN;
}

static int wland_wid_hdrpull(struct wland_private *drvr, u16 val_len, bool query)
{
	struct wland_proto *prot = drvr->prot;
	u8 *wid = prot->buf;
	u16 packet_len, message_len, available, rsp, payload_len, offset;
	enum wid_type type;

	if (drvr->bus_if->state != WLAND_BUS_DATA)
		return -EINVAL;

	prot->rsplen = 0;
	prot->offset = 0;
	if (val_len < sizeof(prot->msg) + 3)
		return -EPROTO;
	packet_len = le16_to_cpu(prot->msg.wid_pkg_length);
	if ((packet_len >> CDC_DCMD_LEN_SHIFT) != PKT_TYPE_CFG_RSP ||
	    prot->msg.wid_msg_type != WLAND_WID_MSG_RESP)
		return -EPROTO;
	packet_len &= CDC_DCMD_LEN_MASK;
	message_len = le16_to_cpu(prot->msg.wid_msg_length);
	/* USB may pad the transfer. Parse only the declared message inside it. */
	if (packet_len > val_len || packet_len < sizeof(prot->msg) + 3 ||
	    message_len < FMW_HEADER_LEN + 3 ||
	    message_len > packet_len - WID_HEADER_LEN)
		return -EPROTO;
	available = message_len - FMW_HEADER_LEN;
	rsp = get_le16(wid);
	if (rsp == WID_STATUS) {
		if (available < 4 || wid[2] != 1)
			return -EPROTO;
		if (wid[3] != STATUS_SUCCESS)
			return -EINVAL;
		/* A successful write acknowledgement is not query data. */
		return query ? -EPROTO : 0;
	}
	/* Multi-WID writes do not set prot->cmd. Match only single-WID GETs. */
	if (query && rsp != prot->cmd) {
		dev_err(drvr->bus_if->dev,
			"query response WID 0x%04x does not match 0x%04x\n",
			rsp, prot->cmd);
		return -EPROTO;
	}
	type = wland_get_wid_type(rsp);
	if (type == WID_UNKNOW)
		return -EPROTO;
	if (type == WID_BIN) {
		if (available < 4)
			return -EPROTO;
		offset = 4;
		payload_len = get_le16(wid + 2) & 0x3fff;
	} else {
		offset = 3;
		payload_len = wid[2];
		if ((type == WID_CHAR && payload_len != 1) ||
		    (type == WID_SHORT && payload_len != 2) ||
		    (type == WID_INT && payload_len != 4))
			return -EPROTO;
	}
	if (payload_len > available - offset)
		return -EPROTO;
	prot->offset = offset;
	prot->rsplen = payload_len;
	return 0;
}

static int wland_proto_cdc_msg(struct wland_private *drvr)
{
	struct wland_proto *prot = drvr->prot;
	uint len = le16_to_cpu(prot->msg.wid_pkg_length) & CDC_DCMD_LEN_MASK;
	struct wland_bus *bus = drvr->bus_if;
	u8 *payload = (u8 *)&prot->msg;

	/* Only up to CDC_MAX_MSG_SIZE bytes are sent to the dongle. */
	if (len > CDC_MAX_MSG_SIZE) {
		dev_warn(bus->dev, "clamping message length %u to %u\n",
			 len, CDC_MAX_MSG_SIZE);
		len = CDC_MAX_MSG_SIZE;
	}

	return wland_bus_txctl(bus, payload, len);
}

static int wland_proto_cdc_cmplt(struct wland_private *drvr, u8 id, u16 len)
{
	int ret;
	unsigned int mismatches = 0;
	unsigned long deadline = jiffies + msecs_to_jiffies(IOCTL_RESP_TIMEOUT);
	struct wland_proto *prot = drvr->prot;

	do {
		ret = wland_bus_rxctl(drvr->bus_if, (u8 *)&prot->msg, len);
		if (ret < 0)
			break;
		if (ret < WID_HEADER_LEN + 4 ||
		    (prot->msg.wid_msg_id != id &&
		     (++mismatches >= 16 ||
		      time_after_eq(jiffies, deadline)))) {
			ret = -EPROTO;
			wland_usb_request_recovery(drvr->bus_if->dev);
			break;
		}
	} while (prot->msg.wid_msg_id != id);

	return ret;
}

/* Send a prepared WID write request; @wid_msg_len includes the header. */
int wland_proto_cdc_data(struct wland_private *drvr, u16 wid_msg_len)
{
	struct wland_proto *prot = drvr->prot;
	struct device *dev = drvr->bus_if->dev;
	int err, retries = 0;
	u16 wid_pkg_len = 0;
	u8 wid_msg_id = wland_get_seqidx(drvr);

	if (drvr->bus_if->state != WLAND_BUS_DATA)
		return -EINVAL;

	prot->msg.wid_msg_type = WLAND_WID_MSG_WRITE;
	prot->msg.wid_msg_id = wid_msg_id;

	wid_pkg_len = wid_msg_len + WID_HEADER_LEN;
	prot->msg.wid_msg_length = cpu_to_le16(wid_msg_len);
	prot->msg.wid_pkg_length =
		cpu_to_le16((wid_pkg_len & CDC_DCMD_LEN_MASK) |
		(PKT_TYPE_CFG_REQ << CDC_DCMD_LEN_SHIFT));

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		dev_err(dev, "failed to send WID write request: %d\n", err);
		goto done;
	}

retry:
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		dev_err(dev, "failed to complete WID write request: %d\n", err);
		goto done;
	}

	if (prot->msg.wid_msg_id < wid_msg_id && ++retries < RETRIES)
		goto retry;

	if (prot->msg.wid_msg_id != wid_msg_id) {
		dev_err(dev, "unexpected response id %u (expected %u)\n",
			prot->msg.wid_msg_id, wid_msg_id);
		err = -EINVAL;
	}

	if (err > 0)
		err = wland_wid_hdrpull(drvr, (u16)err, false);

done:
	return err;
}

/* Write a single WID without waiting for the response. */
int wland_fil_set_cmd_data_without_rsp(struct wland_if *ifp,
				       u16 cmd, const void *data, u16 len)
{
	int err;
	struct wland_private *drvr = ifp ? ifp->drvr : NULL;
	struct wland_proto *prot = drvr ? drvr->prot : NULL;

	if (!drvr || !prot)
		return -EIO;

	if (drvr->bus_if->state != WLAND_BUS_DATA)
		return -EIO;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	err = wland_wid_hdrpush(drvr, cmd, true, data, len);
	if (err < 0)
		goto done;

	err = wland_proto_cdc_msg(drvr);
	if (err < 0)
		dev_err(drvr->bus_if->dev, "failed to send WID 0x%04x: %d\n",
			cmd, err);

done:
	mutex_unlock(&drvr->proto_block);

	return (err >= 0) ? 0 : err;
}

/* Write a single WID and wait for the response. */
int wland_fil_set_cmd_data(struct wland_if *ifp, u16 cmd, const void *data,
			   u16 len)
{
	int err, retries = 0;
	u8 wid_msg_id = 0;
	struct wland_private *drvr = ifp ? ifp->drvr : NULL;
	struct wland_proto *prot = drvr ? drvr->prot : NULL;
	struct device *dev;

	if (!drvr || !prot)
		return -EIO;

	dev = drvr->bus_if->dev;
	if (drvr->bus_if->state != WLAND_BUS_DATA)
		return -EIO;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	err = wland_wid_hdrpush(drvr, cmd, true, data, len);
	if (err < 0)
		goto done;

	wid_msg_id = prot->msg.wid_msg_id;

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		dev_err(dev, "failed to send WID 0x%04x write: %d\n", cmd, err);
		goto done;
	}

retry:
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		dev_err(dev, "failed to complete WID 0x%04x write: %d\n",
			cmd, err);
		goto done;
	}

	if (prot->msg.wid_msg_id < wid_msg_id && ++retries < RETRIES) {
		dev_dbg(dev,
			"WID 0x%04x response id mismatch (sent %u, got %u), retrying\n",
			cmd, wid_msg_id, prot->msg.wid_msg_id);
		goto retry;
	}

	if (prot->msg.wid_msg_id != wid_msg_id) {
		dev_err(dev,
			"WID 0x%04x unexpected response id %u (expected %u)\n",
			cmd, prot->msg.wid_msg_id, wid_msg_id);
		err = -EINVAL;
	}

	if (err >= 0)
		err = wland_wid_hdrpull(drvr, (u16)err, false);

done:
	mutex_unlock(&drvr->proto_block);

	return (err >= 0) ? 0 : err;
}

/* Query a single WID. */
int wland_fil_get_cmd_data(struct wland_if *ifp, u16 cmd, void *data, u16 len)
{
	struct wland_private *drvr = ifp ? ifp->drvr : NULL;
	struct wland_proto *prot = drvr ? drvr->prot : NULL;
	struct device *dev;
	int err = 0, retries = 0;
	u8 wid_msg_id = 0;

	if (!drvr || !prot || !data)
		return -EIO;

	dev = drvr->bus_if->dev;
	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		dev_err(dev, "bus is down\n");
		return -EIO;
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));
	err = wland_wid_hdrpush(drvr, cmd, false, data, len);
	if (err < 0)
		goto done;

	wid_msg_id = prot->msg.wid_msg_id;

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		dev_err(dev, "failed to send WID 0x%04x query: %d\n", cmd, err);
		goto done;
	}

retry:
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		dev_err(dev, "failed to complete WID 0x%04x query: %d\n",
			cmd, err);
		goto done;
	}

	if (prot->msg.wid_msg_id < wid_msg_id && ++retries < RETRIES)
		goto retry;

	if (prot->msg.wid_msg_id != wid_msg_id) {
		dev_err(dev,
			"%s: WID 0x%04x unexpected response id %u (expected %u)\n",
			wland_ifname(drvr, ifp->ifidx), cmd,
			prot->msg.wid_msg_id, wid_msg_id);
		err = -EINVAL;
		goto done;
	}

	if (err > 0)
		err = wland_wid_hdrpull(drvr, (u16)err, true);

	if (err >= 0) {
		len = (prot->rsplen > len) ? len : prot->rsplen;
		memcpy(data, &prot->buf[prot->offset], len);
	}
done:
	mutex_unlock(&drvr->proto_block);

	return (err >= 0) ? len : err;
}

s32 wland_fil_iovar_data_set(struct wland_if *ifp, char *name, void *data,
			     u16 len)
{
	return 0;
}

s32 wland_fil_iovar_data_get(struct wland_if *ifp, char *name, void *data,
			     u16 len)
{
	return 0;
}

static s32 wland_set_power_defaults(struct wland_if *ifp);

void wland_config_and_efuse(struct wland_if *ifp)
{
	int err;

	err = wland_set_power_defaults(ifp);
	if (err < 0)
		dev_warn(ifp->drvr->bus_if->dev,
			 "failed to set RF defaults: %d\n", err);
	wland_set_power_efuse(ifp);
	wland_set_crystal_cal_val(ifp);
}

s32 wland_set_scan_timeout(struct wland_if *ifp)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	wid = WID_SITE_SURVEY_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_CHANNEL_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_ACTIVE_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_ACTIVE_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_PASSIVE_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_PASSIVE_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_p2p_start_go_set(struct wland_if *ifp,
			   struct wland_cfg80211_profile *profile, bool is_p2p)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 u8_value;
	u16 u16_value;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	u8_value = 1;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &u8_value, sizeof(u8_value),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_11I_MODE_PAIRWISE,
			     &profile->sec.security, sizeof(u8), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_11I_MODE_GROUPWISE,
			     &profile->sec.security_group, sizeof(u8), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_AUTH_TYPE,
			     &profile->sec.firmware_autype, sizeof(u8), false);
	if (ret < 0)
		goto out;
	buf += ret;

	u16_value = profile->beacon;
	ret = wland_push_wid(buf, WID_BACON_INTERVAL_GO, &u16_value,
			     sizeof(u16), false);
	if (ret < 0)
		goto out;
	buf += ret;

	profile->dtim = 1;
	u8_value = profile->dtim;
	ret = wland_push_wid(buf, WID_P2P_DTIM_PERIOD, &u8_value, sizeof(u8),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_WID_SSID, &profile->ssid.SSID,
			     profile->ssid.SSID_len, false);
	if (ret < 0)
		goto out;
	buf += ret;

	u8_value = profile->channel;
	ret = wland_push_wid(buf, WID_P2P_OPER_CHAN, &u8_value, sizeof(u8),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	u8_value = 1;
	ret = wland_push_wid(buf, WID_P2P_GO_START_REQ, &u8_value,
			     sizeof(u8), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

s32 wland_start_ap_set(struct wland_if *ifp,
		       struct wland_cfg80211_profile *profile, bool is_p2p)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wid_type type;
	enum wland_firmw_wid wid;
	u8 size;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (profile->mode != WLAND_N_MODE) {
		wid = WID_11N_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}

	/* 40 MHz is not used in AP mode. */
	profile->band_width = 0;

	if (profile->mode == WLAND_N_MODE && profile->band_width == 0) {
		wid = WID_2040_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}

	if (profile->wmm_enable == 0) {
		wid = WID_QOS_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}

	wid = WID_802_11I_MODE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->sec.security;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_AUTH_TYPE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->sec.firmware_autype;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_BEACON_INTERVAL;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = (u8)(profile->beacon & 0x00FF);
	buf[4] = (u8)((profile->beacon & 0xFF00) >> 8);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	if (profile->dtim == 0)
		profile->dtim = 1;
	wid = WID_DTIM_PERIOD;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = (u8)(profile->dtim & 0xFF);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, profile->ssid.SSID_len);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->ssid.SSID, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_HIDDEN_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->hidden_ssid;
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_CURRENT_CHANNEL;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->channel;
	wid_msg_len += (size + 3);
	buf += (size + 3);

	if (profile->mode == WLAND_N_MODE && profile->band_width == 1) {
		wid = WID_USER_PREF_CHANNEL;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 2);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = profile->channel;
		buf[4] = ((profile->channel <= 9) ? 1 : 3) | (0 << 7);
		wid_msg_len += (size + 3);
		buf += (size + 3);
	}

	wid = WID_AP_START_REQ;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = 1;
	wid_msg_len += (size + 3);
	buf += (size + 3);

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_start_scan_set(struct wland_if *ifp,
			 struct wland_ssid_le *scan_ssid, bool enable)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 country_code;
	u8 scan_channel_time;
	u8 scan_active_time;
	u8 scan_passive_time;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));
	if (test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state)) {
		scan_channel_time = 20;
		scan_active_time = 20;
		scan_passive_time = 20;
	} else {
		scan_channel_time = 150;
		scan_active_time = 150;
		scan_passive_time = 150;
	}
	wid = WID_SITE_SURVEY_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_channel_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_ACTIVE_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_active_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_PASSIVE_SCAN_TIME;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_passive_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	country_code = WLAND_DEFAULT_COUNTRY_CODE;
	if (drvr->country_code != 0)
		country_code = drvr->country_code;
	wid = WID_SITE_SURVEY;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = country_code;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_START_SCAN_REQ;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = DEFAULT_SCAN;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	if (scan_ssid) {
		if (scan_ssid->SSID_len == 0) {
			size = 0;
			ret = wland_push_wid(buf, WID_SSID, &size, 1, false);
		} else {
			ret = wland_push_wid(buf, WID_SSID, scan_ssid->SSID,
					     scan_ssid->SSID_len, false);
		}
		if (ret < 0) {
			mutex_unlock(&drvr->proto_block);
			return ret;
		}
		buf += ret;
		wid_msg_len += ret;
	}

	ret = wland_proto_cdc_data(drvr, wid_msg_len);
	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_p2p_start_scan_set(struct wland_if *ifp,
			     struct wland_scan_params_le *sparams)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 data;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (sparams->channel_num == SOCIAL_CHAN_CNT) {
		data = P2P_SITE_SURVEY_SOCIAL;
	} else if (sparams->channel_num == P2P_FULL_CHAN_CNT ||
		   sparams->channel_num == P2P_FULL_CHAN_CNT_11) {
		data = SITE_SURVEY_ALL_CH;
	} else {
		dev_warn(drvr->bus_if->dev,
			 "invalid P2P scan channel count %u, using social channels\n",
			 le32_to_cpu(sparams->channel_num));
		data = P2P_SITE_SURVEY_SOCIAL;
	}
	ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
	if (ret < 0)
		goto out;
	buf += ret;

	data = 1;
	ret = wland_push_wid(buf, WID_P2P_START_SCAN_SEARCH_REQ, &data,
			     sizeof(data), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

s32 wland_p2p_af_scan_set(struct wland_if *ifp,
			  struct wland_scan_params_le *sparams)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 data;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	data = P2P_SITE_SURVEY_SOCIAL;
	ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
	if (ret < 0)
		goto out;
	buf += ret;

	data = 1;
	ret = wland_push_wid(buf, WID_P2P_START_AF_SCAN_REQ, &data,
			     sizeof(data), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

s32 wland_p2p_connect_scan(struct wland_if *ifp,
			   struct wland_scan_params_le *sparams)
{
	struct wland_ssid_le *scan_ssid = &sparams->ssid_le;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 data;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (sparams->channel_num == 1) {
		data = SITE_SURVEY_1CH;
		ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data),
				     false);
		if (ret < 0)
			goto out;
		buf += ret;

		data = sparams->channel_list[0] & 0xff;
		ret = wland_push_wid(buf, WID_P2P_ONE_CHAN, &data, sizeof(data),
				     false);
		if (ret < 0)
			goto out;
		buf += ret;
	} else {
		data = SITE_SURVEY_ALL_CH;
		ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data),
				     false);
		if (ret < 0)
			goto out;
		buf += ret;
	}

	if (scan_ssid->SSID_len == 0) {
		ret = wland_push_wid(buf, WID_P2P_WID_SSID, P2P_WILDCARD_SSID,
				     P2P_WILDCARD_SSID_LEN, false);
	} else {
		ret = wland_push_wid(buf, WID_P2P_WID_SSID, scan_ssid->SSID,
				     scan_ssid->SSID_len, false);
	}
	if (ret < 0)
		goto out;
	buf += ret;

	data = 1;
	ret = wland_push_wid(buf, WID_P2P_CONNECT_SCAN_REQ, &data, sizeof(data),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

s32 wland_enable_arp_offload(struct wland_if *ifp, char *ipv4_addr)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		wid = WID_ARP_OFFLOAD_91H;
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = 5;
		buf[3] = 1;	/* enable */
		memcpy(buf + 4, ipv4_addr, 4);
		buf += (5 + 3);
		wid_msg_len += (5 + 3);
	}

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_start_join(struct wland_if *ifp,
		     struct wland_cfg80211_profile *profile)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 char_val;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	wid = WID_QOS_ENABLE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = profile->wmm_enable;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_802_11I_MODE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	if (profile->sec.security == (ENCRYPT_ENABLED | WEP_EXTENDED))
		char_val = ENCRYPT_ENABLED | WEP | WEP_EXTENDED;
	else
		char_val = profile->sec.security;

	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_AUTH_TYPE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = profile->sec.firmware_autype;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_CURRENT_TX_RATE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 1;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_11N_CURRENT_TX_MCS;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 255;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_11N_SHORT_GI_ENABLE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 1;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_BSSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, sizeof(profile->bssid));
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->bssid, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, profile->ssid.SSID_len);
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->ssid.SSID, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		wid = WID_CURRENT_CHANNEL;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = profile->channel;
		wid_msg_len += (size + 3);
		buf += (size + 3);

		wid = WID_JOIN_REQ;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = 1;
		wid_msg_len += (size + 3);
		buf += (size + 3);

		wid = WID_SITE_SURVEY;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = SITE_SURVEY_OFF;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_p2p_start_join(struct wland_if *ifp,
			 struct wland_cfg80211_profile *profile)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret;
	u8 char_val;
	u8 buf1[100];
	int buf1_len = 0, count = 0;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	char_val = profile->wmm_enable;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &char_val, sizeof(char_val),
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	buf1[buf1_len++] = (u8)(profile->sec.wpa_versions);
	buf1[buf1_len++] = (u8)(profile->sec.cipher_group);
	buf1[buf1_len++] = (u8)(profile->sec.n_ciphers_pairwise);
	for (count = 0; count < profile->sec.n_ciphers_pairwise; ++count)
		buf1[buf1_len++] =
			(u8)(profile->sec.ciphers_pairwise[count] & 0xff);
	buf1[buf1_len++] = (u8)(profile->sec.n_akm_suites);
	for (count = 0; count < profile->sec.n_akm_suites; ++count)
		buf1[buf1_len++] =
			(u8)(profile->sec.akm_suites[count] & 0xff);

	ret = wland_push_wid(buf, WID_P2P_RSN_INFO, buf1, buf1_len, false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = profile->sec.security;
	ret = wland_push_wid(buf, WID_P2P_11I_MODE_PAIRWISE, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = profile->sec.security_group;
	ret = wland_push_wid(buf, WID_P2P_11I_MODE_GROUPWISE, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = profile->sec.firmware_autype;
	ret = wland_push_wid(buf, WID_P2P_AUTH_TYPE, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = 1;
	ret = wland_push_wid(buf, WID_CURRENT_TX_RATE, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = 255;
	ret = wland_push_wid(buf, WID_11N_CURRENT_TX_MCS, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_WID_BSSID, profile->bssid, ETH_ALEN,
			     false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_WID_SSID, profile->ssid.SSID,
			     profile->ssid.SSID_len, false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = profile->channel;
	ret = wland_push_wid(buf, WID_P2P_ONE_CHAN, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	char_val = 0;
	ret = wland_push_wid(buf, WID_P2P_JOIN_REQ, &char_val,
			     sizeof(char_val), false);
	if (ret < 0)
		goto out;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
out:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

s32 wland_disconnect_bss(struct wland_if *ifp,
			 struct wland_scb_val_le *scbval)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	wid = WID_DISCONNECT_REASON;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 4;
	buf[3] = (u8)scbval->val & 0x00FF;
	buf[4] = (u8)((scbval->val & 0xFF00) >> 8);
	wid_msg_len += 7;
	buf += 7;

	wid = WID_DISCONNECT;
	buf[0] = (u8)(wid & 0x00FF);
	buf[1] = (u8)((wid & 0xFF00) >> 8);
	buf[2] = 1;
	buf[3] = 0;
	wid_msg_len += 4;
	buf += 4;

	ret = wland_proto_cdc_data(drvr, wid_msg_len);
	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_p2p_disconnect_bss(struct wland_if *ifp,
			     struct wland_scb_val_le *scbval)
{
	u8 buf[ETH_ALEN + 3];

	memcpy(buf, scbval->ea, ETH_ALEN);
	put_le16(&buf[ETH_ALEN], scbval->val);
	buf[ETH_ALEN + 2] = 0;

	return wland_fil_set_cmd_data(ifp, WID_P2P_DISCONNECT_REQ,
				      buf, sizeof(buf));
}

s32 wland_p2p_go_del_sta(struct wland_if *ifp, struct wland_scb_val_le *scbval)
{
	u8 buf[ETH_ALEN + 3];

	memcpy(buf, scbval->ea, ETH_ALEN);
	put_le16(&buf[ETH_ALEN], scbval->val);
	buf[ETH_ALEN + 2] = scbval->aid;

	return wland_fil_set_cmd_data(ifp, WID_P2P_DISCONNECT_REQ,
				      buf, sizeof(buf));
}

s32 wland_ap_del_sta(struct wland_if *ifp, u8 aid)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 char_val;

	if (aid == 0) {
		netdev_err(ifp->ndev, "invalid AID 0 in del_sta\n");
		return -EINVAL;
	}

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		mutex_lock(&drvr->proto_block);

		memset(prot->buf, '\0', sizeof(prot->buf));

		wid = WID_DISCONNECT;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		char_val = aid;
		buf[0] = (u8)(wid & 0x00FF);
		buf[1] = (u8)((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = char_val;
		buf += (size + 3);
		wid_msg_len += (size + 3);

		ret = wland_proto_cdc_data(drvr, wid_msg_len);

		mutex_unlock(&drvr->proto_block);
	}

	return ret;
}

s32 wland_add_wep_key_bss_sta(struct wland_if *ifp, u8 *key, u8 wep_len,
			      u8 key_id)
{
	s32 err;
	u8 *buf = kzalloc(wep_len + 2, GFP_KERNEL);

	if (!buf)
		return -ENOMEM;

	buf[0] = key_id;
	buf[1] = wep_len;
	memcpy(buf + 2, key, wep_len);
	err = wland_fil_set_cmd_data(ifp, WID_ADD_WEP_KEY, buf, wep_len + 2);
	kfree(buf);

	return err;
}

int wland_set_reg_for_channels(struct wland_if *ifp, u16 reg, u16 *value)
{
	int ret;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	ret = wland_push_wid(buf, WID_RF_SET_CHANNEL_ACTIVE_REG, &reg, 2,
			     false);
	if (ret < 0)
		goto done;
	buf += ret;

	ret = wland_push_wid(buf, WID_RF_SET_CHANNEL_ACTIVE_VAL, (u8 *)value,
			     WLAND_CHANNEL_NUM * 2, false);
	if (ret < 0)
		goto done;
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf - prot->buf + FMW_HEADER_LEN);
done:
	mutex_unlock(&drvr->proto_block);
	return ret;
}

int wland_set_crystal_cal_val(struct wland_if *ifp)
{
	struct device *dev = ifp->drvr->bus_if->dev;
	u8 cal_val = 0;
	int ret;

	ret = wland_read_efuse_xtal_cal_val(ifp->ndev, NULL, 0, &cal_val);
	if (ret < 0 || cal_val == 0) {
		dev_warn(dev, "crystal calibration not found in eFuse: %d\n",
			 ret < 0 ? ret : -ENODATA);
		return ret < 0 ? ret : -ENODATA;
	}
	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 0, cal_val);
	if (ret < 0) {
		dev_err(dev, "failed to set crystal calibration: %d\n", ret);
		return ret;
	}
	dev_info(dev, "applied crystal trim: 0x%02x\n", cal_val & 0xfe);
	return ret;
}

s32 wland_set_power_efuse(struct wland_if *ifp)
{
	struct device *dev = ifp->drvr->bus_if->dev;
	u8 power_efuse[WLAND_TXP_NUM] = {0};
	u8 b_v, n_v;
	int ret;

	ret = wland_read_txpower_from_efuse(ifp->ndev, NULL, 0, power_efuse);
	if (ret < 0 || power_efuse[0] < WLAND_TXP_11F_BASE ||
	    power_efuse[0] > WLAND_TXP_11F_END ||
	    power_efuse[1] < WLAND_TXP_120_BASE ||
	    power_efuse[1] > WLAND_TXP_120_END) {
		dev_warn(dev, "TX power calibration not found in eFuse\n");
		return -ENODATA;
	}

	n_v = power_efuse[0];
	b_v = power_efuse[1];
	ifp->drvr->power_11f = power_efuse[0];
	ifp->drvr->power_120 = power_efuse[1];

	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 1, n_v);
	if (ret < 0) {
		dev_err(dev, "failed to set 11f TX power: %d\n", ret);
		return ret;
	}

	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 2, b_v);
	if (ret < 0) {
		dev_err(dev, "failed to set 120 TX power: %d\n", ret);
		return ret;
	}

	return ret;
}

/*
 * Board RF defaults (11f, 120, g_n_offset, per-channel 0x8a, 1da), applied
 * in this order: defaults, then eFuse TX power, then eFuse crystal trim.
 * eFuse calibration overrides 11f/120/1da.
 */
#define WLAND_DEFAULT_TXP_11F		0x45
#define WLAND_DEFAULT_TXP_120		0x35
#define WLAND_DEFAULT_G_N_OFFSET	0x01
#define WLAND_DEFAULT_XTAL_CAL		0x80

static const u16 wland_default_reg_8a[WLAND_CHANNEL_NUM] = {
	0x69a0, 0x69a0, 0x69a0, 0x6920, 0x6920, 0x68a0, 0x68a0,
	0x68a0, 0x68a0, 0x68a0, 0x68a0, 0x68a0, 0x68a0, 0x6820
};

static s32 wland_set_power_defaults(struct wland_if *ifp)
{
	struct wland_private *drvr = ifp->drvr;
	u16 value_8a[WLAND_CHANNEL_NUM];
	s32 ret;

	drvr->power_11f = WLAND_DEFAULT_TXP_11F;
	drvr->power_120 = WLAND_DEFAULT_TXP_120;
	drvr->power_g_n_offset = WLAND_DEFAULT_G_N_OFFSET;

	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 1, drvr->power_11f);
	if (ret < 0)
		return ret;
	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 2, drvr->power_120);
	if (ret < 0)
		return ret;

	memcpy(value_8a, wland_default_reg_8a, sizeof(value_8a));
	ret = wland_set_reg_for_channels(ifp, 0x8A, value_8a);
	if (ret < 0)
		return ret;

	return wland_set_hardware_param(ifp->ndev, NULL, 0, 0,
					WLAND_DEFAULT_XTAL_CAL);
}

s32 wland_set_11n_action(struct wland_if *ifp, u8 *mac, u8 tid, u8 add)
{
	struct wland_11n_action action;

	action.category = 0x07;
	action.action = 0x02;
	memcpy(action.bssid, mac, ETH_ALEN);
	action.tid = tid;
	action.max_msdu = 0x10;
	action.ack_policy = 0x00;
	action.ba_policy = 0x01;
	action.buff_size = cpu_to_le16(0x10);
	action.ba_timeout = cpu_to_le16(0x00);
	action.add_ba_timeout = cpu_to_le16(1500);

	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY)
		return wland_fil_set_cmd_data(ifp, WID_11N_P_ACTION_REQ,
					      &action, sizeof(action));

	return wland_fil_set_cmd_data(ifp, WID_P2P_P_ACTION_TX, &action,
				      sizeof(action));
}

s32 wland_set_txrate(struct wland_if *ifp, u8 mbps)
{
	return wland_fil_set_cmd_data(ifp, WID_CURRENT_TX_RATE, &mbps,
				      sizeof(mbps));
}

int wland_proto_attach(struct wland_private *drvr)
{
	struct wland_proto *cdc = kzalloc(sizeof(*cdc), GFP_KERNEL);

	if (!cdc)
		return -ENOMEM;

	/* The message buffer must directly follow the message header. */
	if ((uintptr_t)(&cdc->msg + 1) != (uintptr_t)cdc->buf) {
		dev_err(drvr->bus_if->dev, "invalid wland_proto layout\n");
		kfree(cdc);
		return -EINVAL;
	}

	drvr->prot = cdc;
	drvr->hdrlen += WID_HEADER_LEN;
	drvr->maxctl =
		WLAND_DCMD_MEDLEN + sizeof(struct wland_dcmd) + ROUND_UP_MARGIN;

	return 0;
}

void wland_proto_detach(struct wland_private *drvr)
{
	if (drvr) {
		kfree(drvr->prot);
		drvr->prot = NULL;
	}
}

