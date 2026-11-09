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
#include <net/netlink.h>
#include <asm/unaligned.h>

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
#include "wland_rx.h"
#include "wland_rf.h"
#include "wland_usb.h"

#define CHAN2G(_channel, _freq, _flags) {	    \
	.band			  = NL80211_BAND_2GHZ,    \
	.center_freq	  = (_freq),			    \
	.hw_value		  = (_channel),			    \
	.flags			  = (_flags),			    \
	.max_antenna_gain = 0,				        \
	.max_power		  = 30,				        \
}

#define RATE_TO_BASE100KBPS(rate)               (((rate) * 10) / 2)

#define RATETAB_ENT(_rateid, _flags) {            \
	.bitrate      = RATE_TO_BASE100KBPS(_rateid),\
	.hw_value     = (_rateid),                   \
	.flags        = (_flags),                    \
}

static struct ieee80211_rate __wl_rates[] = {
	RATETAB_ENT(WLAND_RATE_1M, 0),
	RATETAB_ENT(WLAND_RATE_2M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLAND_RATE_5M5, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLAND_RATE_11M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLAND_RATE_6M, 0),
	RATETAB_ENT(WLAND_RATE_9M, 0),
	RATETAB_ENT(WLAND_RATE_12M, 0),
	RATETAB_ENT(WLAND_RATE_18M, 0),
	RATETAB_ENT(WLAND_RATE_24M, 0),
	RATETAB_ENT(WLAND_RATE_36M, 0),
	RATETAB_ENT(WLAND_RATE_48M, 0),
	RATETAB_ENT(WLAND_RATE_54M, 0),
};

#define wl_g_rates		(__wl_rates + 0)
#define wl_g_rates_size	12

static struct ieee80211_channel __wl_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

static struct ieee80211_supported_band __wl_band_2ghz = {
	.band = NL80211_BAND_2GHZ,
	.channels = __wl_2ghz_channels,
	.n_channels = ARRAY_SIZE(__wl_2ghz_channels),
	.bitrates = wl_g_rates,
	.n_bitrates = wl_g_rates_size,
};

/* Custom world domain for the 2.4 GHz-only radio. */
static const struct ieee80211_regdomain wland_regdom = {
	.n_reg_rules = 2,
	.alpha2 = "99",
	.reg_rules = {
		/* Channels 1..13 */
		REG_RULE(2412 - 10, 2472 + 10, 40, 6, 20, 0),
		/* Channel 14 */
		REG_RULE(2484 - 10, 2484 + 10, 20, 6, 20, 0),
	}
};

static const u32 __wl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};

/* Vendor specific ie. id = 221, oui and type defines exact ie */
struct wland_vs_tlv {
	u8 id;
	u8 len;
	u8 oui[3];
	u8 oui_type;
};

struct parsed_vndr_ie_info {
	const u8 *ie_ptr;
	u32 ie_len;		/* total length including id & length field */
	struct wland_vs_tlv vndrie;
};

struct parsed_vndr_ies {
	u32 count;
	struct parsed_vndr_ie_info ie_info[VNDR_IE_PARSE_LIMIT];
};

int wland_wait_for_scancmp_event(struct wland_cfg80211_info *cfg, bool *lockvar)
{
	return wait_event_interruptible_timeout(cfg->scanid_wait, !(*lockvar),
						msecs_to_jiffies(SCAN_CMP_TIMEOUT));
}

void wland_wait_event_scancmp_wakeup(struct wland_cfg80211_info *cfg)
{
	wake_up(&cfg->scanid_wait);
}

u16 wland_channel_to_chanspec(struct wland_d11inf *d11inf,
	struct ieee80211_channel *ch)
{
	struct wland_chan ch_inf;

	ch_inf.chnum = ieee80211_frequency_to_channel(ch->center_freq);
	ch_inf.bw = CHAN_BW_20;
	d11inf->encchspec(&ch_inf);

	return ch_inf.chspec;
}

static __always_inline void wland_delay(u32 ms)
{
	if (ms < 1000 / HZ) {
		cond_resched();
		mdelay(ms);
	} else {
		msleep(ms);
	}
}

static s16 wland_find_rsncap(struct wland_tlv *rsn_ie, u16 *rsn_cap)
{
	u8 totlen = 0;
	u8 *buf = rsn_ie->data;
	u16 num;

	totlen += 2; /* version */
	totlen += 4; /* group data cipher suite */
	if (totlen >= rsn_ie->len)
		return -1;

	num = get_unaligned_le16(buf + totlen);
	totlen += num * 4 + 2; /* pairwise cipher suites */
	if (totlen >= rsn_ie->len)
		return -2;

	num = get_unaligned_le16(buf + totlen);
	totlen += num * 4 + 2; /* AKM suites */
	if (totlen >= rsn_ie->len)
		return -3;

	if (totlen + 2 > rsn_ie->len)
		return -4;

	*rsn_cap = get_unaligned_le16(buf + totlen);
	return 0;
}

/* Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element matches tag
 */
struct wland_tlv *wland_parse_tlvs(const void *buf, int buflen,
				   unsigned int key)
{
	struct wland_tlv *elt;
	int totlen = buflen;

	if (!buf)
		return NULL;
	elt = (struct wland_tlv *) buf;

	while (totlen >= TLV_HDR_LEN) {
		int len = elt->len;

		if ((elt->id == key) && (totlen >= (len + TLV_HDR_LEN)))
			return elt;

		elt = (struct wland_tlv *) ((u8 *) elt + (len + TLV_HDR_LEN));
		totlen -= (len + TLV_HDR_LEN);
	}

	return NULL;
}

/* Check if TLV is expected entry; update pointer/length if not. */
static bool wland_tlv_has_ie(u8 *ie, const u8 **tlvs, u32 *tlvs_len, u8 *oui,
	u32 oui_len, u8 type)
{
	if (!ie)
		return false;
	if (ie[TLV_LEN_OFF] >= oui_len + 1
		&& !memcmp(&ie[TLV_BODY_OFF], oui, oui_len)
		&& type == ie[TLV_BODY_OFF + oui_len]) {
		return true;
	}

	if (!tlvs)
		return false;
	ie += ie[TLV_LEN_OFF] + TLV_HDR_LEN;
	*tlvs_len -= (int) (ie - *tlvs);
	*tlvs = ie;

	return false;
}

static struct wland_vs_tlv *wland_find_wmmie(const u8 *parse, u32 len)
{
	struct wland_tlv *ie;

	if (!parse)
		return NULL;

	while ((ie = wland_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (wland_tlv_has_ie((u8 *) ie, &parse, &len, WPA_OUI,
				TLV_OUI_LEN, WME_OUI_TYPE))
			return (struct wland_vs_tlv *) ie;
	}
	return NULL;
}

static struct wland_vs_tlv *wland_find_wpaie(const u8 *parse, u32 len)
{
	struct wland_tlv *ie;

	if (!parse)
		return NULL;

	while ((ie = wland_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (wland_tlv_has_ie((u8 *) ie, &parse, &len, WPA_OUI,
				TLV_OUI_LEN, WPA_OUI_TYPE))
			return (struct wland_vs_tlv *) ie;
	}
	return NULL;
}

static struct wland_vs_tlv *wland_find_wpsie(const u8 *parse, u32 len)
{
	struct wland_tlv *ie;

	if (!parse)
		return NULL;

	while ((ie = wland_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (wland_tlv_has_ie((u8 *) ie, &parse, &len, WPA_OUI,
				TLV_OUI_LEN, WPS_OUI_TYPE))
			return (struct wland_vs_tlv *) ie;
	}
	return NULL;
}

static u8 wland_find_wps_req_type(struct wland_vs_tlv *wps_ie)
{
	u8 *buf = (u8 *)(wps_ie + 1);
	u8 *end = (u8 *)wps_ie + wps_ie->len + 2;
	u16 len;

	/* Attributes have a big-endian 16-bit type and length */
	while (end - buf >= 4) {
		len = get_unaligned_be16(buf + 2);
		if (len > end - buf - 4)
			break;
		if (get_unaligned_be16(buf) == 0x103a && len == 1)
			return buf[4];
		buf += 4 + len;
	}
	return 0;
}

static int wland_send_key_to_chip(struct net_device *ndev,
				  struct wland_wsec_key *key)
{
	int err;

	wland_netdev_wait_pend8021x(ndev);

	err = wland_fil_iovar_data_set(netdev_priv(ndev), "wsec_key", key,
		sizeof(struct wland_wsec_key));
	if (err)
		netdev_err(ndev, "failed to set wsec_key: %d\n", err);

	return err;
}

bool wland_check_vif_up(struct wland_cfg80211_vif *vif)
{
	if (!test_bit(VIF_STATUS_READY, &vif->sme_state)) {
		wiphy_dbg(vif->wdev.wiphy, "device not ready: status 0x%lx\n",
			  vif->sme_state);
		return false;
	}

	if (test_bit(VIF_STATUS_TESTING, &vif->sme_state)) {
		wiphy_dbg(vif->wdev.wiphy,
			  "device in test mode: status 0x%lx\n",
			  vif->sme_state);
		return false;
	}

	return true;
}

/* End the scan hold on data frames and send any queued during it */
void wland_clear_scan_busy(struct wland_cfg80211_info *cfg)
{
	struct wland_usbdev_info *devinfo =
		cfg->pub->bus_if->bus_priv.usb->devinfo;

	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);
	if (!list_empty(&devinfo->tx_postq))
		queue_work(devinfo->wland_txwq, &devinfo->tx_work);
}

s32 wland_notify_escan_complete(struct wland_cfg80211_info *cfg,
	struct wland_if *ifp, bool aborted, bool fw_abort)
{
	struct cfg80211_scan_request *scan_request;
	struct cfg80211_scan_info *info = &cfg->escan_info;

	/*
	 * Clear the scan request first: a firmware abort can call this
	 * function again and report cfg80211_scan_done() twice.
	 */
	scan_request = cfg->scan_request;
	cfg->scan_request = NULL;

	if (timer_pending(&cfg->scan_timeout)) {
		del_timer_sync(&cfg->scan_timeout);
		wland_clear_scan_busy(cfg);
	}

	if (fw_abort)
		wiphy_dbg(cfg->wiphy, "scan aborted in firmware\n");

	/* e-scan can be initiated by scheduled scan, which takes precedence */
	if (cfg->sched_escan) {
		wiphy_dbg(cfg->wiphy, "scheduled scan completed\n");
		cfg->sched_escan = false;
		if (scan_request) {
			kfree(scan_request->channels[0]);
			kfree(scan_request->ssids);
			kfree(scan_request);
		}
		if (!aborted)
			cfg80211_sched_scan_results(cfg_to_wiphy(cfg), 0);
	} else if (scan_request) {
		wiphy_dbg(cfg->wiphy, "escan completed: %s\n",
			  aborted ? "aborted" : "done");

		info->aborted = aborted;
		cfg80211_scan_done(scan_request, info);
	}

	return 0;
}

static s32 wland_cfg80211_change_virtual_iface(struct wiphy *wiphy,
	struct net_device *ndev,
	enum nl80211_iftype type, struct vif_params *params)
{
	struct wland_cfg80211_info *cfg = wiphy_priv(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wland_sta_info *sta_info, *sta_info_tmp;
	struct timer_list *cr_timer = &conn_info->connect_restorework_timeout;
	s32 err = 0;

	switch (type) {
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_MESH_POINT:
	case NL80211_IFTYPE_ADHOC:
		netdev_err(ndev, "unsupported interface type: %d\n", type);
		return -EOPNOTSUPP;
	case NL80211_IFTYPE_P2P_CLIENT:
		vif->mode = WL_MODE_BSS;
		err = wland_p2p_ifchange(cfg, FIL_P2P_IF_CLIENT);
		break;
	case NL80211_IFTYPE_P2P_GO:
		vif->mode = WL_MODE_AP;
		err = wland_p2p_ifchange(cfg, FIL_P2P_IF_GO);
		break;
	case NL80211_IFTYPE_STATION:
		if (vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT) {
			set_bit(VIF_STATUS_CHANGEING, &vif->sme_state);
			if (timer_pending(&conn_info->timer))
				del_timer_sync(&conn_info->timer);
			if (timer_pending(cr_timer))
				del_timer_sync(cr_timer);
			cancel_work_sync(
				&conn_info->connect_restorework_timeout_work);

			while (test_bit(VIF_STATUS_CONNECTING, &vif->sme_state))
				msleep(20);
			err = wland_p2p_ifchange(cfg, FIL_P2P_IF_DEV);
			clear_bit(VIF_STATUS_CONNECTED, &vif->sme_state);
			clear_bit(VIF_STATUS_CHANGEING, &vif->sme_state);
			vif->mode = WL_MODE_P2P;
		} else if (vif->wdev.iftype == NL80211_IFTYPE_P2P_GO) {
			err = wland_p2p_ifchange(cfg, FIL_P2P_IF_DEV);
			spin_lock_bh(&conn_info->sta_info_lock);
			list_for_each_entry_safe(sta_info, sta_info_tmp,
						 &conn_info->sta_info_list,
						 list) {
				netdev_dbg(ndev,
					   "freeing station: conn %u, AID %u, MAC %pM\n",
					   sta_info->connect, sta_info->aid,
					   sta_info->mac_addr);
				list_del(&sta_info->list);
				kfree(sta_info->assoc_req_ie);
				kfree(sta_info);
			}
			spin_unlock_bh(&conn_info->sta_info_lock);
			clear_bit(VIF_STATUS_AP_CREATING, &vif->sme_state);
			clear_bit(VIF_STATUS_AP_CREATED, &vif->sme_state);
			vif->mode = WL_MODE_P2P;
		}
		break;
	case NL80211_IFTYPE_AP:
		vif->mode = WL_MODE_AP;
		break;
	default:
		err = -EINVAL;
		goto done;
	}

	if (!err)
		ndev->ieee80211_ptr->iftype = type;
done:
	return err;
}

static s32 wland_run_escan(struct wland_cfg80211_info *cfg,
	struct wland_if *ifp, struct cfg80211_scan_request *request, u16 action)
{
	struct wland_ssid_le ssid_le;
	s32 err = 0;

	if (!request->ssids || request->n_ssids == 0) {
		cfg->scannum = 0;
		mod_timer(&cfg->scan_timeout,
			jiffies + msecs_to_jiffies(SCAN_TIMER_INTERVAL_MS));
		if (wland_check_test_mode() == 0 &&
		    strncasecmp(rdawlan_firmware_path, "ap", 2) != 0)
			err = wland_start_scan_set(ifp, NULL, true);
		if (err < 0)
			netdev_err(ifp->ndev, "failed to start scan: %d\n",
				   err);
		return err;
	}

	mod_timer(&cfg->scan_timeout,
		  jiffies + msecs_to_jiffies(SCAN_TIMER_INTERVAL_MS *
					     request->n_ssids));
	memset(&ssid_le, 0, sizeof(ssid_le));

	cfg->scannum = request->n_ssids;
	while (cfg->scannum > 0) {
		cfg->scannum--;
		ssid_le.SSID_len =
			cpu_to_le32(request->ssids[cfg->scannum].ssid_len);
		memcpy(ssid_le.SSID, request->ssids[cfg->scannum].ssid,
		       request->ssids[cfg->scannum].ssid_len);

		if (wland_check_test_mode() == 0 &&
		    strncasecmp(rdawlan_firmware_path, "ap", 2)) {
			err = wland_start_scan_set(ifp, &ssid_le, true);
			netdev_dbg(ifp->ndev,
				   "scanning SSID \"%.*s\" (%u/%d)\n",
				   request->ssids[cfg->scannum].ssid_len,
				   request->ssids[cfg->scannum].ssid,
				   cfg->scannum, request->n_ssids);
		}
		if (err < 0) {
			netdev_err(ifp->ndev, "failed to start scan: %d\n",
				   err);
		} else if (cfg->scannum > 0) {
			cfg->ctrl_scan_wait = true;
			err = wland_wait_for_scancmp_event(
				cfg, &cfg->ctrl_scan_wait);
		}
	}

	return err;
}

static s32 wland_do_escan(struct wland_cfg80211_info *cfg, struct wiphy *wiphy,
	struct wland_if *ifp, struct cfg80211_scan_request *request)
{
	struct wland_scan_info *escan = &cfg->scan_info;

	escan->ifp = ifp;
	escan->wiphy = wiphy;
	escan->escan_state = SCAN_STATE_SCANNING;

	return escan->run(cfg, ifp, request, SCAN_ACTION_START);
}

static s32 wland_cfg80211_scan(struct wiphy *wiphy,
	struct cfg80211_scan_request *request)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_cfg80211_vif *vif =
		container_of(request->wdev, struct wland_cfg80211_vif, wdev);
	struct wland_if *ifp = vif->ifp;
	struct cfg80211_ssid *ssids = NULL;
	struct wland_cfg80211_scan_req *sr = &cfg->scan_req_int;
	struct wland_cfg80211_connect_info *cinfo0 =
		&cfg->pub->iflist[0]->vif->conn_info;
	struct wland_cfg80211_connect_info *cinfo1 =
		&cfg->pub->iflist[1]->vif->conn_info;
	s32 err = 0, SSID_len;
	bool escan_req = false;
	struct wland_vs_tlv *wps_ie;

	if (!wland_check_vif_up(vif))
		return -EIO;

	if (timer_pending(&cinfo0->connect_restorework_timeout) ||
	    timer_pending(&cinfo1->connect_restorework_timeout)) {
		netdev_dbg(ifp->ndev, "getting IP, delaying scan\n");
		return -EAGAIN;
	}

	if (test_bit(VIF_STATUS_CONNECTING,
		     &cfg->pub->iflist[0]->vif->sme_state)) {
		netdev_dbg(ifp->ndev,
			   "STA connecting (status 0x%lx), skipping scan\n",
			   cfg->pub->iflist[0]->vif->sme_state);
		return -EAGAIN;
	}

	if (test_bit(VIF_STATUS_CONNECTING,
		     &cfg->pub->iflist[1]->vif->sme_state)) {
		netdev_dbg(ifp->ndev,
			   "P2P connecting (status 0x%lx), skipping scan\n",
			   cfg->pub->iflist[1]->vif->sme_state);
		return -EAGAIN;
	}

	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
		return -EBUSY;

	if (test_bit(SCAN_STATUS_ABORT, &cfg->scan_status)) {
		netdev_dbg(ifp->ndev, "scan being aborted: status 0x%lx\n",
			   cfg->scan_status);
		return -EAGAIN;
	}
	if (test_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status)) {
		netdev_dbg(ifp->ndev, "scan suppressed: status 0x%lx\n",
			   cfg->scan_status);
		return -EAGAIN;
	}

	if (request) {
		ssids = request->ssids;
		escan_req = true;
	}

	wps_ie = wland_find_wpsie(request->ie, request->ie_len);
	if (wps_ie &&
	    wland_find_wps_req_type(wps_ie) == 0x1 &&
	    ifp->bssidx == P2PAPI_BSSCFG_PRIMARY) {
		netdev_dbg(ifp->ndev, "STA WPS scan\n");
		wland_fil_set_cmd_data(ifp, WID_STA_VNDR_IE,
				       wps_ie, wps_ie->len + 2);
	}

	cfg->scan_request = request;

	set_bit(SCAN_STATUS_BUSY, &cfg->scan_status);
	if (escan_req) {
		cfg->scan_info.ifp = ifp;
		cfg->scan_info.run = wland_run_escan;
		if (wland_p2p_scan_is_p2p_request(request, vif)) {
			netdev_dbg(ifp->ndev, "P2P scan requested\n");
			set_bit(VIF_STATUS_P2P,
				&(ifp->drvr->iflist[0]->vif->sme_state));
			err = wland_p2p_scan_prep(wiphy, request, vif);
			if (err < 0)
				goto scan_out;
		}
	} else {
		memset(&sr->ssid_le, 0, sizeof(sr->ssid_le));
		SSID_len = min_t(u8, sizeof(sr->ssid_le.SSID), ssids->ssid_len);
		sr->ssid_le.SSID_len = cpu_to_le32(0);

		if (SSID_len) {
			memcpy(sr->ssid_le.SSID, ssids->ssid, SSID_len);
			sr->ssid_le.SSID_len = cpu_to_le32(SSID_len);
		} else {
			netdev_dbg(ifp->ndev, "broadcast scan\n");
		}
	}

	err = wland_do_escan(cfg, wiphy, vif->ifp, request);
	if (err < 0)
		goto scan_out;
	netdev_dbg(ifp->ndev, "scan started: %u SSIDs, %u channels\n",
		   request->n_ssids, request->n_channels);

	return 0;

scan_out:
	wland_clear_scan_busy(cfg);
	if (timer_pending(&cfg->scan_timeout))
		del_timer_sync(&cfg->scan_timeout);
	cfg->scan_request = NULL;
	return err;
}

static s32 wland_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	return 0;
}

/* Claim CONNECTING before reporting failure to avoid duplicate completion. */
static void wland_connect_failed(struct wland_cfg80211_vif *vif, u16 status,
				 bool timed_out)
{
	struct net_device *ndev = vif->wdev.netdev;
	struct wland_cfg80211_profile *profile = &vif->profile;
	struct wland_cfg80211_connect_info *conn_info = &vif->conn_info;

	if (!test_and_clear_bit(VIF_STATUS_CONNECTING, &vif->sme_state))
		return;

	if (vif->wdev.iftype != NL80211_IFTYPE_STATION &&
	    vif->wdev.iftype != NL80211_IFTYPE_P2P_CLIENT)
		return;

	netdev_dbg(ndev, "connect to %pM failed (%s, status %u)\n",
		   profile->bssid, timed_out ? "timeout" : "link down",
		   status);

	if (timed_out)
		cfg80211_connect_timeout(ndev, profile->bssid,
					 conn_info->req_ie,
					 conn_info->req_ie_len, GFP_KERNEL,
					 NL80211_TIMEOUT_UNSPECIFIED);
	else
		cfg80211_connect_result(ndev, profile->bssid,
					conn_info->req_ie,
					conn_info->req_ie_len, NULL, 0,
					status, GFP_KERNEL);
}

static void wland_link_down(struct wland_cfg80211_vif *vif)
{
	s32 err = 0;
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(vif->wdev.wiphy);
	struct wland_scb_val_le scbval;
	struct wland_cfg80211_profile *profile = &vif->profile;
	struct wland_cfg80211_connect_info *conn_info = &vif->conn_info;

	if (test_bit(VIF_STATUS_CONNECTED, &vif->sme_state)) {
		memset(&scbval, '\0', sizeof(scbval));
		memcpy(&scbval.ea, &profile->bssid, ETH_ALEN);
		err = wland_disconnect_bss(vif->ifp, &scbval);
		if (!err)
			netdev_dbg(vif->wdev.netdev, "disassociated from AP\n");

		cfg80211_disconnected(vif->wdev.netdev, 0, NULL, 0,
				      cfg->in_disconnecting, GFP_KERNEL);
		clear_bit(VIF_STATUS_CONNECTED, &vif->sme_state);
	}
	if (test_bit(VIF_STATUS_CONNECTING, &vif->sme_state)) {
		cancel_work_sync(&conn_info->work);
		if (timer_pending(&conn_info->timer))
			del_timer_sync(&conn_info->timer);
		cancel_work_sync(&conn_info->connect_fail_work);

		if (timer_pending(&conn_info->connect_restorework_timeout))
			del_timer_sync(&conn_info->connect_restorework_timeout);
		cancel_work_sync(&conn_info->connect_restorework_timeout_work);

		/* the attempt never completed, so this is a connect failure */
		wland_connect_failed(vif, WLAN_STATUS_UNSPECIFIED_FAILURE,
				     false);
	}
	clear_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status);
}

static s32 wland_cfg80211_join_ibss(struct wiphy *wiphy,
				     struct net_device *ndev,
				     struct cfg80211_ibss_params *params)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_join_params join_params;
	size_t join_params_size = 0;
	s32 err = 0, wsec = 0, bcnprd;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	if (!params->ssid) {
		netdev_dbg(ndev, "SSID not specified for IBSS join\n");
		return -EOPNOTSUPP;
	}

	set_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (params->privacy)
		wsec |= WEP_ENABLED;

	err = wland_fil_iovar_data_set(ifp, "wsec", &wsec, sizeof(wsec));
	if (err) {
		netdev_err(ndev, "failed to set wsec: %d\n", err);
		goto done;
	}

	if (params->beacon_interval)
		bcnprd = params->beacon_interval;
	else
		bcnprd = 100;

	err = wland_fil_iovar_data_set(ifp, "set_bcnprd", &bcnprd,
		sizeof(bcnprd));
	if (err < 0) {
		netdev_err(ndev, "failed to set beacon period: %d\n", err);
		goto done;
	}

	memset(&join_params, 0, sizeof(struct wland_join_params));

	profile->ssid.SSID_len = min_t(u32, params->ssid_len, 32);

	memcpy(profile->ssid.SSID, params->ssid, profile->ssid.SSID_len);
	memcpy(join_params.ssid_le.SSID, params->ssid, profile->ssid.SSID_len);

	join_params.ssid_le.SSID_len = cpu_to_le32(profile->ssid.SSID_len);
	join_params_size = sizeof(join_params.ssid_le);

	if (params->bssid) {
		memcpy(join_params.params_le.bssid, params->bssid, ETH_ALEN);
		join_params_size = sizeof(join_params.ssid_le) +
			(sizeof(struct wland_assoc_params_le) - sizeof(u16));
		memcpy(profile->bssid, params->bssid, ETH_ALEN);
	} else {
		memset(join_params.params_le.bssid, 0xFF, ETH_ALEN);
		memset(profile->bssid, 0, ETH_ALEN);
	}

	if (params->chandef.chan) {
		u32 target_channel;

		cfg->channel = ieee80211_frequency_to_channel(
			params->chandef.chan->center_freq);

		if (params->channel_fixed) {
			u16 chanspec = wland_channel_to_chanspec(
				&cfg->d11inf, params->chandef.chan);

			join_params.params_le.chanspec_list[0] =
				cpu_to_le16(chanspec);
			join_params.params_le.chanspec_num = cpu_to_le32(1);
			join_params_size += sizeof(join_params.params_le);
		}

		target_channel = cfg->channel;
		err = wland_fil_iovar_data_set(ifp, "set_channel",
			&target_channel, sizeof(target_channel));
		if (err < 0) {
			netdev_err(ndev, "failed to set channel: %d\n", err);
			goto done;
		}
	} else {
		cfg->channel = 0;
	}
	cfg->ibss_starter = false;

	err = wland_fil_iovar_data_set(ifp, "set_ssid", &join_params,
		join_params_size);
	if (err < 0) {
		netdev_err(ndev, "failed to set SSID: %d\n", err);
		goto done;
	}

done:
	if (err)
		clear_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	return err;
}

static s32 wland_cfg80211_leave_ibss(struct wiphy *wiphy,
				      struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	wland_link_down(ifp->vif);

	return 0;
}

static s32 wland_wakeup_connect_worker(struct wland_cfg80211_connect_info
	*conn_info);
static s32 wland_cfg80211_connect(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_connect_params *sme)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct ieee80211_channel *chan = sme->channel;
	struct wland_bss_info_le *bss;
	u8 i;
	s32 err = 0;
	int count = 0;
	struct wland_tlv *rsn_ie;
	struct wland_vs_tlv *wps_ie;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	if (!sme->ssid || !sme->bssid) {
		netdev_err(ndev, "invalid connect target (SSID %s, BSSID %pM)\n",
			   sme->ssid ? (const char *)sme->ssid : "<none>",
			   sme->bssid);
		return -ECONNABORTED;
	}

	while (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status)) {
		netdev_dbg(ndev, "waiting for scan to complete (status 0x%lx)\n",
			   cfg->scan_status);
		msleep(100);
		if (count++ > 20) {
			netdev_dbg(ndev, "scan timed out while preparing to connect\n");
			break;
		}
	}

	if (cfg->in_disconnecting) {
		cfg->in_waiting = true;
		wait_for_completion_timeout(&cfg->disconnecting_wait,
			msecs_to_jiffies(1000));
	}
	cfg->in_waiting = false;

	WARN_ON(atomic_read(&ifp->pend_8021x_cnt));
	atomic_set(&ifp->pend_8021x_cnt, 0);

	if (test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state)) {
		struct wland_scb_val_le scbval;

		netdev_dbg(ndev, "already connected to %s, deauthenticating first\n",
			   profile->ssid.SSID);
		memset(&scbval, '\0', sizeof(scbval));
		memcpy(&scbval.ea, &profile->bssid, ETH_ALEN);

		clear_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
		clear_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
		clear_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status);
		wland_disconnect_bss(ifp->vif->ifp, &scbval);

		msleep(100);
	}

	conn_info->ndev = ndev;

	kfree(profile->wps_ie);
	profile->wps_ie = NULL;
	profile->wps_ie_len = 0;

	kfree(conn_info->req_ie);
	conn_info->req_ie = NULL;
	conn_info->req_ie_len = 0;

	kfree(conn_info->resp_ie);
	conn_info->resp_ie = NULL;
	conn_info->resp_ie_len = 0;

	memset(profile, 0, sizeof(struct wland_cfg80211_profile));
	memcpy(profile->bssid, sme->bssid, ETH_ALEN);
	profile->valid_bssid = true;

	cancel_work_sync(&conn_info->connect_fail_work);
	set_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (timer_pending(&conn_info->connect_restorework_timeout))
		del_timer_sync(&conn_info->connect_restorework_timeout);

	profile->rsn_cap = 0xffff;
	rsn_ie = wland_parse_tlvs((u8 *)sme->ie, sme->ie_len,
				  WLAN_EID_RSN);
	if (rsn_ie) {
		err = wland_vif_set_mgmt_ie(ifp->vif,
					    WLAND_VNDR_IE_RSN_INFO_FLAG,
					    (const u8 *)rsn_ie,
					    rsn_ie->len + TLV_HDR_LEN);
		if (err) {
			netdev_err(ndev, "failed to set RSN info IE: %d\n",
				   err);
			goto done;
		}
		if (wland_find_rsncap(rsn_ie, &profile->rsn_cap) < 0) {
			netdev_err(ndev, "failed to parse RSN capabilities\n");
			err = -EINVAL;
			goto done;
		}
		netdev_dbg(ndev, "RSN capabilities: 0x%04x\n",
			   profile->rsn_cap);
	}

	if (ifp->bssidx == P2PAPI_BSSCFG_DEVICE) {
		err = wland_vif_set_mgmt_ie(ifp->vif,
					    WLAND_VNDR_IE_ASSOCREQ_FLAG,
					    sme->ie, sme->ie_len);
		if (err) {
			netdev_err(ndev, "failed to set assoc req IE: %d\n",
				   err);
			goto done;
		}
	}

	if (chan)
		cfg->channel =
			ieee80211_frequency_to_channel(chan->center_freq);
	else
		cfg->channel = 0;

	profile->channel = cfg->channel;
	profile->beacon = cfg->scan_results.beacon_period;

	profile->sec.wpa_versions = sme->crypto.wpa_versions;
	profile->sec.auth_type = sme->auth_type;
	profile->sec.cipher_pairwise = sme->crypto.ciphers_pairwise[0];
	profile->sec.cipher_group = sme->crypto.cipher_group;
	profile->sec.n_ciphers_pairwise = sme->crypto.n_ciphers_pairwise;

	for (i = 0; i < profile->sec.n_ciphers_pairwise; i++)
		profile->sec.ciphers_pairwise[i] =
			sme->crypto.ciphers_pairwise[i];

	wps_ie = wland_find_wpsie(sme->ie, sme->ie_len);
	if (wps_ie && ifp->bssidx == P2PAPI_BSSCFG_PRIMARY) {
		profile->wps_ie = kmalloc(wps_ie->len + 2, GFP_KERNEL);
		if (profile->wps_ie) {
			profile->wps_ie_len = wps_ie->len + 2;
			memcpy(profile->wps_ie, wps_ie, profile->wps_ie_len);
		}
	}

	profile->sec.n_akm_suites = sme->crypto.n_akm_suites;
	for (i = 0; i < profile->sec.n_akm_suites; i++)
		profile->sec.akm_suites[i] = sme->crypto.akm_suites[i];

	profile->sec.wpa_auth = sme->crypto.akm_suites[0];
	profile->sec.security = NO_ENCRYPT;
	profile->sec.firmware_autype = OPEN_SYSTEM;

	if (profile->sec.cipher_pairwise != NO_ENCRYPT) {
		/*
		 * Determine security value: check group cipher suite,
		 * then pairwise suite.
		 */
		if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_2) {
			if (profile->sec.cipher_pairwise ==
			    WLAN_CIPHER_SUITE_TKIP)
				profile->sec.security =
					ENCRYPT_ENABLED | WPA2 | TKIP;
			else if (profile->sec.cipher_pairwise ==
				 WLAN_CIPHER_SUITE_CCMP ||
				 profile->sec.cipher_pairwise ==
				 WLAN_CIPHER_SUITE_AES_CMAC)
				profile->sec.security =
					ENCRYPT_ENABLED | WPA2 | AES;

			if (profile->sec.cipher_group ==
			    WLAN_CIPHER_SUITE_TKIP)
				profile->sec.security_group =
					ENCRYPT_ENABLED | WPA2 | TKIP;
			else if (profile->sec.cipher_group ==
				 WLAN_CIPHER_SUITE_CCMP ||
				 profile->sec.cipher_group ==
				 WLAN_CIPHER_SUITE_AES_CMAC)
				profile->sec.security_group =
					ENCRYPT_ENABLED | WPA2 | AES;
		} else if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_1) {
			if (profile->sec.cipher_pairwise ==
			    WLAN_CIPHER_SUITE_TKIP)
				profile->sec.security =
					ENCRYPT_ENABLED | WPA | TKIP;
			else if (profile->sec.cipher_pairwise ==
				 WLAN_CIPHER_SUITE_CCMP ||
				 profile->sec.cipher_pairwise ==
				 WLAN_CIPHER_SUITE_AES_CMAC)
				profile->sec.security =
					ENCRYPT_ENABLED | WPA | AES;

			if (profile->sec.cipher_group ==
			    WLAN_CIPHER_SUITE_TKIP)
				profile->sec.security_group =
					ENCRYPT_ENABLED | WPA | TKIP;
			else if (profile->sec.cipher_group ==
				 WLAN_CIPHER_SUITE_CCMP ||
				 profile->sec.cipher_group ==
				 WLAN_CIPHER_SUITE_AES_CMAC)
				profile->sec.security_group =
					ENCRYPT_ENABLED | WPA | AES;
		} else {
			if (sme->crypto.cipher_group ==
			    WLAN_CIPHER_SUITE_WEP40) {
				profile->sec.security = ENCRYPT_ENABLED | WEP;
			} else if (sme->crypto.cipher_group ==
				   WLAN_CIPHER_SUITE_WEP104) {
				profile->sec.security =
					ENCRYPT_ENABLED | WEP | WEP_EXTENDED;
			} else {
				netdev_err(ndev, "unsupported cipher suite: 0x%08x\n",
					   sme->crypto.cipher_group);
				err = -ENOTSUPP;
				goto done;
			}

			profile->wepkey_idx = sme->key_idx;
			profile->wepkeys[sme->key_idx].len = (u32) sme->key_len;
			profile->wepkeys[sme->key_idx].index =
				(u32)sme->key_idx;

			if (profile->wepkeys[sme->key_idx].len >
				sizeof(profile->wepkeys[sme->key_idx].data)) {
				netdev_err(ndev, "key length too long: %u\n",
					   profile->wepkeys[sme->key_idx].len);
				err = -EINVAL;
				goto done;
			}

			memcpy(profile->wepkeys[sme->key_idx].data, sme->key,
				profile->wepkeys[sme->key_idx].len);

			profile->wepkeys[sme->key_idx].flags = WL_PRIMARY_KEY;

			switch (profile->sec.cipher_pairwise) {
			case WLAN_CIPHER_SUITE_WEP40:
				profile->wepkeys[sme->key_idx].algo =
					CRYPTO_ALGO_WEP1;
				break;
			case WLAN_CIPHER_SUITE_WEP104:
				profile->wepkeys[sme->key_idx].algo =
					CRYPTO_ALGO_WEP128;
				break;
			default:
				netdev_err(ndev, "invalid cipher algorithm: %d\n",
					   sme->crypto.ciphers_pairwise[0]);
				err = -EINVAL;
				goto done;
			}

			err = wland_add_wep_key_bss_sta(ifp, (u8 *) sme->key,
				(u8) sme->key_len, (u8) sme->key_idx);
			if (err < 0) {
				netdev_err(ndev, "failed to add WEP key: %d\n",
					   err);
				goto done;
			}
		}
	}

	switch (sme->auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
		profile->sec.firmware_autype = OPEN_SYSTEM;
		break;
	case NL80211_AUTHTYPE_SHARED_KEY:
		profile->sec.firmware_autype = SHARED_KEY;
		break;
	default:
		netdev_dbg(ndev, "automatic authentication type: %d\n",
			   sme->auth_type);
		break;
	}

	profile->ssid.SSID_len =
		min_t(u32, (u32) sizeof(profile->ssid.SSID),
		(u32) sme->ssid_len);

	memcpy(&profile->ssid.SSID, sme->ssid, profile->ssid.SSID_len);

	if (profile->ssid.SSID_len < IEEE80211_MAX_SSID_LEN)
		profile->ssid.SSID[profile->ssid.SSID_len] = 0;

	mutex_lock(&cfg->scan_result_lock);
	list_for_each_entry(bss, &cfg->scan_result_list, list) {
		if (memcmp(bss->BSSID, profile->bssid, ETH_ALEN) == 0) {
			conn_info->wmm_enable = bss->wmm_enable;
			conn_info->n_enable = bss->n_enable;
			profile->wmm_enable = bss->wmm_enable;
			break;
		}
	}
	mutex_unlock(&cfg->scan_result_lock);

	netdev_dbg(ndev, "connect: SSID \"%.*s\" BSSID %pM ch %u, 11i 0x%02x, auth %u, wmm %u\n",
		    (int)profile->ssid.SSID_len, profile->ssid.SSID,
		    profile->bssid, profile->channel, profile->sec.security,
		    profile->sec.firmware_autype, profile->wmm_enable);

	wland_wakeup_connect_worker(conn_info);

	mod_timer(&conn_info->timer,
		  jiffies + msecs_to_jiffies(CONNECT_TIMER_MAX));
	conn_info->retry_times = 0;

done:
	if (err < 0) {
		netdev_err(ndev, "failed to connect: %d\n", err);
		clear_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
		if (timer_pending(&conn_info->timer))
			del_timer_sync(&conn_info->timer);
	}
	return err >= 0 ? 0 : err;
}

static void
wland_flush_rx_reorder_msg(struct wland_rx_info *rx_info, const u8 *addr)
{
	struct rx_reorder_msg *reorder_msg, *target_msg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);
	list_for_each_entry(reorder_msg, &rx_info->rx_reorder_msg_list, list) {
		if (!memcmp(reorder_msg->mac_addr, addr, ETH_ALEN)) {
			list_del_init(&reorder_msg->list);
			target_msg = reorder_msg;
			break;
		}
	}
	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
	if (target_msg)
		wland_rx_reorder_msg_deinit(rx_info, target_msg);
}

s32 wland_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
	u16 reason_code)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_scb_val_le scbval;
	struct wland_usb_dev *usb = ifp->drvr->bus_if->bus_priv.usb;
	struct wland_rx_info *rx_info = usb->devinfo->rx_info;
	s32 err = 0;
	int count = 0;

	if (!wland_check_vif_up(ifp->vif)) {
		netdev_dbg(ndev, "interface is down during disconnect\n");
		return 0;
	}

	while (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status)) {
		netdev_dbg(ndev, "waiting for scan to complete (status 0x%lx)\n",
			   cfg->scan_status);
		msleep(100);
		if (count++ > 20) {
			netdev_dbg(ndev, "scan timed out while preparing to disconnect\n");
			break;
		}
	}

	cancel_work_sync(&conn_info->work);
	if (timer_pending(&conn_info->timer)) {
		del_timer_sync(&conn_info->timer);
		msleep(2000);
	}
	cancel_work_sync(&conn_info->connect_fail_work);
	/*
	 * An attempt still in progress is ended by cfg80211 itself once this
	 * returns, so it must not be reported from here.
	 */
	clear_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (timer_pending(&conn_info->connect_restorework_timeout))
		del_timer_sync(&conn_info->connect_restorework_timeout);
	cancel_work_sync(&conn_info->connect_restorework_timeout_work);

	cfg->in_disconnecting = true;

	memcpy(&scbval.ea, &profile->bssid, ETH_ALEN);
	scbval.val = (u8)reason_code;

	if ((ifp->vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif) ||
	    (ifp->vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_CONNECTION].vif)) {
		if (test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state) ||
		    test_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state)) {
			err = wland_p2p_disconnect_bss(ifp, &scbval);
			clear_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
		}
		wland_flush_rx_reorder_msg(rx_info, ifp->mac_addr);
	} else {
		err = wland_disconnect_bss(ifp, &scbval);
	}

	if (err)
		netdev_err(ndev, "failed to send disconnect: %d\n", err);
	else
		msleep(400);

	return err;
}

static s32 wland_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *ndev, u8 key_idx, bool unicast, bool multicast)
{
	u32 index, wsec;
	s32 err = 0;
	struct wland_if *ifp = netdev_priv(ndev);

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	err = wland_fil_iovar_data_get(ifp, "wsec", &wsec, sizeof(u32));
	if (err < 0) {
		netdev_err(ndev, "failed to get wsec: %d\n", err);
		return err;
	}

	if (wsec & WEP_ENABLED) {
		index = key_idx;
		err = wland_fil_iovar_data_set(ifp, "set_key_primary", &index,
			sizeof(u32));
		if (err < 0)
			netdev_err(ndev, "failed to set primary key: %d\n",
				   err);
	}

	return err;
}

static s32 wland_add_ptkey(struct wiphy *wiphy, struct net_device *ndev,
	u8 key_idx, const u8 *mac_addr, struct key_params *params)
{
	struct wland_if *ifp = netdev_priv(ndev);
	enum nl80211_iftype iftype = ifp->ndev->ieee80211_ptr->iftype;
	struct wland_ptkey ptkey;
	s32 err = 0;

	memset(&ptkey, 0, sizeof(ptkey));
	if (!is_multicast_ether_addr(mac_addr))
		memcpy(ptkey.ea, mac_addr, ETH_ALEN);

	if (params->key_len > 0) {
		if (params->key_len > WLAN_MAX_KEY_LEN) {
			netdev_err(ndev, "invalid PTK key length: %d\n",
				   params->key_len);
			return -EINVAL;
		}

		ptkey.ken_len = params->key_len;
		memcpy(ptkey.key, params->key, params->key_len);

		if ((iftype == NL80211_IFTYPE_STATION ||
		     iftype == NL80211_IFTYPE_P2P_CLIENT) &&
		    params->cipher == WLAN_CIPHER_SUITE_TKIP) {
			memcpy(ptkey.key + 16, params->key + 24, 8);
			memcpy(ptkey.key + 24, params->key + 16, 8);
		}
		if (iftype == NL80211_IFTYPE_STATION ||
		    iftype == NL80211_IFTYPE_P2P_CLIENT)
			wland_netdev_wait_pend8021x(ndev);
		err = wland_fil_set_cmd_data(ifp, WID_ADD_PTK, &ptkey,
					     min_t(size_t, sizeof(ptkey),
						   params->key_len +
						   ETH_ALEN + 1));
		netdev_dbg(ndev, "pairwise key %pM cipher 0x%08x len %d: %d\n",
			   mac_addr, params->cipher, params->key_len, err);
		if (err < 0) {
			netdev_err(ndev, "failed to install pairwise key: %d\n",
				   err);
			return err;
		}
	}

	return 0;
}

static s32 wland_add_gtkey(struct wiphy *wiphy, struct net_device *ndev,
	u8 key_idx, struct key_params *params)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_rx_gtkey gtkey;
	s32 err = 0;
	enum nl80211_iftype iftype = ifp->ndev->ieee80211_ptr->iftype;
	size_t gtk_len = min_t(size_t, sizeof(gtkey) -
			       offsetof(struct wland_rx_gtkey, key_idx),
			       params->key_len + 2);

	memset(&gtkey, 0, sizeof(gtkey));
	memcpy(gtkey.ea, profile->bssid, ETH_ALEN);
	if (params->seq_len)
		memcpy(gtkey.keyRSC, params->seq, params->seq_len);
	gtkey.key_idx = key_idx;
	gtkey.ken_len = params->key_len;
	memcpy(gtkey.key, params->key, params->key_len);
	if ((iftype == NL80211_IFTYPE_STATION ||
	     iftype == NL80211_IFTYPE_P2P_CLIENT) &&
	    params->cipher == WLAN_CIPHER_SUITE_TKIP) {
		memcpy(gtkey.key + 16, params->key + 24, 8);
		memcpy(gtkey.key + 24, params->key + 16, 8);
	}

	switch (iftype) {
	case NL80211_IFTYPE_AP:
		err = wland_fil_set_cmd_data(ifp, WID_ADD_TX_GTK,
					     &gtkey.key_idx, gtk_len);
		break;
	case NL80211_IFTYPE_STATION:
		err = wland_fil_set_cmd_data(ifp, WID_ADD_RX_GTK, &gtkey,
					     min_t(size_t, sizeof(gtkey),
						   params->key_len +
						   ETH_ALEN + 10));
		break;
	case NL80211_IFTYPE_P2P_GO:
		err = wland_fil_set_cmd_data(ifp, WID_P2P_TX_GTK,
					     &gtkey.key_idx, gtk_len);
		break;
	case NL80211_IFTYPE_P2P_CLIENT:
		err = wland_fil_set_cmd_data(ifp, WID_P2P_RX_GTK, &gtkey,
					     min_t(size_t, sizeof(gtkey),
						   params->key_len +
						   ETH_ALEN + 10));
		break;
	default:
		return -EOPNOTSUPP;
	}

	netdev_dbg(ndev, "group key idx %u cipher 0x%08x len %d: %d\n",
		   key_idx, params->cipher, params->key_len, err);
	if (err < 0) {
		netdev_err(ndev, "failed to install group key: %d\n", err);
		return err;
	}

	return 0;
}

static s32 wland_cfg80211_add_key(struct wiphy *wiphy, struct net_device *ndev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	struct key_params *params)
{
	struct wland_if *ifp = netdev_priv(ndev);

	/*
	 * These WIDs carry data keys, not WEP or management integrity keys.
	 * CCMP has one 16-byte key; TKIP adds two 8-byte MIC keys, passed in
	 * the order the firmware expects by the helpers below.
	 */
	if (!params || !params->key || key_idx >= DOT11_MAX_DEFAULT_KEYS ||
	    params->seq_len < 0 || params->seq_len > 8 ||
	    (params->seq_len && !params->seq) ||
	    (pairwise && (!mac_addr || !is_valid_ether_addr(mac_addr))))
		return -EINVAL;
	switch (params->cipher) {
	case WLAN_CIPHER_SUITE_CCMP:
		if (params->key_len != 16)
			return -EINVAL;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		if (params->key_len != 32)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	if (pairwise)
		return wland_add_ptkey(wiphy, ndev, key_idx, mac_addr, params);

	return wland_add_gtkey(wiphy, ndev, key_idx, params);
}

static s32 wland_cfg80211_del_key(struct wiphy *wiphy, struct net_device *ndev,
	u8 key_idx, bool pairwise, const u8 *mac_addr)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_wsec_key key;

	if (key_idx >= DOT11_MAX_DEFAULT_KEYS) {
		/*
		 * Supplicant removes IGTK slots 4/5 during teardown, but this
		 * driver cannot install them.
		 */
		if (!pairwise && (key_idx == 4 || key_idx == 5))
			return -ENOENT;
		return -EINVAL;
	}

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	memset(&key, 0, sizeof(key));
	key.index = (u32)key_idx;
	key.flags = WL_PRIMARY_KEY;
	key.algo = CRYPTO_ALGO_OFF;

	netdev_dbg(ndev, "deleting key index %u\n", key_idx);

	return wland_send_key_to_chip(ndev, &key);
}

static s32 wland_cfg80211_get_key(struct wiphy *wiphy, struct net_device *ndev,
	u8 key_idx, bool pairwise, const u8 *mac_addr, void *cookie,
	void (*callback)(void *cookie, struct key_params *params))
{
	struct key_params params;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_cfg80211_security *sec;
	s32 wsec = 0;
	s32 err = 0;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	memset(&params, 0, sizeof(params));

	err = wland_fil_iovar_data_get(ifp, "wsec", &wsec, sizeof(wsec));
	if (err) {
		netdev_err(ndev, "failed to get wsec: %d\n", err);
		/* May happen during disassociation */
		return -EAGAIN;
	}

	if (wsec & WEP_ENABLED) {
		sec = &profile->sec;
		if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP40)
			params.cipher = WLAN_CIPHER_SUITE_WEP40;
		else if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP104)
			params.cipher = WLAN_CIPHER_SUITE_WEP104;
	} else if (wsec & TKIP_ENABLED) {
		params.cipher = WLAN_CIPHER_SUITE_TKIP;
	} else if (wsec & AES_ENABLED) {
		params.cipher = WLAN_CIPHER_SUITE_AES_CMAC;
	} else {
		netdev_err(ndev, "invalid security algorithm: 0x%x\n", wsec);
		return -EINVAL;
	}

	callback(cookie, &params);
	return 0;
}

static s32 wland_cfg80211_config_default_mgmt_key(struct wiphy *wiphy,
	struct net_device *ndev, u8 key_idx)
{
	return -EOPNOTSUPP;
}

static u32 wland_change_data_rate(struct wland_if *ifp, u32 fw_rate)
{
	static const s32 rate_ht20_longGI[8] = {
		65, 130, 195, 260, 390, 520, 585, 650
	};
	static const s32 rate_ht20_shortGI[8] = {
		72, 144, 217, 289, 433, 578, 650, 722
	};
	static const s32 rate_ht40_longGI[8] = {
		135, 270, 405, 540, 810, 1080, 1215, 1350
	};
	static const s32 rate_ht40_shortGI[8] = {
		150, 300, 450, 600, 900, 1200, 1350, 1500
	};
	u8 rate, flag;

	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY) {
		/* The primary interface reports in bytes 0-1, others in 2-3 */
		rate = fw_rate & 0xff;
		flag = (fw_rate & 0xff00) >> 8;
	} else {
		rate = (fw_rate & 0xff0000) >> 16;
		flag = (fw_rate & 0xff000000) >> 24;
	}

	if ((rate & BIT7) == 0) {	/* 11b/g */
		if (rate == 5)
			return 55;
		if (rate == 2 || rate == 6 || rate == 9 || rate == 11 ||
		    rate == 12 || rate == 18 || rate == 24 || rate == 36 ||
		    rate == 48 || rate == 54)
			return rate * 10;
		if (rate != 1) {
			netdev_dbg(ifp->ndev, "invalid 11b/g rate: %u\n", rate);
			return 0;
		}
	} else {	/* 11n MCS */
		rate &= 0x3f;
		if (rate > 7) {
			netdev_err(ifp->ndev,
				   "invalid 11n rate %u (flag 0x%x)\n",
				   rate, flag);
			return 0;
		}
		/* flag bit 0: HT40, bit 1: short GI */
		if ((flag & BIT0) == 0)
			return (flag & BIT1) ? rate_ht20_shortGI[rate] :
					       rate_ht20_longGI[rate];
		return (flag & BIT1) ? rate_ht40_shortGI[rate] :
				       rate_ht40_longGI[rate];
	}
	return 0;
}

static s32 wland_cfg80211_get_station(
	struct wiphy *wiphy, struct net_device *ndev,
	const u8 *mac, struct station_info *sinfo)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	u16 rssi_u = 0;
	s16 rssi = 0;
	struct wland_bus *bus_if = ifp->drvr->bus_if;
	struct wland_usbdev_info *devinfo = bus_if->bus_priv.usb->devinfo;
	s32 rate = 0, err = 0;
	u8 *bssid = profile->bssid;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	if (ifp->vif->mode == WL_MODE_AP) {
		struct wland_sta_info_le *sta_info_le;

		sta_info_le = kzalloc(sizeof(*sta_info_le), GFP_KERNEL);
		if (!sta_info_le)
			return -ENOMEM;

		memcpy(sta_info_le->ea, mac, ETH_ALEN);

		err = wland_fil_iovar_data_get(ifp, "sta_info", sta_info_le,
			sizeof(struct wland_sta_info_le));
		if (err < 0) {
			netdev_err(ndev, "failed to get STA info: %d\n", err);
			kfree(sta_info_le);
			return 0;
		}

		sinfo->filled = BIT_ULL(NL80211_STA_INFO_INACTIVE_TIME);
		sinfo->inactive_time = le32_to_cpu(sta_info_le->idle) * 1000;

		if (le32_to_cpu(sta_info_le->flags) & WLAND_STA_ASSOC) {
			sinfo->filled |=
				BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME);
			sinfo->connected_time = le32_to_cpu(sta_info_le->in);
		}
		netdev_dbg(ndev, "STA idle %u ms, connected %u s\n",
			   sinfo->inactive_time, sinfo->connected_time);
		kfree(sta_info_le);
	} else if (ifp->vif->mode == WL_MODE_BSS) {
		if (!test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state)) {
			netdev_dbg(ndev, "network not connected (sme_state 0x%lx)\n",
				   ifp->vif->sme_state);
			/* A query is not a link event; cfg80211 must not be
			 * told the link dropped from here.
			 */
			return -ENOENT;
		}
		if (memcmp(mac, bssid, ETH_ALEN)) {
			netdev_err(ndev, "station MAC mismatch: target %pM, connected %pM\n",
				   mac, bssid);
			return -ENOENT;
		}

		if (devinfo->tx_freecount == WLAND_USB_NTXQ) {
			err = wland_fil_get_cmd_data(ifp, WID_GET_TX_RATE,
						     &rate, sizeof(rate));
			if (err < 0) {
				netdev_err(ndev, "failed to get tx rate: %d\n",
					   err);
			} else {
				rate = wland_change_data_rate(ifp, rate);
				if (rate != 0) {
					sinfo->filled |= BIT_ULL(
						NL80211_STA_INFO_TX_BITRATE);
					sinfo->txrate.legacy =
						rate < 540 ? 540 : rate;
					netdev_dbg(ndev,
						   "TX rate: %d (100 kbps)\n",
						   rate);
				}
			}

			err = wland_fil_get_cmd_data(ifp, WID_RSSI,
						     &rssi_u, sizeof(rssi));
			if (err < 0) {
				netdev_err(ndev, "failed to get RSSI: %d\n",
					   err);
			} else {
				rssi = (signed char)rssi_u;
				sinfo->filled |=
					BIT_ULL(NL80211_STA_INFO_SIGNAL);
				sinfo->signal = rssi;
				netdev_dbg(ndev, "RSSI: %d dBm\n", rssi);
			}
		}

		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_BYTES) |
				 BIT_ULL(NL80211_STA_INFO_TX_PACKETS) |
				 BIT_ULL(NL80211_STA_INFO_RX_BYTES) |
				 BIT_ULL(NL80211_STA_INFO_RX_PACKETS);
		sinfo->tx_bytes = ifp->stats.tx_bytes;
		sinfo->tx_packets = ifp->stats.tx_packets;
		sinfo->rx_bytes = ifp->stats.rx_bytes;
		sinfo->rx_packets = ifp->stats.rx_packets;
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_FAILED);
		sinfo->tx_failed = ifp->stats.tx_dropped;
	}

	return 0;
}

static s32 wland_set_fw_power_save(struct wland_if *ifp, bool enabled)
{
	u8 pm = enabled ? MIN_FAST_PS : NO_POWERSAVE;

	/* power save is never enabled for P2P clients */
	if (ifp->vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT)
		pm = NO_POWERSAVE;

	netdev_dbg(ifp->ndev, "firmware power save mode %u\n", pm);
	return wland_fil_set_cmd_data(ifp, WID_POWER_MANAGEMENT, &pm,
				      sizeof(pm));
}

/*
 * Re-send the requested power save state; the firmware does not keep it
 * across a restart. Nothing is sent while power save is off, which is the
 * firmware default.
 */
static void wland_restore_power_save(struct wland_if *ifp)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	s32 err;

	if (!cfg->pwr_save)
		return;

	err = wland_set_fw_power_save(ifp, true);
	if (err < 0)
		netdev_warn(ifp->ndev, "failed to restore power save: %d\n",
			    err);
}

static s32 wland_cfg80211_set_power_mgmt(struct wiphy *wiphy,
	struct net_device *ndev, bool enabled, s32 timeout)
{
	s32 err = 0;
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);

	/*
	 * A request may arrive before the interface is up; the state is then
	 * kept and applied when the interface comes up.
	 */
	if (wland_check_vif_up(ifp->vif)) {
		err = wland_set_fw_power_save(ifp, enabled);
		if (err < 0) {
			netdev_err(ndev, "failed to set power save: %d\n", err);
			return err;
		}
	}
	cfg->pwr_save = enabled;

	return err;
}

static struct wland_bss_info_le *wland_alloc_bss(
	struct wland_cfg80211_info *cfg, struct wland_bss_info_le *old)
{
	struct wland_bss_info_le *bss;

	bss = kmemdup(old, sizeof(struct wland_bss_info_le), GFP_KERNEL);
	if (!bss)
		return ERR_PTR(-ENOMEM);

	list_add_tail(&bss->list, &cfg->scan_result_list);
	cfg->scan_results.count++;

	return bss;
}

static void wland_free_bss(struct wland_cfg80211_info *cfg,
	struct wland_bss_info_le *bss)
{
	list_del(&bss->list);
	if (cfg->scan_results.count == 0)
		wiphy_dbg(cfg->wiphy, "scan result count underflow\n");
	cfg->scan_results.count--;

	kfree(bss->ie);
	kfree(bss);
}

static u64 wland_get_systime_us(void)
{
	return ktime_to_us(ktime_get_boottime());
}

static s32 wland_inform_single_bss(struct wland_cfg80211_info *cfg,
	struct wland_bss_info_le *bi)
{
	struct cfg80211_scan_request *request = cfg->scan_request;
	struct wland_cfg80211_vif *vif;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct ieee80211_channel *notify_channel;
	struct cfg80211_bss *bss;
	struct ieee80211_supported_band *band =
		wiphy->bands[NL80211_BAND_2GHZ];
	struct wland_chan ch;
	s32 notify_signal;
	u16 channel;
	u32 freq;
	u8 *notify_ie;
	u64 notify_timestamp;

	vif = cfg->scan_info.ifp->vif;

	if (!request &&
	    !test_bit(VIF_STATUS_CONNECTING, &vif->sme_state)) {
		wiphy_dbg(wiphy, "ignoring BSS outside scan period\n");
		return 0;
	}

	if (vif != bi->vif) {
		wiphy_dbg(wiphy, "skipping BSS \"%s\" from another vif\n",
			  bi->SSID);
		return 0;
	}
	if (bi->length > WLAND_BSS_INFO_MAX) {
		wiphy_err(wiphy,
			  "BSS info length %u exceeds buffer limit %d, discarding\n",
			  bi->length, WLAND_BSS_INFO_MAX);
		return 0;
	}

	if (!bi->ctl_ch) {
		ch.chspec = bi->chanspec;
		cfg->d11inf.decchspec(&ch);
		bi->ctl_ch = ch.chnum;
	}
	channel = bi->ctl_ch;

	if (channel <= CH_MAX_2G_CHANNEL)
		band = wiphy->bands[NL80211_BAND_2GHZ];
	else
		return 0;	/* not a 2.4 GHz channel (1-14) */

	freq = ieee80211_channel_to_frequency(channel, band->band);
	notify_channel = ieee80211_get_channel(wiphy, freq);
	notify_ie = bi->ie;
	notify_signal = bi->RSSI * 100;

	wiphy_dbg(wiphy,
		  "BSS \"%s\" BSSID %pM ch %u (%u MHz) cap 0x%x bcn %u sig %d\n",
		  bi->SSID, bi->BSSID, channel, freq, bi->capability,
		  bi->beacon_period, notify_signal);

	notify_timestamp = wland_get_systime_us();

	bss = cfg80211_inform_bss(wiphy,
		notify_channel,
		CFG80211_BSS_FTYPE_UNKNOWN,
		(const u8 *) bi->BSSID,
		notify_timestamp, bi->capability, bi->beacon_period,
		notify_ie, (size_t) bi->ie_length, notify_signal, GFP_KERNEL);

	if (!bss)
		return -ENOMEM;

	cfg80211_put_bss(wiphy, bss);

	return 0;
}

static s32 wland_inform_bss(struct wland_cfg80211_info *cfg)
{
	struct wland_bss_info_le *bss, *bss_temp;
	s32 err = 0;

	if (!cfg->scan_request) {
		wiphy_dbg(cfg->wiphy, "ignoring BSS report outside scan period\n");
		return 0;
	}

	mutex_lock(&cfg->scan_result_lock);

	wiphy_dbg(cfg->wiphy, "reporting %u scanned BSS entries\n",
		  cfg->scan_results.count);
	list_for_each_entry_safe(bss, bss_temp, &cfg->scan_result_list, list) {
		err = wland_inform_single_bss(cfg, bss);
		if (err < 0) {
			wiphy_dbg(cfg->wiphy,
				  "failed to inform single BSS: %d\n", err);
			continue;
		}
		if (time_before(bss->time, jiffies -
				msecs_to_jiffies(SCAN_TIMER2_INTERVAL_MS))) {
			wiphy_dbg(cfg->wiphy,
				  "expiring BSS \"%s\" after %d ms\n",
				  bss->SSID, SCAN_TIMER2_INTERVAL_MS);
			wland_free_bss(cfg, bss);
			continue;
		}
	}

	mutex_unlock(&cfg->scan_result_lock);

	return err;
}

static s32 wland_inform_ibss(struct wland_cfg80211_info *cfg,
	struct net_device *ndev, const u8 *bssid)
{
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct ieee80211_channel *notify_channel;
	struct wland_bss_info_le *bi = NULL;
	struct ieee80211_supported_band *band;
	struct cfg80211_bss *bss;
	struct wland_chan ch;
	u8 *buf = NULL;
	s32 err = 0;
	u32 freq;
	const u8 *notify_ie;
	s32 notify_signal;

	buf = kzalloc(WLAND_BSS_INFO_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	*(__le32 *) buf = cpu_to_le32(WLAND_BSS_INFO_MAX);
	err = wland_fil_iovar_data_get(netdev_priv(ndev), "get_bss_info",
		buf, WLAND_BSS_INFO_MAX);
	if (err < 0) {
		netdev_err(ndev, "failed to get BSS info: %d\n", err);
		goto cleanup;
	}

	bi = (struct wland_bss_info_le *) (buf + 4);

	ch.chspec = le16_to_cpu(bi->chanspec);
	cfg->d11inf.decchspec(&ch);

	band = wiphy->bands[NL80211_BAND_2GHZ];

	freq = ieee80211_channel_to_frequency(ch.chnum, band->band);
	notify_channel = ieee80211_get_channel(wiphy, freq);
	notify_ie = (const u8 *)(bi->ie);
	notify_signal = bi->RSSI * 100;

	netdev_dbg(ndev, "IBSS ch %u (%u MHz) cap 0x%x bcn %u sig %d\n",
		   ch.chnum, freq, bi->capability, bi->beacon_period,
		   notify_signal);

	bss = cfg80211_inform_bss(wiphy,
		notify_channel,
		CFG80211_BSS_FTYPE_UNKNOWN,
		bssid, 0, bi->capability,
		bi->beacon_period,
		notify_ie, (size_t) bi->ie_length, notify_signal, GFP_KERNEL);

	if (!bss) {
		err = -ENOMEM;
		goto cleanup;
	}
	cfg80211_put_bss(wiphy, bss);

cleanup:
	kfree(buf);
	return err;
}

void wland_abort_scanning(struct wland_cfg80211_info *cfg)
{
	struct wland_scan_info *escan = &cfg->scan_info;

	if (timer_pending(&cfg->scan_timeout))
		del_timer_sync(&cfg->scan_timeout);

	cancel_work_sync(&cfg->scan_report_work);

	set_bit(SCAN_STATUS_ABORT, &cfg->scan_status);

	if (cfg->scan_request) {
		escan->escan_state = SCAN_STATE_IDLE;
		wland_notify_escan_complete(cfg, escan->ifp, true, true);
	}

	wland_clear_scan_busy(cfg);
	clear_bit(SCAN_STATUS_ABORT, &cfg->scan_status);
}

static void wland_cfg80211_scan_report_worker(struct work_struct *work)
{
	struct wland_cfg80211_info *cfg =
		container_of(work, struct wland_cfg80211_info,
			     scan_report_work);

	wland_notify_escan_complete(cfg, cfg->scan_info.ifp, false, true);
}

static s32 wland_reset_firmware(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	netdev_dbg(ifp->ndev, "firmware reset event: status %u\n", e->status);
	return 0;
}

static void wland_scan_timeout(struct timer_list *t)
{
	struct wland_cfg80211_info *cfg = from_timer(cfg, t, scan_timeout);
	struct wland_event_msg event;

	memset(&event, '\0', sizeof(struct wland_event_msg));

	event.event_code = WLAND_E_ESCAN_RESULT;
	event.status = STATUS_FAILED;
	wland_fweh_push_event(cfg->pub, &event, NULL);
}

static s32 wland_wakeup_connect_worker(struct wland_cfg80211_connect_info
	*conn_info)
{
	queue_work(conn_info->connect_wq, &conn_info->work);
	return 0;
}

/* The attempt took too long; fail it from process context. */
static void wland_connect_timer(struct timer_list *t)
{
	struct wland_cfg80211_connect_info *conn_info =
		from_timer(conn_info, t, timer);

	schedule_work(&conn_info->connect_fail_work);
}

static void wland_cfg80211_connect_fail_worker(struct work_struct *work)
{
	struct wland_cfg80211_connect_info *conn_info =
		container_of(work, struct wland_cfg80211_connect_info,
			     connect_fail_work);
	struct wland_if *ifp = netdev_priv(conn_info->ndev);
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_scb_val_le scbval;

	if (!test_bit(VIF_STATUS_CONNECTING, &vif->sme_state))
		return;

	/* stop the firmware from joining after cfg80211 was told it failed */
	memset(&scbval, 0, sizeof(scbval));
	memcpy(scbval.ea, vif->profile.bssid, ETH_ALEN);
	scbval.val = WLAN_REASON_UNSPECIFIED;
	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY)
		wland_disconnect_bss(ifp, &scbval);
	else
		wland_p2p_disconnect_bss(ifp, &scbval);

	wland_connect_failed(vif, 0, true);
}

static void wland_cfg80211_connect_worker(struct work_struct *work)
{
	struct wland_cfg80211_connect_info *conn_info =
		container_of(work, struct wland_cfg80211_connect_info, work);
	int err = -1;
	struct wland_if *ifp = netdev_priv(conn_info->ndev);
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;

	/* Connect WEP_AP with shared_key or open_system */
	if (profile->sec.security & (WEP | WEP_EXTENDED)) {
		if (profile->sec.firmware_autype == OPEN_SYSTEM)
			profile->sec.firmware_autype = SHARED_KEY;
		else
			profile->sec.firmware_autype = OPEN_SYSTEM;
	}

	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY) {
		if (profile->wps_ie_len) {
			netdev_dbg(ifp->ndev, "STA WPS connect\n");
			wland_fil_set_cmd_data(ifp, WID_STA_VNDR_IE,
					       profile->wps_ie,
					       profile->wps_ie_len);
		}
		err = wland_start_join(ifp, profile);
	} else {
		err = wland_p2p_start_join(ifp, profile);
	}
	if (err)
		netdev_err(ifp->ndev, "failed to initiate join: %d\n", err);
}

static void wland_connect_restorework_timeout(struct timer_list *t)
{
	struct wland_cfg80211_connect_info *conn_info =
		from_timer(conn_info, t, connect_restorework_timeout);

	schedule_work(&conn_info->connect_restorework_timeout_work);
}

s32 wland_set_mcs(struct wland_if *ifp, u8 value)
{
	s32 err;

	err = wland_fil_set_cmd_data(ifp, WID_11N_CURRENT_TX_MCS, &value,
				     sizeof(value));
	if (err)
		netdev_err(ifp->ndev, "failed to set TX MCS to %u: %d\n",
			   value, err);

	return 0;
}

static void
wland_cfg80211_connect_restorework_timeout_worker(struct work_struct *work)
{
	struct wland_cfg80211_connect_info *conn_info =
		container_of(work, struct wland_cfg80211_connect_info,
		connect_restorework_timeout_work);
	struct wland_if *ifp = netdev_priv(conn_info->ndev);

	if (timer_pending(&conn_info->connect_restorework_timeout))
		del_timer_sync(&conn_info->connect_restorework_timeout);

	if (ifp->vif->mode == WL_MODE_BSS) {
		wland_set_mcs(ifp, 0);
		wland_set_txrate(ifp, 0);
	}
}

static s32 wland_init_connect_info(struct wland_cfg80211_info *cfg)
{
	int i;
	struct wland_cfg80211_vif *vif;
	struct wland_cfg80211_connect_info *conn_info;
	int err = 0;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		conn_info = &vif->conn_info;
		atomic_set(&conn_info->tid_map, 0);
		for (i = 0; i < 8; ++i) {
			conn_info->tid_jiffies[i] = jiffies;
			conn_info->tid_num[i] = 0;
		}
		conn_info->ndev = cfg_to_ndev(cfg);
		timer_setup(&conn_info->timer, wland_connect_timer, 0);
		conn_info->timer_on = false;
		INIT_WORK(&conn_info->work, wland_cfg80211_connect_worker);
		INIT_WORK(&conn_info->connect_fail_work,
			  wland_cfg80211_connect_fail_worker);
		spin_lock_init(&conn_info->sta_info_lock);
		memset(&conn_info->ba, 0, sizeof(conn_info->ba));
		INIT_LIST_HEAD(&conn_info->sta_info_list);

		timer_setup(&conn_info->connect_restorework_timeout,
			wland_connect_restorework_timeout, 0);
		INIT_WORK(&conn_info->connect_restorework_timeout_work,
			wland_cfg80211_connect_restorework_timeout_worker);

		conn_info->data = cfg;

		conn_info->connect_wq =
			create_singlethread_workqueue("connect_wq");
		if (!conn_info->connect_wq) {
			wiphy_err(cfg->wiphy,
				  "failed to allocate connect workqueue\n");
			err = -ENOMEM;
			break;
		}
	}

	return err;
}

static s32 wland_deinit_connect_info(struct wland_cfg80211_info *cfg)
{
	struct wland_cfg80211_vif *vif;
	struct wland_cfg80211_connect_info *conn_info;
	struct wland_sta_info *sta_info, *sta_info_tmp;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		conn_info = &vif->conn_info;

		if (timer_pending(&conn_info->timer))
			del_timer_sync(&conn_info->timer);
		if (timer_pending(&conn_info->connect_restorework_timeout))
			del_timer_sync(&conn_info->connect_restorework_timeout);

		cancel_work_sync(&conn_info->work);
		cancel_work_sync(&conn_info->connect_fail_work);
		if (conn_info->connect_wq)
			destroy_workqueue(conn_info->connect_wq);

		cancel_work_sync(&conn_info->connect_restorework_timeout_work);

		spin_lock_bh(&conn_info->sta_info_lock);
		list_for_each_entry_safe(sta_info, sta_info_tmp,
					 &conn_info->sta_info_list, list) {
			wiphy_dbg(cfg->wiphy,
				  "freeing station: AID %u, MAC %pM\n",
				  sta_info->aid, sta_info->mac_addr);
			list_del(&sta_info->list);
			kfree(sta_info->assoc_req_ie);
			kfree(sta_info);
		}
		spin_unlock_bh(&conn_info->sta_info_lock);

		kfree(conn_info->req_ie);
		conn_info->req_ie = NULL;
		conn_info->req_ie_len = 0;
		kfree(conn_info->resp_ie);
		conn_info->resp_ie = NULL;
		conn_info->resp_ie_len = 0;
	}

	return 0;
}

static bool wland_compare_update_same_bss(struct wland_bss_info_le *bss,
	struct wland_bss_info_le *new_bss)
{
	struct list_head *p_next, *p_prev;
	s8 RSSI = bss->RSSI;

	if (ether_addr_equal(bss->BSSID, new_bss->BSSID) &&
	    bss->vif == new_bss->vif) {
		/*
		 * Preserve max RSSI if measurements are both on-channel
		 * or both off-channel.
		 */
		kfree(bss->ie);

		p_next = bss->list.next;
		p_prev = bss->list.prev;
		memcpy(bss, new_bss, sizeof(struct wland_bss_info_le));
		bss->RSSI = max(RSSI, bss->RSSI);
		bss->list.next = p_next;
		bss->list.prev = p_prev;

		return true;
	}
	return false;
}

static void wland_parse_network_info(struct wland_bss_info_le *bi, u8 *data)
{
	u8 msg_type = 0, msg_id = 0, index = 0, len;
	u16 msg_len = 0, wid_id = 0, wid_len = 0, msa_len;
	const u8 *ie;
	u8 *p_wid_val;
	u16 ie_index = MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN +
		CAP_INFO_LEN;
	msg_type = data[0];

	if (('N' != msg_type) || (!bi)) {
		pr_err("invalid network info message format\n");
		return;
	}

	/*
	 * Layout: type 'N', message ID, 16-bit message length, 16-bit WID,
	 * 16-bit WID length, then the WID value: one RSSI byte followed by
	 * the received beacon or probe response frame.
	 */
	msg_id = data[1];
	msg_len = MAKE_WORD16(data[2], data[3]);
	wid_id = MAKE_WORD16(data[4], data[5]);
	wid_len = MAKE_WORD16(data[6], data[7]);

	pr_debug("msg_id %u, msg_len %u, wid_id 0x%04x, wid_len %u\n",
		 msg_id, msg_len, wid_id, wid_len);

	bi->RSSI = (signed char)(data[8]);
	p_wid_val = &data[9];

	/*
	 * wland_handle_async_info() checked that the frame fits the message.
	 * Leaving ctl_ch at 0 drops a frame without its fixed fields and SSID.
	 */
	msa_len = wid_len - 1;
	if (msa_len < ie_index + 2 ||
	    p_wid_val[ie_index + 1] > msa_len - ie_index - 2) {
		pr_err("network info frame too short: %u\n", msa_len);
		return;
	}

	bi->capability = wland_get_cap_info(p_wid_val);
	wland_get_ssid(p_wid_val, bi->SSID, &(bi->SSID_len));
	wland_get_BSSID(p_wid_val, bi->BSSID);

	bi->wmm_enable = !!wland_find_wmmie(p_wid_val + ie_index,
					    msa_len - ie_index);
	bi->n_enable = !!wland_parse_tlvs(p_wid_val + ie_index,
					  msa_len - ie_index,
					  WLAN_EID_HT_CAPABILITY);

	ie = cfg80211_find_ie(WLAN_EID_DS_PARAMS, p_wid_val + ie_index,
			      msa_len - ie_index);
	if (ie && ie[1] >= 1)
		bi->ctl_ch = ie[2];

	ie = cfg80211_find_ie(WLAN_EID_SUPP_RATES, p_wid_val + ie_index,
			      msa_len - ie_index);
	if (ie) {
		bi->rateset.count = min_t(u8, MAX_RATES, ie[1]);
		memcpy(bi->rateset.rates, ie + 2, bi->rateset.count);
	}

	ie = cfg80211_find_ie(WLAN_EID_EXT_SUPP_RATES, p_wid_val + ie_index,
			      msa_len - ie_index);
	if (ie) {
		len = min_t(u8, MAX_RATES - bi->rateset.count, ie[1]);
		memcpy(bi->rateset.rates + bi->rateset.count, ie + 2, len);
		bi->rateset.count += len;
	}

	index = (MAC_HDR_LEN + TIME_STAMP_LEN);

	bi->beacon_period = wland_get_beacon_period(p_wid_val + index);

	index += BEACON_INTERVAL_LEN + CAP_INFO_LEN;

	/* The DTIM period follows the DTIM count in the TIM element */
	ie = cfg80211_find_ie(WLAN_EID_TIM, p_wid_val + ie_index,
			      msa_len - ie_index);
	if (ie && ie[1] >= 2)
		bi->dtim_period = ie[3];

	if (msa_len < index) {
		pr_err("network info frame too short: %u\n", msa_len);
		return;
	}
	bi->ie_length = msa_len - index;
	bi->length = sizeof(struct wland_bss_info_le);
	bi->ie = kmalloc(bi->ie_length, GFP_KERNEL);
	if (!bi->ie)
		return;
	memcpy(bi->ie, &p_wid_val[index], bi->ie_length);
}

static s32 wland_notify_escan_handler(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct cfg80211_scan_request *request = cfg->scan_request;
	struct wland_cfg80211_vif *vif = cfg->scan_info.ifp->vif;
	struct wland_bss_info_le *bss = NULL;
	struct wland_bss_info_le bss_info_le = {};
	struct wland_bss_info_le *new_bss;
	s32 err = 0;

	ifp = vif->ifp;

	if (!wland_check_vif_up(vif))
		goto exit;

	if (e->status == STATUS_SUCCESS) {
		if (!data) {
			netdev_err(ifp->ndev,
				   "invalid escan result: null payload\n");
			goto exit;
		}

		wland_parse_network_info(&bss_info_le, (u8 *) data);
		if (bss_info_le.ctl_ch == 0) {
			netdev_err(ifp->ndev,
				   "failed to get BSS channel number\n");
			goto exit;
		}

		if (bss_info_le.SSID_len == 0) {
			netdev_dbg(ifp->ndev, "empty SSID, skipping BSS\n");
			goto exit;
		}
		if (bss_info_le.ctl_ch == 14 &&
		    cfg->pub->country_code != SITE_SURVEY_ALL_CH) {
			netdev_dbg(ifp->ndev, "skipping channel 14 BSS\n");
			goto exit;
		}

		if (wland_p2p_scan_finding_common_channel(cfg, &bss_info_le))
			goto exit;

		if (!request) {
			netdev_dbg(ifp->ndev,
				   "received BSS outside scan period\n");
			goto exit;
		}

		if (((char *)data)[9] == PROBE_RSP &&
		    memcmp(data + 13, vif->ifp->mac_addr, ETH_ALEN) &&
		    ifp->bssidx != P2PAPI_BSSCFG_PRIMARY) {
			netdev_dbg(ifp->ndev,
				   "P2P dropping foreign probe response\n");
			goto exit;
		}
		if (!(cfg_to_wiphy(cfg)->interface_modes &
				BIT(NL80211_IFTYPE_ADHOC))) {
			if (bss_info_le.capability & CAPABILITY_IBSS) {
				netdev_dbg(ifp->ndev,
					   "ignoring IBSS result (SSID \"%s\")\n",
					   bss_info_le.SSID);
				goto exit;
			}
		}
		bss_info_le.vif = vif;

		mutex_lock(&cfg->scan_result_lock);
		list_for_each_entry(bss, &cfg->scan_result_list, list) {
			if (wland_compare_update_same_bss(bss, &bss_info_le)) {
				bss->time = jiffies;
				mutex_unlock(&cfg->scan_result_lock);
				/* The cached entry now owns the elements */
				bss_info_le.ie = NULL;
				goto exit;
			}
		}

		cfg->scan_results.beacon_period = bss_info_le.beacon_period;
		bss_info_le.time = jiffies;

		new_bss = wland_alloc_bss(cfg, &bss_info_le);
		if (IS_ERR(new_bss)) {
			err = PTR_ERR(new_bss);
		} else {
			bss_info_le.ie = NULL;
			netdev_dbg(ifp->ndev, "new BSS %pM ch %u RSSI %d SSID \"%.*s\"\n",
				    bss_info_le.BSSID, bss_info_le.ctl_ch,
				    bss_info_le.RSSI,
				    (int)min_t(u32, bss_info_le.SSID_len,
					       IEEE80211_MAX_SSID_LEN),
				    bss_info_le.SSID);
		}
		mutex_unlock(&cfg->scan_result_lock);

	} else {
		if (cfg->scannum) {
			cfg->ctrl_scan_wait = false;
			wland_wait_event_scancmp_wakeup(cfg);
			return 0;
		}
		if (timer_pending(&cfg->scan_timeout))
			del_timer_sync(&cfg->scan_timeout);

		netdev_dbg(ifp->ndev, "scan done: status %u, %u BSS cached\n",
			    e->status, cfg->scan_results.count);

		cfg->scan_info.escan_state = SCAN_STATE_IDLE;

		if (cfg->scan_request && cfg->scannum == 0)
			wland_inform_bss(cfg);
		else
			netdev_dbg(ifp->ndev,
				   "ignoring scan result: status 0x%x\n",
				   e->status);

		wland_p2p_scan_finding_common_channel(cfg, NULL);

		if (timer_pending(&cfg->scan_timeout))
			del_timer_sync(&cfg->scan_timeout);

		wland_clear_scan_busy(cfg);
		if (cfg->scan_request)
			schedule_work(&cfg->scan_report_work);
	}

exit:
	kfree(bss_info_le.ie);
	return err;
}

static s32 wland_cfg80211_resume(struct wiphy *wiphy)
{
	return 0;
}

static s32 wland_cfg80211_suspend(struct wiphy *wiphy,
				  struct cfg80211_wowlan *wow)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = cfg_to_ndev(cfg);
	struct wland_cfg80211_vif *vif = ndev_to_vif(ndev);

	/* Nothing to quiesce if the primary interface is not up */
	if (!wland_check_vif_up(vif))
		goto exit;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		if (!test_bit(VIF_STATUS_READY, &vif->sme_state))
			continue;
		/* Let pending firmware events reach the supplicant */
		wland_delay(200);
	}
	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
		wland_abort_scanning(cfg);

exit:
	cfg->scan_status = 0;
	return 0;
}

static __used s32 wland_update_pmklist(struct net_device *ndev,
	struct wland_cfg80211_pmk_list *pmk_list, s32 err)
{
	int pmkid_len = le32_to_cpu(pmk_list->pmkids.npmkid);

	netdev_dbg(ndev, "updating %d PMKID entries\n", pmkid_len);

	if (!err)
		wland_fil_iovar_data_set(netdev_priv(ndev), "pmkid_info",
			(char *) pmk_list, sizeof(*pmk_list));

	return err;
}

static s32 wland_cfg80211_set_pmksa(struct wiphy *wiphy,
				     struct net_device *ndev,
				     struct cfg80211_pmksa *pmksa)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct pmkid_list *pmkids = &cfg->pmk_list->pmkids;
	s32 err = 0;
	int i, pmkid_len;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	pmkid_len = le32_to_cpu(pmkids->npmkid);

	for (i = 0; i < pmkid_len; i++) {
		if (!memcmp(pmksa->bssid, pmkids->pmkid[i].BSSID, ETH_ALEN))
			break;
	}
	if (i < MAXPMKID) {
		memcpy(pmkids->pmkid[i].BSSID, pmksa->bssid, ETH_ALEN);
		memcpy(pmkids->pmkid[i].PMKID, pmksa->pmkid, WLAN_PMKID_LEN);
		netdev_dbg(ndev, "adding PMKID for %pM\n", pmksa->bssid);

		if (i == pmkid_len) {
			pmkid_len++;
			pmkids->npmkid = cpu_to_le32(pmkid_len);
		}
	} else {
		err = -EINVAL;
	}

	return wland_update_pmklist(ndev, cfg->pmk_list, err);
}

static s32 wland_cfg80211_del_pmksa(struct wiphy *wiphy,
				     struct net_device *ndev,
				     struct cfg80211_pmksa *pmksa)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	s32 err = 0;
	int i, pmkid_len;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	netdev_dbg(ndev, "removing PMKID for %pM\n", pmksa->bssid);

	pmkid_len = le32_to_cpu(cfg->pmk_list->pmkids.npmkid);

	for (i = 0; i < pmkid_len; i++)
		if (!memcmp(pmksa->bssid, &cfg->pmk_list->pmkids.pmkid[i].BSSID,
				ETH_ALEN))
			break;

	if ((pmkid_len > 0) && (i < pmkid_len)) {
		memset(&cfg->pmk_list->pmkids.pmkid[i], 0,
			sizeof(struct pmkid));

		for (; i < (pmkid_len - 1); i++) {
			memcpy(&cfg->pmk_list->pmkids.pmkid[i].BSSID,
			       &cfg->pmk_list->pmkids.pmkid[i + 1].BSSID,
			       ETH_ALEN);
			memcpy(&cfg->pmk_list->pmkids.pmkid[i].PMKID,
			       &cfg->pmk_list->pmkids.pmkid[i + 1].PMKID,
			       WLAN_PMKID_LEN);
		}
		cfg->pmk_list->pmkids.npmkid = cpu_to_le32(pmkid_len - 1);
	} else {
		err = -EINVAL;
	}

	return wland_update_pmklist(ndev, cfg->pmk_list, err);
}

static s32 wland_cfg80211_flush_pmksa(struct wiphy *wiphy,
				       struct net_device *ndev)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	memset(cfg->pmk_list, 0, sizeof(struct wland_cfg80211_pmk_list));

	return wland_update_pmklist(ndev, cfg->pmk_list, 0);
}

/*
 * A PNO result lacks the IEs the supplicant needs, so build a scan request
 * from the event and run a targeted escan that reports full BSS entries.
 */
static s32 wland_notify_sched_scan_results(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_pno_net_info_le *netinfo, *netinfo_start;
	struct cfg80211_scan_request *request = NULL;
	struct cfg80211_ssid *ssid = NULL;
	struct ieee80211_channel *channel = NULL;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct wland_pno_scanresults_le *pfn_result =
		(struct wland_pno_scanresults_le *) data;
	s32 err = 0, channel_req = 0, band = 0;

	/*
	 * A PNO event is limited to 512 bytes, so results may span several
	 * NET_FOUND events; only a single complete event is handled.
	 */
	WARN_ON(pfn_result->status != WLAND_PNO_SCAN_COMPLETE);

	netdev_dbg(ifp->ndev, "PFN network found event: count %u\n",
		   pfn_result->count);

	if (pfn_result->count > 0) {
		int i;

		request = kzalloc(sizeof(*request) +
				  pfn_result->count *
				  sizeof(request->channels[0]),
				  GFP_KERNEL);
		ssid = kcalloc(pfn_result->count, sizeof(*ssid),
			       GFP_KERNEL);
		channel = kcalloc(pfn_result->count, sizeof(*channel),
				  GFP_KERNEL);

		if (!request || !ssid || !channel) {
			err = -ENOMEM;
			goto out_err;
		}

		request->wiphy = wiphy;

		data += sizeof(struct wland_pno_scanresults_le);
		netinfo_start = (struct wland_pno_net_info_le *) data;

		for (i = 0; i < pfn_result->count; i++) {
			netinfo = &netinfo_start[i];

			netdev_dbg(ifp->ndev, "PNO SSID \"%.*s\" ch %u\n",
				   netinfo->SSID_len, netinfo->SSID,
				   netinfo->channel);
			memcpy(ssid[i].ssid, netinfo->SSID, netinfo->SSID_len);
			ssid[i].ssid_len = netinfo->SSID_len;
			request->n_ssids++;

			channel_req = netinfo->channel;
			if (channel_req <= CH_MAX_2G_CHANNEL)
				band = NL80211_BAND_2GHZ;
			else
				band = NL80211_BAND_5GHZ;
			channel[i].center_freq =
				ieee80211_channel_to_frequency(channel_req,
							       band);
			channel[i].band = band;
			channel[i].flags |= IEEE80211_CHAN_NO_HT40;

			request->channels[i] = &channel[i];
			request->n_channels++;
		}

		if (request->n_ssids)
			request->ssids = &ssid[0];

		if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
			wland_abort_scanning(cfg);

		set_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

		err = wland_do_escan(cfg, wiphy, ifp, request);
		if (err < 0) {
			wland_clear_scan_busy(cfg);
			goto out_err;
		}
		cfg->sched_escan = true;
		cfg->scan_request = request;
	} else {
		netdev_dbg(ifp->ndev, "spurious PNO event (pfn_count is 0)\n");
		goto out_err;
	}

	return 0;

out_err:
	kfree(ssid);
	kfree(channel);
	kfree(request);
	cfg80211_sched_scan_stopped(wiphy, 0);

	return err;
}

static int wland_cfg80211_sched_scan_start(struct wiphy *wiphy,
	struct net_device *ndev, struct cfg80211_sched_scan_request *request)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_info *cfg = wiphy_priv(wiphy);
	struct wland_pno_net_param_le pfn;
	int i, enable = 1, ret = 0;

	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status)) {
		netdev_dbg(ndev, "scan already active: status 0x%lx\n",
			   cfg->scan_status);
		return -EAGAIN;
	}

	if (test_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status)) {
		netdev_dbg(ndev, "scan suppressed: status 0x%lx\n",
			   cfg->scan_status);
		return -EAGAIN;
	}

	if (!request->n_ssids || !request->n_match_sets) {
		netdev_err(ndev, "invalid scheduled scan request: n_ssids=%d\n",
			   request->n_ssids);
		return -EINVAL;
	}

	if (request->n_match_sets > 0) {
		struct wland_pno_param_le pfn_param;

		memset(&pfn_param, 0, sizeof(pfn_param));
		pfn_param.version = cpu_to_le32(WLAND_PNO_VERSION);

		pfn_param.flags =
			cpu_to_le16(1 << WLAND_PNO_ENABLE_ADAPTSCAN_BIT);
		pfn_param.repeat = WLAND_PNO_REPEAT;
		pfn_param.exp = WLAND_PNO_FREQ_EXPO_MAX;
		pfn_param.scan_freq = cpu_to_le32(WLAND_PNO_TIME);

		ret = wland_fil_iovar_data_set(netdev_priv(ndev), "pfn_set",
			&pfn_param, sizeof(pfn_param));
		if (ret < 0) {
			netdev_err(ndev, "failed to setup PNO: %d\n", ret);
			return -EINVAL;
		}

		for (i = 0; i < request->n_match_sets; i++) {
			struct cfg80211_ssid *ssid =
				&request->match_sets[i].ssid;
			u32 ssid_len = ssid->ssid_len;

			if (!ssid_len) {
				netdev_dbg(ndev, "skipping broadcast SSID\n");
				continue;
			}
			pfn.auth = cpu_to_le32(AUTH_OPEN);
			pfn.wpa_auth = cpu_to_le32(WLAND_PNO_WPA_AUTH_ANY);
			pfn.wsec = cpu_to_le32(0);
			pfn.infra = cpu_to_le32(1);
			pfn.flags = cpu_to_le32(1 << WLAND_PNO_HIDDEN_BIT);
			pfn.ssid.SSID_len = cpu_to_le32(ssid_len);

			memcpy(pfn.ssid.SSID, ssid->ssid, ssid_len);

			ret = wland_fil_iovar_data_set(ifp, "pfn_add", &pfn,
				sizeof(pfn));
			if (ret < 0)
				netdev_dbg(ndev,
					   "failed to add PNO filter for SSID \"%.*s\": %d\n",
					   ssid_len, ssid->ssid, ret);
		}

		ret = wland_fil_iovar_data_set(ifp, "pfn", &enable, sizeof(u8));
		if (ret < 0) {
			netdev_err(ndev, "failed to enable PNO: %d\n", ret);
			ret = -EINVAL;
		}
	} else {
		ret = -EINVAL;
	}

	return ret;
}

static int wland_cfg80211_sched_scan_stop(struct wiphy *wiphy,
	struct net_device *ndev, u64 reqid)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);

	if (cfg->sched_escan)
		wland_notify_escan_complete(cfg, netdev_priv(ndev), true, true);

	return 0;
}

static bool wland_valid_wpa_oui(u8 *oui, bool is_rsn_ie)
{
	if (is_rsn_ie)
		return (memcmp(oui, RSN_OUI, TLV_OUI_LEN) == 0);

	return (memcmp(oui, WPA_OUI, TLV_OUI_LEN) == 0);
}

static s32 wland_configure_wpaie(struct net_device *ndev,
	struct wland_vs_tlv *wpa_ie, bool is_rsn_ie)
{
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	u16 count;
	s32 err = 0, len = 0;
	u32 i, pval = 0, gval = 0, offset;
	u8 *data;

	if (!wpa_ie)
		return 0;

	len = wpa_ie->len + TLV_HDR_LEN;
	data = (u8 *) wpa_ie;
	offset = TLV_HDR_LEN;

	if (!is_rsn_ie)
		offset += VS_IE_FIXED_HDR_LEN;
	else
		offset += WPA_IE_VERSION_LEN;

	if (offset + WPA_IE_MIN_OUI_LEN > len) {
		netdev_err(ndev, "missing multicast cipher suite\n");
		return -EINVAL;
	}

	if (!wland_valid_wpa_oui(&data[offset], is_rsn_ie)) {
		netdev_err(ndev, "invalid multicast cipher OUI\n");
		return -EINVAL;
	}
	offset += TLV_OUI_LEN;

	switch (data[offset]) {
	case WPA_CIPHER_NONE:
		gval = 0;
		break;
	case WPA_CIPHER_WEP_40:
		netdev_dbg(ndev, "unsupported multicast cipher: WEP-40\n");
		return -ENOTSUPP;
	case WPA_CIPHER_WEP_104:
		netdev_dbg(ndev, "unsupported multicast cipher: WEP-104\n");
		return -ENOTSUPP;
	case WPA_CIPHER_TKIP:
		gval = TKIP;
		break;
	case WPA_CIPHER_AES_CCM:
		gval = AES;
		break;
	default:
		netdev_err(ndev, "invalid multicast cipher: %u\n",
			   data[offset]);
		return -EINVAL;
	}

	offset++;
	count = data[offset] + (data[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN;

	if (offset + (WPA_IE_MIN_OUI_LEN * count) > len) {
		netdev_err(ndev, "missing unicast cipher suite\n");
		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		if (!wland_valid_wpa_oui(&data[offset], is_rsn_ie)) {
			netdev_err(ndev, "invalid unicast cipher OUI\n");
			return -EINVAL;
		}
		offset += TLV_OUI_LEN;
		switch (data[offset]) {
		case WPA_CIPHER_NONE:
			pval = 0;
			break;
		case WPA_CIPHER_WEP_40:
			netdev_dbg(ndev, "unsupported unicast cipher: WEP-40\n");
			return -ENOTSUPP;
		case WPA_CIPHER_WEP_104:
			netdev_dbg(ndev, "unsupported unicast cipher: WEP-104\n");
			return -ENOTSUPP;
		case WPA_CIPHER_TKIP:
			pval |= TKIP;
			break;
		case WPA_CIPHER_AES_CCM:
			pval |= AES;
			break;
		default:
			netdev_err(ndev, "invalid unicast cipher: %u\n",
				   data[offset]);
			break;
		}
		offset++;
	}

	if (gval | AES)
		pval &= (~TKIP);

	if (gval) {
		if (is_rsn_ie)
			profile->sec.security_group =
				gval | ENCRYPT_ENABLED | WPA2;
		else
			profile->sec.security_group =
				gval | ENCRYPT_ENABLED | WPA;
	}

	if (pval) {
		if (is_rsn_ie)
			profile->sec.security =
				pval | ENCRYPT_ENABLED | WPA2;
		else
			profile->sec.security =
				pval | ENCRYPT_ENABLED | WPA;
	}

	return err;
}

static s32 wland_parse_vndr_ies(const u8 *vndr_ie_buf, u32 vndr_ie_len,
	struct parsed_vndr_ies *vndr_ies)
{
	s32 remaining_len = (s32)vndr_ie_len;
	struct wland_vs_tlv *vndrie;
	struct wland_tlv *ie;
	struct parsed_vndr_ie_info *parsed_info;

	memset(vndr_ies, 0, sizeof(*vndr_ies));

	ie = (struct wland_tlv *) vndr_ie_buf;

	while (ie) {
		if (ie->id != WLAN_EID_VENDOR_SPECIFIC)
			goto next;
		vndrie = (struct wland_vs_tlv *) ie;
		/* At least the OUI and type (an assoc response P2P IE has 4) */
		if (vndrie->len < (VS_IE_FIXED_HDR_LEN - TLV_HDR_LEN)) {
			pr_err("vendor IE too small: %d\n", vndrie->len);
			goto next;
		}

		if (!memcmp(vndrie->oui, (u8 *) WPA_OUI, TLV_OUI_LEN) &&
		    (vndrie->oui_type == WPA_OUI_TYPE ||
		     vndrie->oui_type == WME_OUI_TYPE)) {
			pr_debug("skipping WPA/WME vendor OUI\n");
			goto next;
		}

		parsed_info = &vndr_ies->ie_info[vndr_ies->count];

		parsed_info->ie_ptr = (char *) vndrie;
		parsed_info->ie_len = vndrie->len + TLV_HDR_LEN;

		memcpy(&parsed_info->vndrie, vndrie, sizeof(*vndrie));

		vndr_ies->count++;

		if (vndr_ies->count >= VNDR_IE_PARSE_LIMIT)
			break;
next:
		remaining_len -= (ie->len + TLV_HDR_LEN);

		if (remaining_len <= TLV_HDR_LEN)
			ie = NULL;
		else
			ie = (struct wland_tlv *) (((u8 *) ie) + ie->len +
				TLV_HDR_LEN);
	}

	return 0;
}

static u32 wland_vndr_ie(struct wland_if *ifp, u8 *iebuf, s32 pktflag,
			 const u8 *ie_ptr, u32 ie_len)
{
	memcpy(iebuf, ie_ptr, ie_len);

	return ie_len;
}

s32 wland_vif_set_mgmt_ie(struct wland_cfg80211_vif *vif, s32 pktflag,
	const u8 *vndr_ie_buf, u32 vndr_ie_len)
{
	struct parsed_vndr_ies new_vndr_ies;
	struct parsed_vndr_ie_info *vndrie_info;
	struct wland_if *ifp;
	struct vif_saved_ie *saved_ie;
	s32 err = 0, i;
	u8 *iovar_ie_buf;
	u8 *curr_ie_buf;
	u8 *mgmt_ie_buf = NULL;
	int mgmt_ie_buf_len, remained_buf_len;
	u32 *mgmt_ie_len;
	u32 del_add_ie_buf_len = 0, total_ie_buf_len = 0, parsed_ie_buf_len = 0;
	u8 *ptr;
	__le16 pktflag_le;

	if (!vif)
		return -ENODEV;
	if (!vndr_ie_buf)
		return 0;
	ifp = vif->ifp;

	if (ifp->bssidx != P2PAPI_BSSCFG_DEVICE)
		return 0;

	saved_ie = &vif->saved_ie;

	iovar_ie_buf = kzalloc(WLAND_EXTRA_BUF_MAX, GFP_KERNEL);
	if (!iovar_ie_buf)
		return -ENOMEM;

	pktflag_le = cpu_to_le16(pktflag);
	memcpy(iovar_ie_buf, &pktflag_le, sizeof(pktflag_le));
	total_ie_buf_len += 2;
	curr_ie_buf = iovar_ie_buf + 2;

	switch (pktflag) {
	case WLAND_VNDR_IE_RSN_INFO_FLAG:
		mgmt_ie_buf = saved_ie->rsn_ie;
		mgmt_ie_len = &saved_ie->rsn_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->rsn_ie);

		if (*mgmt_ie_len == vndr_ie_len &&
		    !memcmp(mgmt_ie_buf, vndr_ie_buf, vndr_ie_len))
			goto exit;

		total_ie_buf_len += wland_vndr_ie(vif->ifp, curr_ie_buf,
						  pktflag, vndr_ie_buf,
						  vndr_ie_len);
		*mgmt_ie_len = vndr_ie_len;
		goto send;

	case WLAND_VNDR_IE_PRBREQ_FLAG:
		mgmt_ie_buf = saved_ie->probe_req_ie;
		mgmt_ie_len = &saved_ie->probe_req_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->probe_req_ie);
		break;
	case WLAND_VNDR_IE_PRBRSP_FLAG:
		mgmt_ie_buf = saved_ie->probe_res_ie;
		mgmt_ie_len = &saved_ie->probe_res_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->probe_res_ie);
		break;
	case WLAND_VNDR_IE_BEACON_FLAG:
		mgmt_ie_buf = saved_ie->beacon_ie;
		mgmt_ie_len = &saved_ie->beacon_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->beacon_ie);
		break;
	case WLAND_VNDR_IE_ASSOCREQ_FLAG:
		mgmt_ie_buf = saved_ie->assoc_req_ie;
		mgmt_ie_len = &saved_ie->assoc_req_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->assoc_req_ie);
		break;
	case WLAND_VNDR_IE_ASSOCRSP_FLAG:
		mgmt_ie_buf = saved_ie->assoc_rsp_ie;
		mgmt_ie_len = &saved_ie->assoc_rsp_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->assoc_rsp_ie);
		break;
	default:
		err = -EPERM;
		netdev_err(ifp->ndev,
			   "unsupported vendor IE packet flag: 0x%x\n",
			   pktflag);
		goto exit;
	}

	if (vndr_ie_len > mgmt_ie_buf_len) {
		err = -ENOMEM;
		netdev_err(ifp->ndev,
			   "vendor IE size %u exceeds buffer limit %d\n",
			   vndr_ie_len, mgmt_ie_buf_len);
		goto exit;
	}

	/* Collect the new vendor IEs in curr_ie_buf to compare with the old */
	if (vndr_ie_len) {
		ptr = curr_ie_buf;
		wland_parse_vndr_ies(vndr_ie_buf, vndr_ie_len, &new_vndr_ies);

		for (i = 0; i < new_vndr_ies.count; i++) {
			vndrie_info = &new_vndr_ies.ie_info[i];
			memcpy(ptr + parsed_ie_buf_len, vndrie_info->ie_ptr,
				vndrie_info->ie_len);
			parsed_ie_buf_len += vndrie_info->ie_len;
		}
	}

	if (mgmt_ie_buf && *mgmt_ie_len) {
		if (parsed_ie_buf_len && parsed_ie_buf_len == *mgmt_ie_len &&
		    !memcmp(mgmt_ie_buf, curr_ie_buf, parsed_ie_buf_len))
			goto exit;
	}

	*mgmt_ie_len = 0;

	if (mgmt_ie_buf && parsed_ie_buf_len) {
		ptr = mgmt_ie_buf;
		remained_buf_len = mgmt_ie_buf_len;

		for (i = 0; i < new_vndr_ies.count; i++) {
			vndrie_info = &new_vndr_ies.ie_info[i];

			if (remained_buf_len <
			    vndrie_info->vndrie.len + VNDR_IE_VSIE_OFFSET) {
				netdev_err(ifp->ndev,
					   "no space in mgmt_ie_buf: remaining %d\n",
					   remained_buf_len);
				break;
			}
			remained_buf_len -=
				(vndrie_info->ie_len + VNDR_IE_VSIE_OFFSET);

			del_add_ie_buf_len =
				wland_vndr_ie(vif->ifp, curr_ie_buf, pktflag,
					      vndrie_info->ie_ptr,
					      vndrie_info->ie_len);

			memcpy(ptr + (*mgmt_ie_len), vndrie_info->ie_ptr,
			       vndrie_info->ie_len);
			*mgmt_ie_len += vndrie_info->ie_len;

			curr_ie_buf += del_add_ie_buf_len;
			total_ie_buf_len += del_add_ie_buf_len;
		}
	}

send:
	iovar_ie_buf[total_ie_buf_len++] = 0;
	err = wland_fil_set_cmd_data(vif->ifp, WID_P2P_VNDR_IE,
				     iovar_ie_buf, total_ie_buf_len);
	if (err < 0)
		netdev_err(ifp->ndev, "failed to set vendor IE: %d\n", err);

exit:
	kfree(iovar_ie_buf);
	return err;
}

s32 wland_vif_clear_mgmt_ies(struct wland_cfg80211_vif *vif)
{
	s32 i, pktflags[] = {
		WLAND_VNDR_IE_PRBREQ_FLAG,
		WLAND_VNDR_IE_PRBRSP_FLAG, WLAND_VNDR_IE_BEACON_FLAG
	};

	for (i = 0; i < ARRAY_SIZE(pktflags); i++)
		wland_vif_set_mgmt_ie(vif, pktflags[i], NULL, 0);

	memset(&vif->saved_ie, 0, sizeof(vif->saved_ie));
	return 0;
}

s32 wland_cfg80211_parse_ap_settings(struct net_device *ndev,
	struct cfg80211_ap_settings *settings)
{
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);

	profile->sec.security = NO_ENCRYPT;
	profile->sec.security_group = NO_ENCRYPT;
	profile->sec.firmware_autype = ANY;

	if (settings->crypto.cipher_group != NO_ENCRYPT) {
		int i;

		profile->sec.security = ENCRYPT_ENABLED;
		profile->sec.security_group = ENCRYPT_ENABLED;

		/*
		 * Determine security value: check group cipher suite,
		 * then pairwise suite.
		 */
		if (settings->crypto.wpa_versions & NL80211_WPA_VERSION_2) {
			profile->sec.firmware_autype = OPEN_SYSTEM;
			profile->sec.security |= WPA2;
			profile->sec.security_group |= WPA2;
		} else if (settings->crypto.wpa_versions &
			   NL80211_WPA_VERSION_1) {
			profile->sec.firmware_autype = OPEN_SYSTEM;
			profile->sec.security |= WPA;
			profile->sec.security_group |= WPA;
		} else {
			profile->sec.firmware_autype = SHARED_KEY;
			return 0;
		}

		for (i = 0; i < settings->crypto.n_ciphers_pairwise; i++) {
			if (settings->crypto.ciphers_pairwise[i] ==
				WLAN_CIPHER_SUITE_TKIP)
				profile->sec.security |= TKIP;
			else if (settings->crypto.ciphers_pairwise[i] ==
				 WLAN_CIPHER_SUITE_CCMP)
				profile->sec.security |= AES;
		}

		if (settings->crypto.cipher_group == WLAN_CIPHER_SUITE_TKIP) {
			profile->sec.security_group |= TKIP;
		} else if (settings->crypto.cipher_group ==
			   WLAN_CIPHER_SUITE_CCMP) {
			profile->sec.security_group |= AES;
			profile->sec.security &= (~TKIP);
		}
	} else {
		profile->sec.firmware_autype = OPEN_SYSTEM;
	}

	return 0;
}

static s32 wland_cfg80211_start_ap(struct wiphy *wiphy,
				    struct net_device *ndev,
				    struct cfg80211_ap_settings *settings)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_tlv *ssid_ie;
	struct wland_tlv *supprot_rates_ie;
	struct wland_tlv *rsn_ie;
	struct wland_tlv *ht_ie;
	struct wland_vs_tlv *wpa_ie;
	enum nl80211_iftype dev_role;
	s32 ie_offset, err = -EPERM;

	/* Beacon head consumed below, including capability field */
	if (!settings->beacon.head ||
	    settings->beacon.head_len <
	    DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN ||
	    !settings->chandef.chan ||
	    settings->ssid_len > sizeof(profile->ssid.SSID))
		return -EINVAL;
	if (ifp->vif->wdev.iftype == NL80211_IFTYPE_AP &&
	    strncasecmp(rdawlan_firmware_path, "ap", 2)) {
		netdev_err(ndev,
			   "AP requires AP firmware selected before interface open\n");
		return -EOPNOTSUPP;
	}

	netdev_dbg(ndev,
		   "starting AP: SSID \"%.*s\", auth %d, bcn %d, dtim %d, hidden %d, wpa %u\n",
		   (int)settings->ssid_len, settings->ssid,
		   settings->auth_type, settings->beacon_interval,
		   settings->dtim_period, settings->hidden_ssid,
		   settings->crypto.wpa_versions);

	dev_role = ifp->vif->wdev.iftype;
	conn_info->ndev = ndev;

	memset(&profile->ssid, '\0', sizeof(struct wland_ssid));
	profile->rsn_cap = 0;

	if (!settings->ssid || settings->ssid_len == 0) {
		ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
		ssid_ie = wland_parse_tlvs(
			(u8 *)&settings->beacon.head[ie_offset],
			settings->beacon.head_len - ie_offset,
			WLAN_EID_SSID);
		if (!ssid_ie || ssid_ie->len > sizeof(profile->ssid.SSID))
			return -EINVAL;

		memcpy(profile->ssid.SSID, ssid_ie->data, ssid_ie->len);
		profile->ssid.SSID_len = ssid_ie->len;
	} else {
		memcpy(profile->ssid.SSID, settings->ssid, settings->ssid_len);
		profile->ssid.SSID_len = settings->ssid_len;
	}

	profile->beacon = settings->beacon_interval;
	profile->dtim = settings->dtim_period;
	profile->channel =
		ieee80211_frequency_to_channel(
			settings->chandef.chan->center_freq);
	profile->hidden_ssid = settings->hidden_ssid;

	WARN_ON(atomic_read(&ifp->pend_8021x_cnt));
	atomic_set(&ifp->pend_8021x_cnt, 0);

	rsn_ie = wland_parse_tlvs((u8 *) settings->beacon.tail,
		settings->beacon.tail_len, WLAN_EID_RSN);
	if (rsn_ie) {
		err = wland_vif_set_mgmt_ie(ifp->vif,
					    WLAND_VNDR_IE_RSN_INFO_FLAG,
					    (const u8 *)rsn_ie,
					    rsn_ie->len + TLV_HDR_LEN);
		if (err)
			return err;
		profile->rsn_cap = 0xffff;
		if (wland_find_rsncap(rsn_ie, &profile->rsn_cap) == 0)
			netdev_dbg(ndev, "RSN capabilities: 0x%04x\n",
				   profile->rsn_cap);
	}

	wpa_ie = wland_find_wpaie((u8 *) settings->beacon.tail,
		settings->beacon.tail_len);

	if (wpa_ie) {
		err = wland_configure_wpaie(ndev, wpa_ie, false);
		if (err < 0)
			return err;
	} else if (rsn_ie) {
		err = wland_configure_wpaie(ndev,
			(struct wland_vs_tlv *) rsn_ie, true);
		if (err < 0)
			return err;
	}

	profile->mode = WLAND_N_MODE;
	profile->band_width = 1;
	profile->wmm_enable = 1;

	ht_ie = wland_parse_tlvs((u8 *) settings->beacon.tail,
		settings->beacon.tail_len, WLAN_EID_HT_CAP);
	if (ht_ie) {	/* 11n and wmm_enabled, check band_width */
		u8 *data = ht_ie->data;

		if (!ht_ie->len)
			return -EINVAL;
		/* HT capability info bit 1: 20/40 MHz channel width */
		if (data[0] & BIT1)
			profile->band_width = 1;
		else
			profile->band_width = 0;
	} else {
		const u8 *bc = settings->beacon.head;

		ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
		supprot_rates_ie = wland_parse_tlvs(
			(u8 *)&settings->beacon.head[ie_offset],
			settings->beacon.head_len - ie_offset,
			WLAN_EID_SUPP_RATES);
		if (!supprot_rates_ie) {
			netdev_err(ndev,
				   "missing supported rates IE in beacon\n");
		} else {
			profile->band_width = 0;
			profile->wmm_enable = !!wland_find_wmmie(
				settings->beacon.tail,
				settings->beacon.tail_len);

			/* G mode: short slot time or 8 basic rates */
			if ((bc[35] & BIT2) || supprot_rates_ie->len == 8)
				profile->mode = WLAND_G_MODE;
			else
				profile->mode = WLAND_B_MODE;
		}
	}

	netdev_dbg(ndev, "AP mode %u, bandwidth %u, WMM %u\n",
		   profile->mode, profile->band_width, profile->wmm_enable);

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_BEACON_FLAG,
		settings->beacon.tail, settings->beacon.tail_len);
	if (err) {
		netdev_err(ndev, "failed to set beacon IE: %d\n", err);
		return err;
	}

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_PRBRSP_FLAG,
		settings->beacon.proberesp_ies,
		settings->beacon.proberesp_ies_len);
	if (err) {
		netdev_err(ndev, "failed to set probe response IE: %d\n", err);
		return err;
	}

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_ASSOCRSP_FLAG,
		settings->beacon.assocresp_ies,
		settings->beacon.assocresp_ies_len);
	if (err) {
		netdev_err(ndev, "failed to set assoc response IE: %d\n", err);
		return err;
	}

	err = wland_cfg80211_parse_ap_settings(ndev, settings);
	if (err) {
		netdev_err(ndev, "failed to parse AP settings: %d\n", err);
		return err;
	}

	if (dev_role == NL80211_IFTYPE_AP) {
		err = wland_preinit_cmds_91h(ifp);
		if (err) {
			netdev_err(ndev, "failed to preinit 802.11h: %d\n",
				   err);
			return err;
		}
		err = wland_start_ap_set(ifp, profile, false);
		if (err) {
			netdev_err(ndev, "failed to start AP: %d\n", err);
			return err;
		}
		wland_config_and_efuse(ifp);
	} else {
		err = wland_p2p_start_go_set(ifp, profile, true);
		if (err)
			return err;
	}

	clear_bit(VIF_STATUS_AP_CREATING, &ifp->vif->sme_state);
	set_bit(VIF_STATUS_AP_CREATED, &ifp->vif->sme_state);

	return err;
}

static int wland_cfg80211_stop_ap(struct wiphy *wiphy,
				   struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	s32 err = 0;

	if (ifp->bssidx == P2PAPI_BSSCFG_DEVICE) {
		err = wland_fil_set_cmd_data(ifp, WID_STOP_AP_MAC1,
					     ifp->mac_addr, ETH_ALEN);
		if (err < 0)
			netdev_err(ndev, "failed to stop AP: %d\n", err);
	}

	set_bit(VIF_STATUS_AP_CREATING, &ifp->vif->sme_state);
	clear_bit(VIF_STATUS_AP_CREATED, &ifp->vif->sme_state);

	return err;
}

static s32
wland_cfg80211_change_beacon(struct wiphy *wiphy, struct net_device *ndev,
			     struct cfg80211_beacon_data *info)
{
	s32 err = 0;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_tlv *rsn_ie;

	rsn_ie = wland_parse_tlvs((u8 *)info->tail,
				  info->tail_len, WLAN_EID_RSN);
	if (rsn_ie)
		err = wland_vif_set_mgmt_ie(ifp->vif,
					    WLAND_VNDR_IE_RSN_INFO_FLAG,
					    (const u8 *)rsn_ie,
					    rsn_ie->len + TLV_HDR_LEN);

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_BEACON_FLAG,
		info->tail, info->tail_len);
	if (err) {
		netdev_err(ndev, "failed to set beacon IE: %d\n", err);
		return err;
	}

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_PRBRSP_FLAG,
		info->proberesp_ies, info->proberesp_ies_len);
	if (err) {
		netdev_err(ndev, "failed to set probe response IE: %d\n", err);
		return err;
	}

	err = wland_vif_set_mgmt_ie(ifp->vif, WLAND_VNDR_IE_ASSOCRSP_FLAG,
		info->assocresp_ies, info->assocresp_ies_len);
	if (err) {
		netdev_err(ndev, "failed to set assoc response IE: %d\n", err);
		return err;
	}

	return err;
}

static int wland_cfg80211_del_station(struct wiphy *wiphy,
				       struct net_device *ndev,
				       struct station_del_parameters *params)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wland_sta_info *sta_info, *sta_info_tmp;
	u8 connect_tmp;
	struct wland_scb_val_le scbval;
	const u8 *mac = params->mac;
	LIST_HEAD(del_list);
	struct wland_usb_dev *usb = ifp->drvr->bus_if->bus_priv.usb;
	struct wland_rx_info *rx_info = usb->devinfo->rx_info;

	if (!wland_check_vif_up(ifp->vif))
		return -EIO;

	if (mac)
		netdev_dbg(ndev, "deleting station %pM\n", mac);
	else
		netdev_dbg(ndev, "deleting all stations\n");

	scbval.val = WLAN_REASON_DEAUTH_LEAVING;
	spin_lock_bh(&conn_info->sta_info_lock);
	list_for_each_entry_safe(sta_info, sta_info_tmp,
				 &conn_info->sta_info_list, list) {
		if (!mac ||
		    memcmp(mac, sta_info->mac_addr, ETH_ALEN) == 0 ||
		    is_broadcast_ether_addr(mac)) {
			list_move_tail(&sta_info->list, &del_list);
		}
	}
	spin_unlock_bh(&conn_info->sta_info_lock);

	list_for_each_entry_safe(sta_info, sta_info_tmp, &del_list, list) {
		memcpy(scbval.ea, sta_info->mac_addr, ETH_ALEN);
		netdev_dbg(ndev,
			   "freeing station: conn %u, AID %u, MAC %pM\n",
			   sta_info->connect, sta_info->aid,
			   sta_info->mac_addr);
		connect_tmp = sta_info->connect;
		scbval.aid = sta_info->aid;
		if (connect_tmp) {
			if (ifp->vif ==
			    cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif)
				wland_ap_del_sta(ifp, scbval.aid);
			else
				wland_p2p_go_del_sta(ifp, &scbval);
		}
		list_del(&sta_info->list);
		kfree(sta_info->assoc_req_ie);
		kfree(sta_info);
	}

	wland_flush_rx_reorder_msg(rx_info, ifp->mac_addr);
	msleep(50);

	return 0;
}

static void wland_cfg80211_mgmt_frame_register(struct wiphy *wiphy,
	struct wireless_dev *wdev, u16 frame_type, bool reg)
{
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);
	u16 mgmt_type = (frame_type & IEEE80211_FCTL_STYPE) >> 4;

	if (reg)
		vif->mgmt_rx_reg |= BIT(mgmt_type);
	else
		vif->mgmt_rx_reg &= ~BIT(mgmt_type);
}

static s32
wland_cfg80211_change_bss(struct wiphy *wiphy, struct net_device *dev,
			  struct bss_parameters *params)
{
	return 0;
}

static s32 wland_cfg80211_mgmt_tx(struct wiphy *wiphy,
	struct wireless_dev *wdev,
	struct cfg80211_mgmt_tx_params *params,
	u64 *cookie)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	const struct ieee80211_mgmt *mgmt;
	struct wland_fil_action_frame_le *action_frame;
	struct wland_fil_af_params_le *af_params;
	bool ack;
	s32 chan_nr, err = 0, ie_offset, ie_len;
	u32 freq;
	u16 action_len;
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);

	*cookie = 0;

	if (!params || !params->buf || params->len < DOT11_MGMT_HDR_LEN) {
		wiphy_err(wiphy, "invalid or truncated management frame\n");
		return -EINVAL;
	}

	mgmt = (const struct ieee80211_mgmt *)params->buf;

	if (!ieee80211_is_mgmt(mgmt->frame_control)) {
		wiphy_err(wiphy, "only management frame type allowed\n");
		return -EPERM;
	}

	if (ieee80211_is_probe_resp(mgmt->frame_control)) {
		/*
		 * Probe responses are only sent for P2P listen or P2P GO.
		 * The supplicant sends them on the primary netdev, but the
		 * firmware expects them on the P2P device vif.
		 */
		ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
		if (params->len < ie_offset)
			return -EINVAL;
		ie_len = params->len - ie_offset;

		if (vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif)
			vif = cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
		err = wland_vif_set_mgmt_ie(vif, WLAND_VNDR_IE_PRBRSP_FLAG,
					    &(params->buf)[ie_offset], ie_len);
		cfg80211_mgmt_tx_status(wdev, *cookie, params->buf, params->len,
					true, GFP_KERNEL);
	} else if (ieee80211_is_action(mgmt->frame_control)) {
		action_len = params->len - DOT11_MGMT_HDR_LEN;
		if (action_len > WLAND_FIL_ACTION_FRAME_SIZE) {
			wiphy_err(wiphy, "action frame too large: %u > %u\n",
				  action_len, WLAND_FIL_ACTION_FRAME_SIZE);
			return -EINVAL;
		}

		af_params = kzalloc(sizeof(*af_params), GFP_KERNEL);
		if (!af_params)
			return -ENOMEM;

		action_frame = &af_params->action_frame;
		action_frame->packet_id = cpu_to_le32(*cookie);
		memcpy(&action_frame->da[0], &mgmt->da[0], ETH_ALEN);
		memcpy(&af_params->bssid[0], &mgmt->bssid[0], ETH_ALEN);
		/* Length excludes the 802.11 header */
		action_frame->len = cpu_to_le16(action_len);
		/* Use the requested channel, otherwise channel 1 */
		if (params->chan) {
			freq = params->chan->center_freq;
		} else {
			wland_fil_iovar_data_get(vif->ifp, "get_channel", &freq,
				sizeof(freq));
			freq = 2412;
		}

		chan_nr = ieee80211_frequency_to_channel(freq);
		af_params->channel = cpu_to_le32(chan_nr);

		memcpy(action_frame->data, &(params->buf)[DOT11_MGMT_HDR_LEN],
			action_len);

		wiphy_dbg(wiphy, "action frame: cookie %llu, len %u, freq %u\n",
			  *cookie, action_len, freq);

		ack = wland_p2p_send_action_frame(cfg, cfg_to_ndev(cfg),
			af_params);

		cfg80211_mgmt_tx_status(wdev, *cookie, params->buf,
			params->len, ack, GFP_KERNEL);
		kfree(af_params);
	} else {
		wiphy_dbg(wiphy, "unhandled mgmt frame: fc 0x%04x\n",
			  le16_to_cpu(mgmt->frame_control));
	}

	return err;
}

static s32 wland_cfg80211_remain_on_channel(struct wiphy *wiphy,
	struct wireless_dev *wdev,
	struct ieee80211_channel *channel,
	unsigned int duration, u64 *cookie)
{
	return wland_cfg80211_p2p_remain_on_channel(wiphy,
		wdev, channel, duration, cookie);
}

static s32 wland_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
	struct wireless_dev *wdev,
	u64 cookie)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_cfg80211_vif *vif =
		cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	if (!vif) {
		wiphy_err(wiphy, "no P2P device available\n");
		return -ENODEV;
	}
	wland_p2p_cancel_remain_on_channel(vif->ifp);
	return 0;
}

static int wland_cfg80211_crit_proto_start(struct wiphy *wiphy,
	struct wireless_dev *wdev, enum nl80211_crit_proto_id proto,
	u16 duration)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);

	/* Only DHCP is protected: scanning is suppressed until it ends */
	if (proto != NL80211_CRIT_PROTO_DHCP)
		return -EINVAL;

	set_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status);
	wland_abort_scanning(cfg);

	return 0;
}

static void wland_cfg80211_crit_proto_stop(struct wiphy *wiphy,
	struct wireless_dev *wdev)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);

	clear_bit(SCAN_STATUS_SUPPRESS, &cfg->scan_status);
}

static int wland_cfg80211_tdls_oper(struct wiphy *wiphy,
	struct net_device *ndev,
	const u8 *peer,
	enum nl80211_tdls_operation oper)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_tdls_iovar_le info;
	int ret = 0;

	switch (oper) {
	case NL80211_TDLS_DISCOVERY_REQ:
		ret = TDLS_MANUAL_EP_DISCOVERY;
		break;
	case NL80211_TDLS_SETUP:
		ret = TDLS_MANUAL_EP_CREATE;
		break;
	case NL80211_TDLS_TEARDOWN:
		ret = TDLS_MANUAL_EP_DELETE;
		break;
	default:
		netdev_err(ndev, "unsupported TDLS operation: %d\n", oper);
		return -EOPNOTSUPP;
	}

	memset(&info, 0, sizeof(info));
	info.mode = (u8) ret;

	if (peer)
		memcpy(info.ea, peer, ETH_ALEN);

	return wland_fil_iovar_data_set(ifp, "tdls_endpoint", &info,
		sizeof(info));
}

static s32 wland_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
	struct wireless_dev *wdev, u64 cookie)
{
	/* The off-channel wait is ended by the mgmt_tx path itself */
	return 0;
}

/* Configure the connection quality monitor RSSI threshold. */
static s32 wland_cfg80211_set_cqm_rssi_config(struct wiphy *wiphy,
					       struct net_device *dev,
					       s32 rssi_thold,
					       u32 rssi_hyst)
{
	return 0;
}

static struct cfg80211_ops wl_cfg80211_ops = {
	.change_virtual_intf = wland_cfg80211_change_virtual_iface,
	.scan = wland_cfg80211_scan,
	.set_wiphy_params = wland_cfg80211_set_wiphy_params,
	.join_ibss = wland_cfg80211_join_ibss,
	.leave_ibss = wland_cfg80211_leave_ibss,
	.get_station = wland_cfg80211_get_station,
	.add_key = wland_cfg80211_add_key,
	.del_key = wland_cfg80211_del_key,
	.get_key = wland_cfg80211_get_key,
	.set_default_key = wland_cfg80211_config_default_key,
	.set_default_mgmt_key = wland_cfg80211_config_default_mgmt_key,
	.set_power_mgmt = wland_cfg80211_set_power_mgmt,
	.connect = wland_cfg80211_connect,
	.disconnect = wland_cfg80211_disconnect,
	.suspend = wland_cfg80211_suspend,
	.resume = wland_cfg80211_resume,
	.set_pmksa = wland_cfg80211_set_pmksa,
	.del_pmksa = wland_cfg80211_del_pmksa,
	.flush_pmksa = wland_cfg80211_flush_pmksa,
	.start_ap = wland_cfg80211_start_ap,
	.stop_ap = wland_cfg80211_stop_ap,
	.change_beacon = wland_cfg80211_change_beacon,
	.del_station = wland_cfg80211_del_station,
	.mgmt_tx_cancel_wait = wland_cfg80211_mgmt_tx_cancel_wait,
	.sched_scan_start = wland_cfg80211_sched_scan_start,
	.sched_scan_stop = wland_cfg80211_sched_scan_stop,
	.mgmt_frame_register = wland_cfg80211_mgmt_frame_register,
	.change_bss = wland_cfg80211_change_bss,
	.mgmt_tx = wland_cfg80211_mgmt_tx,
	.remain_on_channel = wland_cfg80211_remain_on_channel,
	.cancel_remain_on_channel = wland_cfg80211_cancel_remain_on_channel,
	.crit_proto_start = wland_cfg80211_crit_proto_start,
	.crit_proto_stop = wland_cfg80211_crit_proto_stop,
	.tdls_oper = wland_cfg80211_tdls_oper,
	.set_cqm_rssi_config = wland_cfg80211_set_cqm_rssi_config,
};

static s32 wland_nl80211_iftype_to_mode(enum nl80211_iftype type)
{
	switch (type) {
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_MESH_POINT:
		return -ENOTSUPP;
	case NL80211_IFTYPE_ADHOC:
		return WL_MODE_IBSS;
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		return WL_MODE_BSS;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		return WL_MODE_AP;
	case NL80211_IFTYPE_P2P_DEVICE:
		return WL_MODE_P2P;
	case NL80211_IFTYPE_UNSPECIFIED:
	default:
		break;
	}
	return -EINVAL;
}

static const struct ieee80211_iface_limit wland_iface_limits[] = {
	{
		.max = 3,
		.types = BIT(NL80211_IFTYPE_STATION) |
		BIT(NL80211_IFTYPE_AP)
	},
};

static const struct ieee80211_iface_combination wland_iface_combos[] = {
	{
		.max_interfaces = WLAND_IFACE_MAX_CNT,
		.num_different_channels = 2,
		.n_limits = ARRAY_SIZE(wland_iface_limits),
		.limits = wland_iface_limits}
};

/* There isn't a lot of sense in it, but you can transmit anything you like */
static const struct ieee80211_txrx_stypes
	cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_ADHOC] = {
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_DISASSOC >> 4) |
			BIT(IEEE80211_STYPE_AUTH >> 4) |
			BIT(IEEE80211_STYPE_DEAUTH >> 4) |
			BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_AP_VLAN] = {
		/* Same as AP */
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_DISASSOC >> 4) |
			BIT(IEEE80211_STYPE_AUTH >> 4) |
			BIT(IEEE80211_STYPE_DEAUTH >> 4) |
			BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_GO] = {
		.tx = 0xFFFF,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_DISASSOC >> 4) |
			BIT(IEEE80211_STYPE_AUTH >> 4) |
			BIT(IEEE80211_STYPE_DEAUTH >> 4) |
			BIT(IEEE80211_STYPE_ACTION >> 4)
	}
};

static void wland_cfg80211_reg_notifier(struct wiphy *wiphy,
	struct regulatory_request *request)
{
	struct wland_cfg80211_info *cfg = wiphy_priv(wiphy);
	struct wland_country cspec = {
		{0},
		0,
		{0}
	};

	if (!request || !cfg) {
		wiphy_err(wiphy, "invalid arguments in regulatory notifier\n");
		return;
	}

	/* Only user regulatory requests are handled */
	if (request->initiator != NL80211_REGDOM_SET_BY_USER) {
		wiphy_dbg(wiphy, "unsupported regulatory initiator: %d\n",
			  request->initiator);
		return;
	}

	if (request->alpha2[0] == '0' && request->alpha2[1] == '0') {
		strncpy(cspec.country_abbrev, "XY", strlen("XY"));
		cspec.rev = 4;
	} else {
		memcpy(cspec.country_abbrev, request->alpha2, 2);
		cspec.country_abbrev[3] = '\0';
		cspec.rev = -1;	/* Unspecified */
	}

	wiphy_dbg(wiphy, "set country '%s/%d' done\n",
		  cspec.country_abbrev, cspec.rev);
}

static struct wiphy *wland_setup_wiphy(struct device *phydev)
{
	s32 err = 0;
	struct wiphy *wiphy = NULL;

	wiphy = wiphy_new(&wl_cfg80211_ops, sizeof(struct wland_cfg80211_info));
	if (!wiphy) {
		dev_err(phydev, "failed to allocate wiphy device\n");
		return ERR_PTR(-ENOMEM);
	}

	set_wiphy_dev(wiphy, phydev);

	wiphy->max_scan_ssids = SCAN_NUM_MAX;
	wiphy->max_scan_ie_len = SCAN_IE_LEN_MAX;
	wiphy->max_num_pmkids = MAXPMKID;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION)
		| BIT(NL80211_IFTYPE_AP)
		| BIT(NL80211_IFTYPE_P2P_CLIENT)
		| BIT(NL80211_IFTYPE_P2P_GO);
	wiphy->iface_combinations = wland_iface_combos;
	wiphy->n_iface_combinations = ARRAY_SIZE(wland_iface_combos);

	wiphy->software_iftypes |=
		BIT(NL80211_IFTYPE_P2P_DEVICE) |
		BIT(NL80211_IFTYPE_P2P_CLIENT) |
		BIT(NL80211_IFTYPE_P2P_GO);

	wiphy->bands[NL80211_BAND_2GHZ] = &__wl_band_2ghz;

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

	wiphy->cipher_suites = __wl_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(__wl_cipher_suites);

	wiphy->max_remain_on_channel_duration = 5000;	/* ms */

	wiphy->mgmt_stypes = cfg80211_default_mgmt_stypes;

	wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;

	wiphy->flags |= WIPHY_FLAG_NETNS_OK | WIPHY_FLAG_4ADDR_AP |
		WIPHY_FLAG_4ADDR_STATION;

	wiphy->flags |=
		WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL | WIPHY_FLAG_OFFCHAN_TX;

	wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;

	wiphy->regulatory_flags |= REGULATORY_CUSTOM_REG;
	wiphy->reg_notifier = wland_cfg80211_reg_notifier;

	wiphy_apply_custom_regulatory(wiphy, &wland_regdom);

	err = wiphy_register(wiphy);
	if (unlikely(err < 0)) {
		dev_err(phydev, "failed to register wiphy device: %d\n", err);
		wiphy_free(wiphy);
		return ERR_PTR(err);
	}
	return wiphy;
}

struct wland_cfg80211_vif *wland_alloc_vif(struct wland_cfg80211_info *cfg,
	enum nl80211_iftype type, bool pm_block)
{
	struct wland_cfg80211_vif *vif;

	if (cfg->vif_cnt == WLAND_IFACE_MAX_CNT) {
		wiphy_dbg(cfg->wiphy, "maximum vif count reached: %u\n",
			  cfg->vif_cnt);
		return ERR_PTR(-ENOSPC);
	}

	vif = kzalloc(sizeof(struct wland_cfg80211_vif), GFP_KERNEL);
	if (!vif)
		return ERR_PTR(-ENOMEM);

	vif->wdev.wiphy = cfg->wiphy;
	vif->wdev.iftype = type;

	vif->mode = wland_nl80211_iftype_to_mode(type);
	vif->pm_block = pm_block;
	vif->roam_off = -1;

	list_add_tail(&vif->list, &cfg->vif_list);
	cfg->vif_cnt++;
	return vif;
}

void wland_free_vif(struct wland_cfg80211_info *cfg,
	struct wland_cfg80211_vif *vif)
{
	list_del(&vif->list);
	cfg->vif_cnt--;

	kfree(vif);
}

static bool wland_is_nonetwork(struct wland_cfg80211_info *cfg,
	const struct wland_event_msg *e)
{
	return e->status != STATUS_SUCCESS;
}

s32 wland_get_assoc_ies_from_frame(struct wland_if *ifp, u8 *frame,
				   u16 frame_len, u8 frame_stype)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	s32 err = 0;
	u16 mgmt_hdr_len = GET_MGMT_HDR_LEN(frame);
	u16 assoc_ies_len;
	u8 sub_type = frame_stype;
	u8 *mac_addr = frame + MAC_HDR_ADDR2_OFFSET;
	struct wland_sta_info *sta_info;
	u8 find = 0;
	int i;

	if (frame_len < mgmt_hdr_len + (sub_type == ASSOC_REQ ?
			CAP_INFO_LEN + LISTEN_INTERVAL_LEN :
			CAP_INFO_LEN + STATUS_CODE_LEN + AID_LEN))
		return -EINVAL;
	assoc_ies_len = frame_len - mgmt_hdr_len;

	if (sub_type == ASSOC_REQ) {
		spin_lock_bh(&conn_info->sta_info_lock);
		list_for_each_entry(sta_info, &conn_info->sta_info_list, list) {
			if (!memcmp(mac_addr, sta_info->mac_addr, ETH_ALEN)) {
				find = 1;
				break;
			}
		}

		if (!find) {
			sta_info = kzalloc(sizeof(*sta_info),
					   GFP_ATOMIC);
			if (!sta_info) {
				spin_unlock_bh(&conn_info->sta_info_lock);
				return -1;
			}
			atomic_set(&sta_info->tid_map, 0);
			for (i = 0; i < 8; ++i) {
				sta_info->tid_jiffies[i] = jiffies;
				sta_info->tid_num[i] = 0;
			}
			list_add_tail(&sta_info->list,
				      &conn_info->sta_info_list);
		}

		kfree(sta_info->assoc_req_ie);
		sta_info->assoc_req_ie_len = assoc_ies_len - CAP_INFO_LEN -
			LISTEN_INTERVAL_LEN;
		sta_info->assoc_req_ie = kmemdup(
			frame + mgmt_hdr_len + CAP_INFO_LEN +
			LISTEN_INTERVAL_LEN,
			sta_info->assoc_req_ie_len, GFP_ATOMIC);
		sta_info->connect = 0;
		sta_info->aid = 0;
		if (sta_info->assoc_req_ie) {
			sta_info->wmm_enable = !!wland_find_wmmie(
				sta_info->assoc_req_ie,
				sta_info->assoc_req_ie_len);
			sta_info->n_enable = !!wland_parse_tlvs(
				sta_info->assoc_req_ie,
				sta_info->assoc_req_ie_len,
				WLAN_EID_HT_CAPABILITY);
		}
		memcpy(sta_info->mac_addr, mac_addr, ETH_ALEN);

		spin_unlock_bh(&conn_info->sta_info_lock);
	} else if (sub_type == ASSOC_RSP) {
		kfree(conn_info->resp_ie);
		conn_info->resp_ie = NULL;
		conn_info->resp_ie_len = 0;

		if (assoc_ies_len) {
			conn_info->resp_ie_len = assoc_ies_len -
				CAP_INFO_LEN - STATUS_CODE_LEN - AID_LEN;
			conn_info->resp_ie = kmemdup(
				frame + mgmt_hdr_len + CAP_INFO_LEN +
				STATUS_CODE_LEN + AID_LEN,
				conn_info->resp_ie_len, GFP_KERNEL);
		}
	}

	return err;
}

static s32 wland_get_assoc_ies(struct wland_cfg80211_info *cfg,
	struct wland_if *ifp)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	u8 req_len, resp_len;
	s32 err;

	kfree(conn_info->req_ie);
	conn_info->req_ie = NULL;
	conn_info->req_ie_len = 0;
	kfree(conn_info->resp_ie);
	conn_info->resp_ie = NULL;
	conn_info->resp_ie_len = 0;

	err = wland_fil_get_cmd_data(ifp, WID_ASSOC_REQ_INFO, cfg->extra_buf,
		WLAND_ASSOC_INFO_MAX);
	if (err < 0) {
		netdev_err(ifp->ndev, "failed to get assoc req info: %d\n", err);
		return err;
	}

	req_len = cfg->extra_buf[0];
	if (req_len) {
		conn_info->req_ie_len = req_len;
		conn_info->req_ie = kmemdup(&cfg->extra_buf[1],
					    conn_info->req_ie_len, GFP_KERNEL);
	}

	err = wland_fil_get_cmd_data(ifp, WID_ASSOC_RES_INFO, cfg->extra_buf,
		WLAND_ASSOC_INFO_MAX);
	if (err < 0) {
		netdev_err(ifp->ndev, "failed to get assoc resp info: %d\n", err);
		return err;
	}

	resp_len = cfg->extra_buf[0];
	if (resp_len) {
		conn_info->resp_ie_len = resp_len;
		conn_info->resp_ie = kmemdup(&cfg->extra_buf[1],
					     conn_info->resp_ie_len, GFP_KERNEL);
	}

	return 0;
}

static s32 wland_bss_roaming_done(struct wland_cfg80211_info *cfg,
	struct net_device *ndev, const struct wland_event_msg *e)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct ieee80211_channel *notify_channel = NULL;
	struct ieee80211_supported_band *band =
		wiphy->bands[NL80211_BAND_2GHZ];
	struct wland_bss_info_le *bi;
	struct wland_chan ch;
	u32 freq;
	s32 err = 0;
	u8 *buf;

	wland_get_assoc_ies(cfg, ifp);

	buf = kzalloc(WLAND_BSS_INFO_MAX, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}

	*(__le32 *) buf = cpu_to_le32(WLAND_BSS_INFO_MAX);

	err = wland_fil_iovar_data_get(ifp, "get_bss_info", buf,
		WLAND_BSS_INFO_MAX);
	if (err < 0)
		goto done;

	bi = (struct wland_bss_info_le *) (buf + 4);
	ch.chspec = le16_to_cpu(bi->chanspec);
	cfg->d11inf.decchspec(&ch);

	if (ch.band == CHAN_BAND_2G)
		band = wiphy->bands[NL80211_BAND_2GHZ];

	freq = ieee80211_channel_to_frequency(ch.chnum, band->band);
	notify_channel = ieee80211_get_channel(wiphy, freq);

done:
	kfree(buf);
out:
	{
		struct cfg80211_roam_info roam_info = {
			.channel = notify_channel,
			.bssid = (u8 *) profile->bssid,
			.req_ie = conn_info->req_ie,
			.req_ie_len = conn_info->req_ie_len,
			.resp_ie = conn_info->resp_ie,
			.resp_ie_len = conn_info->resp_ie_len,
		};
		cfg80211_roamed(ndev, &roam_info, GFP_KERNEL);
	}
	set_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
	return err;
}

static s32 wland_bss_connect_done(struct wland_cfg80211_info *cfg,
	struct net_device *ndev, const struct wland_event_msg *e,
	bool completed)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;

	if (!completed) {
		wland_connect_failed(ifp->vif, WLAN_STATUS_UNSPECIFIED_FAILURE,
				     false);
	} else if (test_and_clear_bit(VIF_STATUS_CONNECTING,
				      &ifp->vif->sme_state)) {
		set_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
		wland_set_phy_timeout(ifp->drvr,
				      profile->sec.cipher_pairwise,
				      profile->sec.cipher_group);
		wland_restore_power_save(ifp);

		cfg80211_connect_result(ndev,
			(u8 *) profile->bssid,
			conn_info->req_ie,
			conn_info->req_ie_len,
			conn_info->resp_ie,
			conn_info->resp_ie_len,
			WLAN_STATUS_SUCCESS, GFP_KERNEL);
		netdev_dbg(ndev, "association succeeded with %pM (req IE %d, resp IE %d)\n",
			    profile->bssid, conn_info->req_ie_len,
			    conn_info->resp_ie_len);
	}
	return 0;
}

static int wland_check_and_inform_bss(struct wland_if *ifp)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct wland_cfg80211_profile *profile = ndev_to_prof(ifp->ndev);
	struct cfg80211_bss *bss_internal = NULL;
	struct wland_bss_info_le *bss;
	bool find = false;
	int ret = 0;

	if (!((ifp->bssidx == 0) && !is_zero_ether_addr(profile->bssid)
		&& (profile->ssid.SSID_len) && wiphy))
		return 0;

	bss_internal = cfg80211_get_bss(wiphy, NULL, profile->bssid,
		profile->ssid.SSID, profile->ssid.SSID_len,
		WLAN_CAPABILITY_ESS, WLAN_CAPABILITY_ESS);

	cfg80211_put_bss(wiphy, bss_internal);
	if (bss_internal)
		return 0;

	mutex_lock(&cfg->scan_result_lock);
	list_for_each_entry(bss, &cfg->scan_result_list, list) {
		if (!memcmp(bss->BSSID, profile->bssid, ETH_ALEN)) {
			find = true;
			bss->time = jiffies;
			ret = wland_inform_single_bss(cfg, bss);
			if (ret)
				netdev_dbg(ifp->ndev, "failed to inform BSS: %d\n",
					   ret);
			break;
		}
	}
	mutex_unlock(&cfg->scan_result_lock);
	if (!find) {
		ret = -1;
		netdev_warn(ifp->ndev, "BSS %pM not found in scan results\n",
			    profile->bssid);
	}

	return ret;
}

static s32 wland_notify_connect_status(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct timer_list *cr_timer = &conn_info->connect_restorework_timeout;
	struct work_struct *cr_work =
		&conn_info->connect_restorework_timeout_work;
	struct list_head *sta_list = &conn_info->sta_info_list;
	spinlock_t *sta_lock = &conn_info->sta_info_lock;
	struct net_device *ndev = ifp->ndev;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct wland_sta_info *sta_info, *sta_info_tmp;
	struct ieee80211_channel *chan;
	struct wland_usb_dev *usb = ifp->drvr->bus_if->bus_priv.usb;
	struct wland_rx_info *rx_info = usb->devinfo->rx_info;
	u8 find = 0;
	s32 err = 0;
	u8 *pU8Buffer = (u8 *) data;
	int i;

	if (!wland_check_vif_up(ifp->vif)) {
		netdev_dbg(ndev, "interface not ready (event %d, reason %d)\n",
			   e->event_code, e->reason);
		return -EINVAL;
	}

	if (memcmp(ifp->mac_addr, e->addr, ETH_ALEN) == 0) {
		netdev_dbg(ndev, "ignoring connection from self MAC %pM\n",
			   e->addr);
		goto fail;
	}

	cancel_work_sync(&conn_info->work);

	switch (ifp->vif->mode) {
	case WL_MODE_AP: {
		static int generation;
		struct station_info sinfo;

		if (e->event_code == WLAND_E_CONNECT_IND) {
			if (e->action == WLAND_ACTION_AP_CONNECTED) {
				if (!pU8Buffer) {
					netdev_err(ndev, "missing payload in CONNECT_IND event\n");
					err = -EINVAL;
					goto fail;
				}

				if (!netif_carrier_ok(ndev))
					netif_carrier_on(ndev);
				if (netif_queue_stopped(ndev))
					netif_wake_queue(ndev);

				memset(&sinfo, 0, sizeof(sinfo));
				spin_lock_bh(sta_lock);
				list_for_each_entry(sta_info, sta_list, list) {
					if (!memcmp(e->addr, sta_info->mac_addr,
						    ETH_ALEN)) {
						find = 1;
						break;
					}
				}
				if (!find) {
					sta_info = kzalloc(sizeof(*sta_info),
							   GFP_ATOMIC);
					if (!sta_info) {
						spin_unlock_bh(sta_lock);
						return -1;
					}
					sta_info->aid = 0;
					memcpy(sta_info->mac_addr, e->addr,
					       ETH_ALEN);
					list_add_tail(&sta_info->list,
						      sta_list);
				}
				atomic_set(&sta_info->tid_map, 0);
				for (i = 0; i < 8; ++i) {
					sta_info->tid_jiffies[i] = jiffies;
					sta_info->tid_num[i] = 0;
				}
				sta_info->connect = 1;
				sta_info->aid = pU8Buffer[8];
				if (sta_info->assoc_req_ie) {
					sinfo.assoc_req_ies_len =
						sta_info->assoc_req_ie_len;
					sinfo.assoc_req_ies =
						sta_info->assoc_req_ie;
				} else {
					sinfo.assoc_req_ies_len = 0;
					sinfo.assoc_req_ies = NULL;
					netdev_dbg(ndev, "no assoc request IE for %pM\n",
						   e->addr);
				}
				spin_unlock_bh(sta_lock);

				generation++;
				sinfo.generation = generation;
				cancel_work_sync(cr_work);

				cfg80211_new_sta(ndev, e->addr, &sinfo,
						 GFP_ATOMIC);
			}
		} else if (e->event_code == WLAND_E_DISCONNECT_IND) {
			if (e->action == WLAND_ACTION_AP_DISCONNECTED) {
				spin_lock_bh(sta_lock);
				list_for_each_entry_safe(sta_info, sta_info_tmp,
							 sta_list, list) {
					if (memcmp(sta_info->mac_addr, e->addr,
						   ETH_ALEN))
						continue;

					if (sta_info->connect) {
						cfg80211_del_sta(ndev, e->addr,
								 GFP_ATOMIC);
						sta_info->connect = 0;
					}
					break;
				}
				spin_unlock_bh(sta_lock);
				wland_flush_rx_reorder_msg(rx_info, e->addr);
				if (timer_pending(cr_timer))
					del_timer_sync(cr_timer);
				cancel_work_sync(cr_work);
			}
		}
		break;
	}
	case WL_MODE_BSS:
		netdev_dbg(ndev, "firmware link event: %s, status %u, reason %u\n",
			    e->event_code == WLAND_E_CONNECT_IND ?
			    "connect" : "disconnect", e->status, e->reason);
		if ((e->event_code == WLAND_E_CONNECT_IND)
			&& (e->status == STATUS_SUCCESS)) {
			if (timer_pending(&conn_info->timer))
				del_timer_sync(&conn_info->timer);
			if (test_bit(VIF_STATUS_CHANGEING,
				     &ifp->vif->sme_state)) {
				clear_bit(VIF_STATUS_CONNECTING,
					  &ifp->vif->sme_state);
				wland_cfg80211_disconnect(cfg->wiphy,
							  ifp->ndev, 0);
				return 0;
			}

			cancel_work_sync(cr_work);
			mod_timer(cr_timer, jiffies +
				  msecs_to_jiffies(
					CONNECT_RESTOREWORK_TIMER_MS));

			if (ifp->vif->mode == WL_MODE_IBSS) {
				memcpy(profile->bssid, e->addr, ETH_ALEN);
				wland_inform_ibss(cfg, ndev, e->addr);
				chan = ieee80211_get_channel(cfg->wiphy,
							     cfg->channel);
				cfg80211_ibss_joined(ndev, e->addr, chan,
						     GFP_KERNEL);
				clear_bit(VIF_STATUS_CONNECTING,
					  &ifp->vif->sme_state);
				set_bit(VIF_STATUS_CONNECTED,
					&ifp->vif->sme_state);
			} else {
				if (!netif_carrier_ok(ndev))
					netif_carrier_on(ndev);
				if (netif_queue_stopped(ndev))
					netif_wake_queue(ndev);
				atomic_set(&conn_info->tid_map, 0);
				spin_lock_bh(sta_lock);
				memset(&conn_info->ba, 0,
				       sizeof(conn_info->ba));
				spin_unlock_bh(sta_lock);
				for (i = 0; i < 8; ++i) {
					conn_info->tid_jiffies[i] = jiffies;
					conn_info->tid_num[i] = 0;
				}

				if (wland_check_and_inform_bss(ifp)) {
					netdev_err(ndev, "connected but failed to report BSS to cfg80211\n");
					wland_bss_connect_done(cfg, ndev,
							       NULL, false);
				} else {
					wland_bss_connect_done(cfg, ndev,
							       e, true);
				}
			}
		} else if (e->event_code == WLAND_E_CONNECT_IND &&
			   e->status == STATUS_TIMEOUT) {
			if (test_bit(VIF_STATUS_CHANGEING,
				     &ifp->vif->sme_state)) {
				clear_bit(VIF_STATUS_CONNECTING,
					  &ifp->vif->sme_state);
			} else if (test_bit(VIF_STATUS_CONNECTING,
					    &ifp->vif->sme_state) &&
				   conn_info) {
				conn_info->retry_times++;
				if (conn_info->retry_times <
				    CONNECT_RETRY_TIMES_MAX) {
					wland_wakeup_connect_worker(conn_info);
				} else {
					if (timer_pending(&conn_info->timer))
						del_timer_sync(&conn_info->timer);

					wland_connect_failed(ifp->vif, 0,
							     true);
				}
			}

		} else if (e->event_code == WLAND_E_DISCONNECT_IND) {
			wland_flush_rx_reorder_msg(rx_info, ifp->mac_addr);
			wland_tx_pkt_reinit(rx_info);

			if (timer_pending(&conn_info->timer))
				del_timer_sync(&conn_info->timer);

			if (timer_pending(cr_timer))
				del_timer_sync(cr_timer);
			cancel_work_sync(cr_work);

			if (ifp->vif->mode != WL_MODE_IBSS) {
				if (test_and_clear_bit(VIF_STATUS_CONNECTED,
						       &ifp->vif->sme_state)) {
					msleep(200);
					cfg80211_disconnected(
						ndev, 0, NULL, 0,
						cfg->in_disconnecting,
						GFP_KERNEL);
				}
			}

			wland_link_down(ifp->vif);

			kfree(profile->wps_ie);
			profile->wps_ie = NULL;
			profile->wps_ie_len = 0;
			memset(profile, '\0', sizeof(*profile));
			if (cfg->in_disconnecting) {
				if (cfg->in_waiting)
					complete(&cfg->disconnecting_wait);
				cfg->in_disconnecting = false;
			}

			if (ndev != cfg_to_ndev(cfg))
				complete(&cfg->vif_disabled);
		}
		break;
	case WL_MODE_IBSS:
		if (timer_pending(&conn_info->timer))
			del_timer_sync(&conn_info->timer);

		if (wland_is_nonetwork(cfg, e)) {
			if (ifp->vif->mode != WL_MODE_IBSS)
				clear_bit(VIF_STATUS_CONNECTING,
					  &ifp->vif->sme_state);
			else
				wland_bss_connect_done(cfg, ndev, e, false);
		}
		break;
	default:
		break;
	}

fail:
	return err;
}

static s32 wland_notify_roaming_status(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;

	if (e->event_code == WLAND_E_ROAM && e->status == STATUS_SUCCESS) {
		if (test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state))
			wland_bss_roaming_done(cfg, ifp->ndev, e);
		else
			wland_bss_connect_done(cfg, ifp->ndev, e, true);
	}

	return 0;
}

static s32 wland_notify_vif_event(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_cfg80211_vif_event *event = &cfg->vif_event;
	struct wland_cfg80211_vif *vif = event->vif;

	mutex_lock(&event->vif_event_lock);
	event->action = e->action;

	switch (e->action) {
	case WLAND_ACTION_IF_ADD:
		/* The waiter may have timed out */
		if (!cfg->vif_event.vif) {
			mutex_unlock(&event->vif_event_lock);
			return -EBADF;
		}

		ifp->vif = vif;

		vif->ifp = ifp;
		if (ifp->ndev) {
			vif->wdev.netdev = ifp->ndev;
			ifp->ndev->ieee80211_ptr = &vif->wdev;

			SET_NETDEV_DEV(ifp->ndev, wiphy_dev(cfg->wiphy));
		}
		mutex_unlock(&event->vif_event_lock);
		wake_up(&event->vif_wq);
		return 0;

	case WLAND_ACTION_IF_DEL:
		mutex_unlock(&event->vif_event_lock);
		/* The event need not follow a user request */
		if (wland_cfg80211_vif_event_armed(cfg))
			wake_up(&event->vif_wq);
		return 0;

	case WLAND_ACTION_IF_CHANGE:
		mutex_unlock(&event->vif_event_lock);
		wake_up(&event->vif_wq);
		return 0;

	default:
		mutex_unlock(&event->vif_event_lock);
		break;
	}

	return -EINVAL;
}

/* sta_info_lock protects both lookup lifetime and BA state. */
static struct wland_ba_state *wland_ba_lookup(struct wland_if *ifp,
					    const u8 *peer)
{
	struct wland_cfg80211_connect_info *ci = &ifp->vif->conn_info;
	struct wland_sta_info *sta;

	if (ifp->vif->mode == WL_MODE_BSS) {
		if (!test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state) ||
		    !ether_addr_equal(peer, ifp->vif->profile.bssid) ||
		    !ci->wmm_enable || !ci->n_enable)
			return NULL;
		return &ci->ba;
	}
	if (ifp->vif->mode != WL_MODE_AP)
		return NULL;
	list_for_each_entry(sta, &ci->sta_info_list, list) {
		if (ether_addr_equal(peer, sta->mac_addr) &&
		    sta->wmm_enable && sta->n_enable)
			return &sta->ba;
	}
	return NULL;
}

#define WLAND_BA_TIMEOUT_MS 1500
#define WLAND_BA_RETRY_MS 30000

void wland_queue_addba(struct wland_if *ifp, u8 tid, const u8 *peer)
{
	struct wland_cfg80211_connect_info *ci = &ifp->vif->conn_info;
	struct wland_event_msg event = { 0 };
	struct wland_addba_msg msg = { 0 };
	struct wland_ba_state *ba;
	bool queue = false;

	if (tid >= 8)
		return;
	spin_lock_bh(&ci->sta_info_lock);
	ba = wland_ba_lookup(ifp, peer);
	if (!ba || (ba->active & BIT(tid)))
		goto unlock;
	/*
	 * A pending request times out on the next packet; TX never waits for
	 * the BA session, and no timer or work keeps a station pointer alive
	 * after disconnect.
	 */
	if (ba->pending & BIT(tid)) {
		if (time_after_eq(jiffies, ba->deadline[tid])) {
			ba->pending &= ~BIT(tid);
			ba->retry_at[tid] = jiffies +
				msecs_to_jiffies(WLAND_BA_RETRY_MS);
		}
		goto unlock;
	}
	if (ba->retry_at[tid] && time_before(jiffies, ba->retry_at[tid]))
		goto unlock;
	ba->pending |= BIT(tid);
	ba->deadline[tid] = jiffies + msecs_to_jiffies(WLAND_BA_TIMEOUT_MS);
	memcpy(msg.mac_addr, peer, ETH_ALEN);
	queue = true;
unlock:
	spin_unlock_bh(&ci->sta_info_lock);
	if (!queue)
		return;
	event.bsscfgidx = ifp->bssidx;
	event.event_code = WLAND_E_ADDBA;
	event.action = WLAND_ACTION_ADDBA_SEND;
	event.datalen = sizeof(msg);
	msg.action = 1;
	msg.tid = tid;
	wland_fweh_push_event(ifp->drvr, &event, &msg);
}

static s32 wland_addba_event(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_connect_info *ci;
	struct wland_ba_state *ba;
	struct wland_addba_msg *msg = data;
	bool send = false;
	int ret = 0;

	if (!ifp || !ifp->vif || e->datalen < sizeof(*msg) || msg->tid >= 8)
		return -EINVAL;
	ci = &ifp->vif->conn_info;
	spin_lock_bh(&ci->sta_info_lock);
	ba = wland_ba_lookup(ifp, msg->mac_addr);
	if (!ba)
		goto unlock;
	switch (e->action) {
	case WLAND_ACTION_ADDBA_SEND:
		if (!(ba->pending & BIT(msg->tid)))
			break;
		if (time_after_eq(jiffies, ba->deadline[msg->tid]) ||
		    test_bit(SCAN_STATUS_BUSY,
			     &ifp->drvr->config->scan_status)) {
			ba->pending &= ~BIT(msg->tid);
			ba->retry_at[msg->tid] = jiffies +
				msecs_to_jiffies(WLAND_BA_RETRY_MS);
			break;
		}
		send = true;
		break;
	case WLAND_ACTION_ADDBA_DONE:
		/*
		 * The firmware identifies interface, peer and TID; a late
		 * response must not wake the unrelated vif-event waiter.
		 */
		if ((ba->pending & BIT(msg->tid)) &&
		    time_before(jiffies, ba->deadline[msg->tid])) {
			ba->pending &= ~BIT(msg->tid);
			ba->active |= BIT(msg->tid);
			ba->retry_at[msg->tid] = 0;
		}
		break;
	case WLAND_ACTION_DELBA:
		ba->pending &= ~BIT(msg->tid);
		ba->active &= ~BIT(msg->tid);
		ba->retry_at[msg->tid] = jiffies +
			msecs_to_jiffies(WLAND_BA_RETRY_MS);
		break;
	default:
		ret = -EINVAL;
	}
unlock:
	spin_unlock_bh(&ci->sta_info_lock);
	if (!send)
		return ret;

	/*
	 * A WID transaction can sleep: no station pointer or sta_info_lock is
	 * held across it, and the later aggregation event is not waited for.
	 */
	ret = wland_set_11n_action(ifp, msg->mac_addr, msg->tid, msg->action);
	if (ret) {
		spin_lock_bh(&ci->sta_info_lock);
		ba = wland_ba_lookup(ifp, msg->mac_addr);
		if (ba) {
			ba->pending &= ~BIT(msg->tid);
			ba->retry_at[msg->tid] = jiffies +
				msecs_to_jiffies(WLAND_BA_RETRY_MS);
		}
		spin_unlock_bh(&ci->sta_info_lock);
	}
	return ret;
}

static s32 wland_notify_arp_offload_event(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	s32 ret;

	ret = wland_enable_arp_offload(ifp, (char *)data);
	if (ifp->vif->mode == WL_MODE_BSS) {
		wland_set_mcs(ifp, 0);
		wland_set_txrate(ifp, 0);
		if (timer_pending(&conn_info->connect_restorework_timeout))
			del_timer_sync(&conn_info->connect_restorework_timeout);
		cancel_work_sync(&conn_info->connect_restorework_timeout_work);
	}

	return ret;
}

static s32 notify_mic_event(struct wland_if *ifp,
	const struct wland_event_msg *e, void *data)
{
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;
	enum nl80211_key_type key_type;

	if (e->status == 1)
		key_type = NL80211_KEYTYPE_PAIRWISE;
	else
		key_type = NL80211_KEYTYPE_GROUP;
	if (test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state))
		cfg80211_michael_mic_failure(ifp->ndev, (u8 *)profile->bssid,
					     key_type, -1, NULL, GFP_KERNEL);
	return 0;
}

static void wland_register_event_handlers(struct wland_cfg80211_info *cfg)
{
	wland_fweh_register(cfg->pub, WLAND_E_ESCAN_RESULT,
		wland_notify_escan_handler);
	wland_fweh_register(cfg->pub, WLAND_E_DISCONNECT_IND,
		wland_notify_connect_status);
	wland_fweh_register(cfg->pub, WLAND_E_CONNECT_IND,
		wland_notify_connect_status);
	wland_fweh_register(cfg->pub, WLAND_E_ROAM,
		wland_notify_roaming_status);
	wland_fweh_register(cfg->pub, WLAND_E_PFN_NET_FOUND,
		wland_notify_sched_scan_results);
	wland_fweh_register(cfg->pub, WLAND_E_IF_ADD,
		wland_notify_vif_event);
	wland_fweh_register(cfg->pub, WLAND_E_IF_DEL,
		wland_notify_vif_event);
	wland_fweh_register(cfg->pub, WLAND_E_IF_CHANGE,
		wland_notify_vif_event);
	wland_fweh_register(cfg->pub, WLAND_E_ARP_OFFLOAD,
		wland_notify_arp_offload_event);
	wland_fweh_register(cfg->pub, WLAND_E_ADDBA,
		wland_addba_event);
	wland_fweh_register(cfg->pub, WLAND_E_MIC_ERROR,
		notify_mic_event);
	wland_fweh_register(cfg->pub, WLAND_E_RESET_FW,
		wland_reset_firmware);
	wland_fweh_register(cfg->pub, WLAND_E_P2P_PROBEREQ_MSG,
		wland_notify_p2p_rx_mgmt_probereq);
	wland_fweh_register(cfg->pub, WLAND_E_P2P_DISC_LISTEN_COMPLETE,
		wland_notify_p2p_listen_complete);
	wland_fweh_register(cfg->pub, WLAND_E_ACTION_FRAME_RX,
		wland_notify_p2p_action_frame_rx);
	wland_fweh_register(cfg->pub, WLAND_E_ACT_FRAME_COMPLETE,
		wland_notify_p2p_action_tx_complete);
	wland_fweh_register(cfg->pub, WLAND_E_ACT_FRAME_OFF_CHAN_COMPLETE,
		wland_notify_p2p_action_tx_complete);
}

static void wland_deinit_priv_mem(struct wland_cfg80211_info *cfg)
{
	kfree(cfg->conf);
	cfg->conf = NULL;

	kfree(cfg->extra_buf);
	cfg->extra_buf = NULL;

	kfree(cfg->pmk_list);
	cfg->pmk_list = NULL;
}

static s32 wland_init_priv_mem(struct wland_cfg80211_info *cfg)
{
	cfg->conf = kzalloc(sizeof(struct wland_cfg80211_conf), GFP_KERNEL);
	if (!cfg->conf)
		goto init_priv_mem_out;

	cfg->extra_buf = kzalloc(WLAND_EXTRA_BUF_MAX, GFP_KERNEL);
	if (!cfg->extra_buf)
		goto init_priv_mem_out;

	cfg->pmk_list =
		kzalloc(sizeof(struct wland_cfg80211_pmk_list), GFP_KERNEL);
	if (!cfg->pmk_list)
		goto init_priv_mem_out;

	return 0;

init_priv_mem_out:
	wland_deinit_priv_mem(cfg);
	return -ENOMEM;
}

static s32 wland_dongle_roam(struct wland_if *ifp, u32 roamvar, u32 bcn_timeout)
{
	s32 err;
	__le32 roamtrigger[2];
	__le32 roam_delta[2];

	/* With roaming off, report link down after a beacon loss timeout */
	if (roamvar) {
		err = wland_fil_iovar_data_set(ifp, "bcn_timeout",
			&bcn_timeout, sizeof(bcn_timeout));
		if (err < 0) {
			netdev_err(ifp->ndev, "failed to set beacon timeout: %d\n",
				   err);
			goto dongle_rom_out;
		}
	}

	err = wland_fil_iovar_data_set(ifp, "roam_off",
		&roamvar, sizeof(roamvar));
	if (err < 0) {
		netdev_err(ifp->ndev, "failed to set roam_off: %d\n", err);
		goto dongle_rom_out;
	}

	roamtrigger[0] = cpu_to_le32(ROAM_TRIGGER_LEVEL);
	roamtrigger[1] = cpu_to_le32(WLAND_BAND_ALL);
	err = wland_fil_iovar_data_set(ifp, "roam_trigger",
		roamtrigger, sizeof(roamtrigger));
	if (err < 0) {
		netdev_err(ifp->ndev, "failed to set roam_trigger: %d\n", err);
		goto dongle_rom_out;
	}

	roam_delta[0] = cpu_to_le32(ROAM_DELTA);
	roam_delta[1] = cpu_to_le32(WLAND_BAND_ALL);
	err = wland_fil_iovar_data_set(ifp, "roam_delta",
		roam_delta, sizeof(roam_delta));
	if (err < 0) {
		netdev_err(ifp->ndev, "failed to set roam_delta: %d\n", err);
		goto dongle_rom_out;
	}

dongle_rom_out:
	return err;
}

static s32 wland_construct_reginfo(struct wland_cfg80211_info *cfg, u32 bw_cap)
{
	return 0;
}

static s32 wland_update_wiphybands(struct wland_cfg80211_info *cfg, bool notify)
{
	struct wland_if *ifp = netdev_priv(cfg_to_ndev(cfg));
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct ieee80211_supported_band *bands[NUM_NL80211_BANDS];
	s32 phy_list, err, i, index;
	u32 band_list[3] = {0};
	u32 nmode, nband, bw_cap = 0;

	err = wland_fil_iovar_data_get(ifp, "get_phylist", &phy_list,
		sizeof(phy_list));
	if (err < 0) {
		wiphy_err(wiphy, "failed to get phylist: %d\n", err);
		return err;
	}

	err = wland_fil_iovar_data_get(ifp, "nmode", &nmode, sizeof(nmode));
	if (err < 0) {
		wiphy_err(wiphy, "failed to get nmode: %d\n", err);
	} else {
		err = wland_fil_iovar_data_get(ifp, "mimo_bw_cap", &bw_cap,
			sizeof(bw_cap));
		/* Fixed capabilities replace the queried values */
		bw_cap = 1;
		nmode = 1;
		band_list[0] = 0x01;
		band_list[1] = 0x02;
		band_list[2] = 0x00;
		if (err < 0)
			wiphy_err(wiphy, "failed to get mimo_bw_cap: %d\n", err);
	}

	err = wland_construct_reginfo(cfg, bw_cap);
	if (err < 0) {
		wiphy_err(wiphy, "failed to construct reginfo: %d\n", err);
		return err;
	}

	nband = band_list[0];
	memset(bands, 0, sizeof(bands));

	for (i = 1; i <= nband && i < ARRAY_SIZE(band_list); i++) {
		index = -1;
		if ((band_list[i] == WLC_BAND_2G)
			&& (__wl_band_2ghz.n_channels > 0)) {
			index = NL80211_BAND_2GHZ;
			bands[index] = &__wl_band_2ghz;

			if (bw_cap == WLC_N_BW_40ALL) {
				bands[index]->ht_cap.cap |=
					IEEE80211_HT_CAP_SGI_40;
				bands[index]->ht_cap.cap |=
					IEEE80211_HT_CAP_SUP_WIDTH_20_40;
			}
		}

		if ((index >= 0) && nmode) {
			bands[index]->ht_cap.ht_supported = true;
			bands[index]->ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;
			bands[index]->ht_cap.ampdu_factor =
				IEEE80211_HT_MAX_AMPDU_64K;
			bands[index]->ht_cap.ampdu_density =
				IEEE80211_HT_MPDU_DENSITY_16;
			/* MCS 0-7: all equal-modulation rates, one stream */
			bands[index]->ht_cap.mcs.rx_mask[0] = 0xFF;
		}
	}

	wiphy->bands[NL80211_BAND_2GHZ] = bands[NL80211_BAND_2GHZ];
	if (notify)
		wiphy_apply_custom_regulatory(wiphy, &wland_regdom);

	return err;
}

s32 wland_cfg80211_updata_mac(struct wland_cfg80211_info *cfg)
{
	int ret = 0;
	struct wland_private *drvr = cfg->pub;
	struct wland_if *ifp = drvr->iflist[P2PAPI_BSSCFG_PRIMARY];
	struct wland_if *p2p_ifp = drvr->iflist[P2PAPI_BSSCFG_DEVICE];
	u8 mac_addr[ETH_ALEN] = {0};

	ret = wland_efuse_get_mac_addr(ifp->ndev, NULL, 0, mac_addr);
	if (ret < 0 || !is_valid_ether_addr(mac_addr))
		return ret < 0 ? ret : -ENODATA;

	memcpy(ifp->mac_addr, mac_addr, ETH_ALEN);
	memcpy(ifp->ndev->dev_addr, mac_addr, ETH_ALEN);
	memcpy(ifp->ndev->perm_addr, mac_addr, ETH_ALEN);
	ifp->ndev->addr_assign_type = NET_ADDR_PERM;
	memcpy(cfg_to_wiphy(cfg)->perm_addr, mac_addr, ETH_ALEN);

	if (p2p_ifp) {
		wland_p2p_generate_bss_mac(&cfg->p2p, NULL);
		memcpy(p2p_ifp->mac_addr, cfg->p2p.dev_addr, ETH_ALEN);
		memcpy(p2p_ifp->ndev->dev_addr, p2p_ifp->mac_addr, ETH_ALEN);
	}

	/* The preinit command applies the eFuse address to firmware. */
	drvr->bus_if->up_data_mac = 0;
	netdev_info(ifp->ndev, "factory MAC address %pM\n", mac_addr);

	return ret;
}

s32 wland_cfg80211_up(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_info *cfg = ndev_to_cfg(ndev);
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	s32 err = 0;

	mutex_lock(&cfg->usr_sync);

	set_bit(VIF_STATUS_READY, &ifp->vif->sme_state);

	if (cfg->dongle_up)
		goto up_exit;

	err = wland_dongle_roam(ifp, (cfg->roam_on ? 0 : 1),
		WLAND_BEACON_TIMEOUT);
	if (err < 0)
		goto up_exit;

	err = wland_cfg80211_change_virtual_iface(wdev->wiphy, ndev,
						  wdev->iftype, NULL);
	if (err < 0)
		goto up_exit;

	err = wland_update_wiphybands(cfg, true);
	if (err)
		goto up_exit;

	wland_restore_power_save(ifp);

	cfg->dongle_up = true;
up_exit:
	mutex_unlock(&cfg->usr_sync);

	return err;
}

s32 wland_cfg80211_down(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_info *cfg = ndev_to_cfg(ndev);

	if (!cfg || !ifp) {
		netdev_err(ndev, "invalid parameter in cfg80211 down\n");
		return 0;
	}

	/* Disassociate before going down */
	mutex_lock(&cfg->usr_sync);
	if (wland_check_vif_up(ifp->vif)) {
		wland_link_down(ifp->vif);

		/* Let the disassociation events reach the supplicant */
		wland_delay(400);
	}
	wland_abort_scanning(cfg);
	clear_bit(VIF_STATUS_READY, &ifp->vif->sme_state);
	mutex_unlock(&cfg->usr_sync);

	if (ifp->bssidx == 0)
		cfg->dongle_up = false;

	return 0;
}

bool wland_vif_get_state_all(struct wland_cfg80211_info *cfg,
			     unsigned long state)
{
	struct wland_cfg80211_vif *vif;
	u8 result = 0;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		if (test_bit(state, &vif->sme_state))
			result++;
	}

	return result;
}

static inline bool
wland_vif_event_equals(struct wland_cfg80211_vif_event *event, u8 action)
{
	u8 evt_action;

	mutex_lock(&event->vif_event_lock);
	evt_action = event->action;
	mutex_unlock(&event->vif_event_lock);

	return evt_action == action;
}

void wland_cfg80211_arm_vif_event(struct wland_cfg80211_info *cfg,
	struct wland_cfg80211_vif *vif)
{
	struct wland_cfg80211_vif_event *event = &cfg->vif_event;

	mutex_lock(&event->vif_event_lock);
	event->vif = vif;
	event->action = 0;
	mutex_unlock(&event->vif_event_lock);
}

bool wland_cfg80211_vif_event_armed(struct wland_cfg80211_info *cfg)
{
	struct wland_cfg80211_vif_event *event = &cfg->vif_event;
	bool armed;

	mutex_lock(&event->vif_event_lock);
	armed = !!event->vif;
	mutex_unlock(&event->vif_event_lock);

	return armed;
}

int wland_cfg80211_wait_vif_event_timeout(struct wland_cfg80211_info *cfg,
	u8 action, unsigned long timeout)
{
	struct wland_cfg80211_vif_event *event = &cfg->vif_event;

	return wait_event_timeout(event->vif_wq,
		wland_vif_event_equals(event, action), timeout);
}

struct wland_cfg80211_info *wland_cfg80211_attach(struct wland_private *drvr,
	struct device *busdev)
{
	struct net_device *ndev = drvr->iflist[0]->ndev;
	struct wland_cfg80211_info *cfg;
	struct wiphy *wiphy;
	struct wland_cfg80211_vif *vif;
	struct wland_if *ifp = netdev_priv(ndev);
	s32 err = 0;

	if (!ndev) {
		dev_err(busdev, "invalid net_device in attach\n");
		return NULL;
	}

	wiphy = wland_setup_wiphy(busdev);
	if (IS_ERR(wiphy)) {
		dev_err(busdev, "failed to setup wiphy\n");
		return NULL;
	}

	cfg = wiphy_priv(wiphy);
	cfg->wiphy = wiphy;
	cfg->pub = drvr;

	init_waitqueue_head(&cfg->vif_event.vif_wq);
	init_waitqueue_head(&cfg->scanid_wait);

	mutex_init(&cfg->vif_event.vif_event_lock);

	INIT_LIST_HEAD(&cfg->vif_list);

	vif = wland_alloc_vif(cfg, NL80211_IFTYPE_STATION, false);
	if (IS_ERR(vif)) {
		wiphy_unregister(wiphy);
		wiphy_free(wiphy);
		dev_err(busdev, "failed to allocate vif\n");
		return NULL;
	}

	vif->ifp = ifp;
	vif->wdev.netdev = ndev;
	vif->profile.mode = WLAND_ERR_MODE;

	ndev->ieee80211_ptr = &vif->wdev;

	SET_NETDEV_DEV(ndev, wiphy_dev(cfg->wiphy));

	cfg->scan_request = NULL;
	memset(&cfg->escan_info, 0, sizeof(cfg->escan_info));
	/* power save stays off unless requested through cfg80211 */
	cfg->pwr_save = false;
	cfg->roam_on = true;
	cfg->active_scan = true;
	cfg->dongle_up = false;

	mutex_init(&cfg->usr_sync);
	mutex_init(&cfg->scan_result_lock);
	INIT_LIST_HEAD(&cfg->scan_result_list);
	cfg->scan_results.version = SCAN_VERSION_NUM;
	cfg->scan_results.count = 0;

	err = wland_init_priv_mem(cfg);
	if (err < 0)
		goto cfg80211_attach_out;

	wland_register_event_handlers(cfg);

	cfg->scan_info.ifp = ifp;
	cfg->scan_info.escan_state = SCAN_STATE_IDLE;

	timer_setup(&cfg->scan_timeout, wland_scan_timeout, 0);

	INIT_WORK(&cfg->scan_report_work, wland_cfg80211_scan_report_worker);

	if (cfg->conf)
		memset(cfg->conf, 0, sizeof(struct wland_cfg80211_conf));

	init_completion(&cfg->vif_disabled);
	cfg->in_disconnecting = false;
	cfg->in_waiting = false;
	init_completion(&cfg->disconnecting_wait);

	ifp->vif = vif;

	err = cfg80211_p2p_attach(cfg);
	if (err < 0) {
		wiphy_err(wiphy, "failed to initialize P2P: %d\n", err);
		goto cfg80211_p2p_attach_out;
	}

	err = wland_init_connect_info(cfg);
	if (err < 0) {
		wiphy_err(wiphy, "failed to init connect_info: %d\n", err);
		goto cfg80211_attach_out;
	}

	cfg->d11inf.io_type = WLAND_D11N_IOTYPE;

	wland_d11_attach(&cfg->d11inf);

	return cfg;

cfg80211_p2p_attach_out:
	cfg->dongle_up = false;
	wland_deinit_connect_info(cfg);
	wland_abort_scanning(cfg);
	wland_deinit_priv_mem(cfg);

cfg80211_attach_out:
	wland_free_vif(cfg, vif);
	wiphy_unregister(wiphy);
	wiphy_free(wiphy);
	return NULL;
}

void wland_cfg80211_detach(struct wland_cfg80211_info *cfg)
{
	struct wland_cfg80211_vif *vif;
	struct wland_cfg80211_vif *tmp;
	struct wland_bss_info_le *bss;
	struct wland_bss_info_le *bss_tmp;

	if (!cfg || IS_ERR(cfg)) {
		pr_err("invalid cfg pointer in detach\n");
		return;
	}

	cfg->dongle_up = false;

	wland_deinit_connect_info(cfg);
	wland_abort_scanning(cfg);
	wland_deinit_priv_mem(cfg);

	cfg80211_p2p_detach(&cfg->p2p);

	list_for_each_entry_safe(bss, bss_tmp, &cfg->scan_result_list, list)
		wland_free_bss(cfg, bss);

	list_for_each_entry_safe(vif, tmp, &cfg->vif_list, list)
		wland_free_vif(cfg, vif);

	wiphy_unregister(cfg->wiphy);
	wiphy_free(cfg->wiphy);
}
