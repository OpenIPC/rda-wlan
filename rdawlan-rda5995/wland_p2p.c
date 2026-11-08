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
#include <linux/random.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>

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

#define P2P_VER			9	/* Wi-Fi P2P v1.0 */
#define P2P_PUB_AF_CATEGORY	0x04
#define P2P_PUB_AF_ACTION	0x09
#define P2P_AF_CATEGORY		0x7F
#define P2P_OUI			"\x50\x6F\x9A"
#define P2P_OUI_LEN		3

#define DOT11_ACTION_HDR_LEN	2	/* action frame category + action */
#define DOT11_ACTION_CAT_OFF	0
#define DOT11_ACTION_ACT_OFF	1

#define P2P_AF_DWELL_TIME	200
#define P2P_AF_MIN_DWELL_TIME	100
#define P2P_AF_MED_DWELL_TIME	400
#define P2P_AF_LONG_DWELL_TIME	1000
#define P2P_AF_TX_MAX_RETRY	2
#define P2P_AF_MAX_WAIT_TIME	2000
#define P2P_INVALID_CHANNEL	-1
#define P2P_CHANNEL_SYNC_RETRY	3

#define P2P_AF_FRM_SCAN_MAX_WAIT	1500
#define P2P_DEFAULT_SLEEP_TIME_VSDB	200

/* WiFi P2P Public Action Frame OUI Subtypes */
#define P2P_PAF_GON_REQ		0	/* Group Owner Negotiation Req */
#define P2P_PAF_GON_RSP		1	/* Group Owner Negotiation Rsp */
#define P2P_PAF_GON_CONF	2	/* Group Owner Negotiation Confirm */
#define P2P_PAF_INVITE_REQ	3	/* P2P Invitation Request */
#define P2P_PAF_INVITE_RSP	4	/* P2P Invitation Response */
#define P2P_PAF_DEVDIS_REQ	5	/* Device Discoverability Request */
#define P2P_PAF_DEVDIS_RSP	6	/* Device Discoverability Response */
#define P2P_PAF_PROVDIS_REQ	7	/* Provision Discovery Request */
#define P2P_PAF_PROVDIS_RSP	8	/* Provision Discovery Response */
#define P2P_PAF_SUBTYPE_INVALID	255	/* Invalid Subtype */

/* WiFi P2P Action Frame OUI Subtypes */
#define P2P_AF_NOTICE_OF_ABSENCE	0	/* Notice of Absence */
#define P2P_AF_PRESENCE_REQ		1	/* P2P Presence Request */
#define P2P_AF_PRESENCE_RSP		2	/* P2P Presence Response */
#define P2P_AF_GO_DISC_REQ		3	/* GO Discoverability Request */

/* P2P Service Discovery related */
#define P2PSD_ACTION_CATEGORY		0x04	/* Public action frame */
#define P2PSD_ACTION_ID_GAS_IREQ	0x0A	/* GAS Initial Request AF */
#define P2PSD_ACTION_ID_GAS_IRESP	0x0B	/* GAS Initial Response AF */
#define P2PSD_ACTION_ID_GAS_CREQ	0x0C	/* GAS Comback Request AF */
#define P2PSD_ACTION_ID_GAS_CRESP	0x0D	/* GAS Comback Response AF */

/*
 * struct wland_p2p_disc_st_le - set discovery state in firmware.
 *
 * @state   : requested discovery state (see enum wland_p2p_disc_state).
 * @chspec  : channel parameter for %WL_P2P_DISC_ST_LISTEN state.
 * @dwell   : dwell time in ms for %WL_P2P_DISC_ST_LISTEN state.
 */
struct wland_p2p_disc_st_le {
	u8 state;
	__le16 chspec;
	__le16 dwell;
};

/*
 * enum wland_p2p_disc_state - P2P discovery state values
 *
 * @WL_P2P_DISC_ST_SCAN     :   P2P discovery with wildcard SSID and P2P IE.
 * @WL_P2P_DISC_ST_LISTEN   : P2P discovery off-channel for specified time.
 * @WL_P2P_DISC_ST_SEARCH   : P2P discovery with P2P wildcard SSID and P2P IE.
 */
enum wland_p2p_disc_state {
	WL_P2P_DISC_ST_SCAN,
	WL_P2P_DISC_ST_LISTEN,
	WL_P2P_DISC_ST_SEARCH,
	WL_P2P_CONNECT_SCAN_RDA
};



/*
 * struct wland_p2p_pub_act_frame - WiFi P2P Public Action Frame
 *
 * @category    : P2P_PUB_AF_CATEGORY
 * @action      : P2P_PUB_AF_ACTION
 * @oui[3]      : P2P_OUI
 * @oui_type    : OUI type - P2P_VER
 * @subtype     : OUI subtype - P2P_TYPE_*
 * @dialog_token: nonzero, identifies req/rsp transaction
 * @elts[1]     : Variable length information elements.
 */
struct wland_p2p_pub_act_frame {
	u8 category;
	u8 action;
	u8 oui[3];
	u8 oui_type;
	u8 subtype;
	u8 dialog_token;
	u8 elts[1];
};

/**
 * struct wland_p2p_action_frame - WiFi P2P Action Frame
 *
 * @category: P2P_AF_CATEGORY
 * @OUI[3]  : OUI - P2P_OUI
 * @type    : OUI Type - P2P_VER
 * @subtype : OUI Subtype - P2P_AF_*
 * @dialog_token: nonzero, identifies req/resp tranaction
 * @elts[1] : Variable length information elements.
 */
struct wland_p2p_action_frame {
	u8 category;
	u8 oui[3];
	u8 type;
	u8 subtype;
	u8 dialog_token;
	u8 elts[1];
};

/*
 * struct wland_p2psd_gas_pub_act_frame - Wi-Fi GAS Public Action Frame
 *
 * @category        : 0x04 Public Action Frame
 * @action          : 0x6c Advertisement Protocol
 * @dialog_token    : nonzero, identifies req/rsp transaction
 * @query_data[1]   : Query Data. SD gas ireq SD gas iresp
 */
struct wland_p2psd_gas_pub_act_frame {
	u8 category;
	u8 action;
	u8 dialog_token;
	u8 query_data[1];
};

/*
 * struct wland_config_af_params - Action Frame Parameters for tx.
 *
 * @search_channel  : 1: search peer's channel to send af
 * @extra_listen    : keep the dwell time to get af response frame.
 */
struct wland_config_af_params {
	bool search_channel;
	bool extra_listen;
};

/*
 * wland_p2p_is_pub_action() - true if p2p public type frame.
 *
 * @frame       : action frame data.
 * @frame_len   : length of action frame data.
 *
 * Determine if action frame is p2p public action type
 */
static bool wland_p2p_is_pub_action(void *frame, u32 frame_len)
{
	struct wland_p2p_pub_act_frame *pact_frm = frame;

	if (!frame)
		return false;

	if (frame_len < sizeof(struct wland_p2p_pub_act_frame) - 1)
		return false;

	if (pact_frm->category == P2P_PUB_AF_CATEGORY &&
	    pact_frm->action == P2P_PUB_AF_ACTION &&
	    pact_frm->oui_type == P2P_VER &&
	    !memcmp(pact_frm->oui, P2P_OUI, P2P_OUI_LEN))
		return true;

	return false;
}

/*
 * wland_p2p_is_p2p_action() - true if p2p action type frame.
 *
 * @frame       : action frame data.
 * @frame_len   : length of action frame data.
 *
 * Determine if action frame is p2p action type
 */
static bool wland_p2p_is_p2p_action(void *frame, u32 frame_len)
{
	struct wland_p2p_action_frame *act_frm = frame;

	if (!frame)
		return false;

	if (frame_len < sizeof(struct wland_p2p_action_frame) - 1)
		return false;

	if (act_frm->category == P2P_AF_CATEGORY &&
	    act_frm->type == P2P_VER &&
	    memcmp(act_frm->oui, P2P_OUI, P2P_OUI_LEN) == 0)
		return true;

	return false;
}

/*
 * wland_p2p_is_gas_action() - true if p2p gas action type frame.
 *
 * @frame: action frame data.
 * @frame_len: length of action frame data.
 *
 * Determine if action frame is p2p gas action type
 */
static bool wland_p2p_is_gas_action(void *frame, u32 frame_len)
{
	struct wland_p2psd_gas_pub_act_frame *sd_act_frm = frame;

	if (!frame)
		return false;

	if (frame_len < sizeof(struct wland_p2psd_gas_pub_act_frame) - 1)
		return false;

	if (sd_act_frm->category != P2PSD_ACTION_CATEGORY)
		return false;

	if (sd_act_frm->action == P2PSD_ACTION_ID_GAS_IREQ ||
	    sd_act_frm->action == P2PSD_ACTION_ID_GAS_IRESP ||
	    sd_act_frm->action == P2PSD_ACTION_ID_GAS_CREQ ||
	    sd_act_frm->action == P2PSD_ACTION_ID_GAS_CRESP)
		return true;

	return false;
}

/*
 * wland_p2p_set_firmware() - prepare firmware for peer-to-peer operation.
 *
 * @ifp     : ifp to use for iovars (primary).
 * @p2p_mac : mac address to configure for p2p_da_override
 */
static int wland_p2p_set_firmware(struct wland_if *ifp, u8 *p2p_mac)
{
	u8 val = 1;

	wland_fil_iovar_data_set(ifp, "apsta", &val, sizeof(u8));

	return 0;
}

/*
 * wland_p2p_generate_bss_mac() - derive mac addresses for P2P.
 *
 * @p2p     : P2P specific data.
 * @dev_addr: optional device address.
 *
 * P2P needs mac addresses for P2P device and interface. If no device
 * address it specified, these are derived from the primary net device, ie.
 * the permanent ethernet address of the device.
 */
void wland_p2p_generate_bss_mac(struct wland_p2p_info *p2p, u8 *dev_addr)
{
	struct wland_if *pri_ifp = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->ifp;
	bool local_admin = false;

	if (!dev_addr || is_zero_ether_addr(dev_addr)) {
		dev_addr = pri_ifp->mac_addr;
		local_admin = true;
	}

	/*
	 * Generate the P2P Device Address. This consists of the device's
	 * primary MAC address with the locally administered bit set.
	 */
	if (dev_addr)
		memcpy(p2p->dev_addr, dev_addr, ETH_ALEN);

	if (local_admin)
		p2p->dev_addr[0] ^= 0x04;
	/*
	 * Generate the P2P Interface Address. If the discovery and connection
	 * BSSCFGs need to simultaneously co-exist, then this address must be
	 * different from the P2P Device Address, but also locally administered.
	 */
	memcpy(p2p->int_addr, p2p->dev_addr, ETH_ALEN);
	p2p->int_addr[4] ^= 0x80;
}

/*
 * wland_p2p_scan_is_p2p_request() - is cfg80211 scan request a P2P scan.
 *
 * @request: the scan request as received from cfg80211.
 *
 * returns true if one of the ssids in the request matches the
 * P2P wildcard ssid; otherwise returns false.
 */

bool wland_p2p_scan_is_p2p_request(struct cfg80211_scan_request *request,
	struct wland_cfg80211_vif *vif)
{
	struct cfg80211_ssid *ssids = request->ssids;
	int i;

	if (vif->ifp->bssidx != P2PAPI_BSSCFG_PRIMARY)
		return true;

	for (i = 0; i < request->n_ssids; i++) {
		wiphy_dbg(vif->wdev.wiphy, "comparing SSID \"%.*s\"\n",
			  ssids[i].ssid_len, ssids[i].ssid);

		if (ssids[i].ssid_len == P2P_WILDCARD_SSID_LEN &&
		    !memcmp(P2P_WILDCARD_SSID, ssids[i].ssid,
			    P2P_WILDCARD_SSID_LEN))
			return true;
	}
	return false;
}

/*
 * wland_p2p_set_discover_state - set discover state in firmware.
 *
 * @ifp         : low-level interface object.
 * @state       : discover state to set.
 * @chanspec    : channel parameters (for state @WL_P2P_DISC_ST_LISTEN only).
 * @listen_ms   : duration to listen (for state @WL_P2P_DISC_ST_LISTEN only).
 */
static s32 wland_p2p_set_discover_state(struct wland_if *ifp, u8 state,
	u16 chanspec, u16 listen_ms)
{
	struct wland_p2p_disc_st_le discover_state;

	discover_state.state = state;
	discover_state.chspec = cpu_to_le16(chanspec);
	discover_state.dwell = cpu_to_le16(listen_ms);

	return wland_fil_iovar_data_set(ifp, "p2p_state", &discover_state,
		sizeof(discover_state));
}

/*
 * wland_p2p_deinit_discovery() - disable P2P device discovery.
 *
 * @p2p: P2P specific data.
 *
 * Resets the discovery state and disables it in firmware.
 */
static s32 wland_p2p_deinit_discovery(struct wland_p2p_info *p2p)
{
	u8 enable = 0;
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	wland_p2p_set_discover_state(vif->ifp, WL_P2P_DISC_ST_SCAN, 0, 0);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;

	return wland_fil_iovar_data_set(vif->ifp, "p2p_disc", &enable,
		sizeof(u8));
}

/*
 * wland_p2p_enable_discovery() - initialize and configure discovery.
 *
 * @p2p: P2P specific data.
 *
 * Initializes the discovery device and configure the virtual interface.
 */
static s32 wland_p2p_enable_discovery(struct wland_p2p_info *p2p)
{
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	s32 ret = 0;
	u8 enable = 1;

	if (!vif) {
		wiphy_err(p2p->cfg->wiphy,
			  "P2P config device not available\n");
		ret = -EPERM;
		goto exit;
	}

	if (test_bit(P2P_STATUS_ENABLED, &p2p->status)) {
		wiphy_dbg(p2p->cfg->wiphy,
			  "P2P config device already configured\n");
		goto exit;
	}

	vif = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;

	ret = wland_fil_iovar_data_set(vif->ifp, "p2p_disc", &enable,
		sizeof(u8));
	if (ret < 0) {
		netdev_err(vif->ifp->ndev, "failed to set P2P discovery: %d\n",
			   ret);
		goto exit;
	}
	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	ret = wland_p2p_set_discover_state(vif->ifp, WL_P2P_DISC_ST_SCAN, 0, 0);
	if (ret < 0) {
		netdev_err(vif->ifp->ndev,
			   "failed to set WL_P2P_DISC_ST_SCAN: %d\n", ret);
		goto exit;
	}

	/*
	 * Set wsec to any non-zero value in the discovery bsscfg
	 * to ensure our P2P probe responses have the privacy bit
	 * set in the 802.11 WPA IE. Some peer devices may not
	 * initiate WPS with us if this bit is not set.
	 */
	enable = AES_ENABLED;
	ret = wland_fil_iovar_data_set(vif->ifp, "wsec", &enable, sizeof(u8));
	if (ret < 0) {
		netdev_err(vif->ifp->ndev, "failed to configure security: %d\n",
			   ret);
		goto exit;
	}

	set_bit(P2P_STATUS_ENABLED, &p2p->status);

exit:
	return ret;
}

/*
 * wland_p2p_escan() - initiate a P2P scan.
 *
 * @p2p         : P2P specific data.
 * @num_chans   : number of channels to scan.
 * @chanspecs   : channel parameters for @num_chans channels.
 * @search_state: P2P discover state to use.
 * @action      : scan action to pass to firmware.
 * @bss_type    : type of P2P bss.
 */
static s32 wland_p2p_escan(struct wland_p2p_info *p2p, u32 num_chans,
	u16 chanspecs[], s32 search_state, u16 action)
{
	s32 ret = 0;
	u32 i;
	struct wland_cfg80211_vif *vif;
	struct wland_scan_params_le sparams;
	struct wland_ssid_le *scan_ssid = &sparams.ssid_le;

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	if (!vif) {
		wiphy_err(p2p->cfg->wiphy, "no vif for BSS type %d\n",
			  P2PAPI_BSSCFG_DEVICE);
		ret = -EINVAL;
		goto exit;
	}

	switch (search_state) {
	case WL_P2P_DISC_ST_SEARCH:
	case WL_P2P_DISC_ST_SCAN:
		/*
		 * A progressive p2p_find needs the P2P wildcard SSID;
		 * without an SSID the scan is a plain broadcast scan.
		 */
		scan_ssid->SSID_len = P2P_WILDCARD_SSID_LEN;
		memcpy(scan_ssid->SSID, P2P_WILDCARD_SSID,
		       P2P_WILDCARD_SSID_LEN);
		break;
	case WL_P2P_CONNECT_SCAN_RDA:
		scan_ssid->SSID_len = p2p->ssid.SSID_len;
		memcpy(scan_ssid->SSID, p2p->ssid.SSID, p2p->ssid.SSID_len);
		wiphy_dbg(p2p->cfg->wiphy,
			  "connect scan SSID: %s, SSID len: %d\n",
			  scan_ssid->SSID, scan_ssid->SSID_len);
		break;
	default:
		wiphy_err(p2p->cfg->wiphy, "invalid search state: %d\n",
			  search_state);
		ret = -EINVAL;
		goto exit;
	}

	wland_p2p_set_discover_state(vif->ifp, search_state, 0, 0);

	sparams.channel_num = num_chans;

	for (i = 0; i < num_chans; i++) {
		sparams.channel_list[i] = chanspecs[i];
		wiphy_dbg(p2p->cfg->wiphy, "scan chanspecs[%d] = 0x%x\n",
			  i, chanspecs[i]);
	}

	if (search_state == WL_P2P_CONNECT_SCAN_RDA) {
		ret = wland_p2p_connect_scan(vif->ifp, &sparams);
	} else if (num_chans == AF_PEER_SEARCH_CNT) {
		ret = wland_p2p_af_scan_set(vif->ifp, &sparams);
	} else {
		ret = wland_p2p_start_scan_set(vif->ifp, &sparams);
		if (!ret)
			set_bit(SCAN_STATUS_BUSY, &p2p->cfg->scan_status);
	}

exit:
	return ret;
}

/*
 * wland_p2p_run_escan() - escan callback for peer-to-peer.
 *
 * @cfg     : driver private data for cfg80211 interface.
 * @ndev    : net device for which scan is requested.
 * @request : scan request from cfg80211.
 * @action  : scan action.
 *
 * Determines the P2P discovery state based to scan request parameters and
 * validates the channels in the request.
 */
static s32 wland_p2p_run_escan(struct wland_cfg80211_info *cfg,
	struct wland_if *ifp, struct cfg80211_scan_request *request, u16 action)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;
	s32 search_state = WL_P2P_DISC_ST_SCAN;
	struct wland_cfg80211_vif *vif;
	struct net_device *dev = NULL;
	int i, num_nodfs = 0;
	u16 *chanspecs;

	if (!request) {
		err = -EINVAL;
		goto exit;
	}
	if ((request->n_channels == 1) || (request->n_channels == 2))
		mod_timer(&cfg->scan_timeout, jiffies + msecs_to_jiffies(400));
	else
		mod_timer(&cfg->scan_timeout, jiffies + msecs_to_jiffies(3000));

	if (request->n_channels) {
		chanspecs = kcalloc(request->n_channels, sizeof(*chanspecs),
				    GFP_KERNEL);
		if (!chanspecs) {
			err = -ENOMEM;
			goto exit;
		}
		vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

		if (vif)
			dev = vif->wdev.netdev;

		if (request->n_channels == 3 &&
			request->channels[0]->hw_value == SOCIAL_CHAN_1 &&
			request->channels[1]->hw_value == SOCIAL_CHAN_2 &&
			request->channels[2]->hw_value == SOCIAL_CHAN_3) {
			/* Social channels 1, 6 and 11 */
			search_state = WL_P2P_DISC_ST_SEARCH;
			wiphy_dbg(cfg->wiphy, "P2P search phase start\n");
		} else if (dev && vif->mode == WL_MODE_AP) {
			wiphy_dbg(cfg->wiphy,
				  "already a GO, doing search only\n");
			search_state = WL_P2P_DISC_ST_SEARCH;
		} else if (request->n_ssids == 1 &&
			   request->ssids->ssid_len >= P2P_WILDCARD_SSID_LEN &&
			   !memcmp(request->ssids->ssid, P2P_WILDCARD_SSID,
				   P2P_WILDCARD_SSID_LEN) &&
			   request->ssids->ssid_len != P2P_WILDCARD_SSID_LEN) {
			wiphy_dbg(cfg->wiphy,
				  "client connect scan, channels: %d\n",
				  request->n_channels);
			search_state = WL_P2P_CONNECT_SCAN_RDA;
		} else if (request->n_channels == 1 &&
			   request->n_ssids == 0) {
			wiphy_dbg(cfg->wiphy,
				  "client connect scan, channels: %d\n",
				  request->n_channels);
			search_state = WL_P2P_CONNECT_SCAN_RDA;
		} else {
			wiphy_dbg(cfg->wiphy, "P2P scan state start\n");
		}

		/* No P2P scanning on passive or DFS channels */
		for (i = 0; i < request->n_channels; i++) {
			struct ieee80211_channel *chan = request->channels[i];

			if (chan->flags & (IEEE80211_CHAN_RADAR |
					   IEEE80211_CHAN_NO_IR))
				continue;

			chanspecs[num_nodfs] =
				wland_channel_to_chanspec(&p2p->cfg->d11inf,
							  chan);
			wiphy_dbg(cfg->wiphy,
				  "%d: chan=%d, channel spec=%x\n", num_nodfs,
				  chan->hw_value, chanspecs[i]);
			num_nodfs++;
		}
		err = wland_p2p_escan(p2p, num_nodfs, chanspecs, search_state,
			action);
		kfree(chanspecs);
	}
exit:
	if (err)
		wiphy_err(cfg->wiphy, "failed to run escan: %d\n", err);
	return err;
}

static s32 wland_p2p_find_listen_channel(const u8 *ie, u32 ie_len)
{
	u8 channel_ie[5] = {0};
	s32 listen_channel;
	s32 err;

	err = cfg80211_get_p2p_attr(ie, ie_len,
				    IEEE80211_P2P_ATTR_LISTEN_CHANNEL,
				    channel_ie, sizeof(channel_ie));
	if (err < 0)
		return err;

	/* Listen channel attribute: country (3), operating class, channel */
	listen_channel = (s32)channel_ie[3 + 1];

	if (listen_channel == SOCIAL_CHAN_1 ||
	    listen_channel == SOCIAL_CHAN_2 ||
	    listen_channel == SOCIAL_CHAN_3)
		return listen_channel;

	return -EPERM;
}

static s32 wland_p2p_enable(struct wland_cfg80211_info *cfg, int re_enable)
{
	s32 err = 0;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	struct wland_private *drvr;
	u8 *buf;
	u8 val;

	atomic_set(&p2p->p2p_state, 1);
	drvr = vif->ifp->drvr;
	buf = drvr->prot->buf;

	mutex_lock(&drvr->proto_block);

	if (re_enable == 0) {
		val = NO_POWERSAVE;
		err = wland_push_wid(buf, WID_POWER_MANAGEMENT, &val,
				     sizeof(val), false);
		if (err < 0) {
			wiphy_err(cfg->wiphy, "failed to push WID: %d\n", err);
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += err;

		err = wland_push_wid(buf, WID_P2P_SET_DEV_ADDR, p2p->dev_addr,
				     ETH_ALEN, false);
		if (err < 0) {
			wiphy_err(cfg->wiphy, "failed to push WID: %d\n", err);
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += err;

		val = (u8)(p2p->afx_hdl.my_listen_chan);
		if (val != 0) {
			err = wland_push_wid(buf, WID_P2P_LISTEN_CHAN, &val,
					     sizeof(val), false);
			if (err < 0) {
				wiphy_err(cfg->wiphy, "failed to push WID: %d\n",
					  err);
				mutex_unlock(&drvr->proto_block);
				return -1;
			}
			buf += err;
		}
	}

	val = 1;
	err = wland_push_wid(buf, WID_P2P_ENABLE, &val, sizeof(val), false);
	if (err < 0) {
		wiphy_err(cfg->wiphy, "failed to push WID: %d\n", err);
		mutex_unlock(&drvr->proto_block);
		return -1;
	}
	buf += err;

	err = wland_proto_cdc_data(drvr,
				   buf - drvr->prot->buf + FMW_HEADER_LEN);
	if (err < 0)
		wiphy_err(cfg->wiphy, "failed to initialize P2P: %d\n", err);

	mutex_unlock(&drvr->proto_block);
	return err;
}

/*
 * wland_p2p_scan_prep() - prepare scan based on request.
 *
 * @wiphy   : wiphy device.
 * @request : scan request from cfg80211.
 * @vif     : vif on which scan request is to be executed.
 *
 * Prepare the scan appropriately for type of scan requested. Overrides the
 * escan .run() callback for peer-to-peer scanning.
 */
s32 wland_p2p_scan_prep(struct wiphy *wiphy,
			struct cfg80211_scan_request *request,
			struct wland_cfg80211_vif *vif)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;

	if (request->ssids) {
		p2p->ssid.SSID_len = min_t(u8, request->ssids->ssid_len,
					   DOT11_MAX_SSID_LEN);
		memcpy(p2p->ssid.SSID, request->ssids->ssid,
		       p2p->ssid.SSID_len);
	} else {
		p2p->ssid.SSID_len = 0;
	}
	err = wland_p2p_find_listen_channel(request->ie,
		request->ie_len);
	if (err < 0) {
		wiphy_err(wiphy, "failed to find listen channel\n");
		return err;
	}

	p2p->afx_hdl.my_listen_chan = err;

	clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
	wiphy_dbg(wiphy, "P2P: GO_NEG_PHASE status cleared\n");

	err = wland_p2p_enable_discovery(p2p);
	if (err < 0)
		return err;

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	cancel_work_sync(&p2p->p2p_alive_timeout_work);
	mod_timer(&p2p->p2p_alive_timer,
		jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
	atomic_set(&p2p->p2p_alive_timer_count, 0);

	cfg->scan_info.run = wland_p2p_run_escan;
	if (atomic_read(&p2p->p2p_state) == 0)
		wland_p2p_enable(cfg, 0);
	else if (atomic_read(&p2p->p2p_state) == 2)
		wland_p2p_enable(cfg, 1);
	wiphy_dbg(wiphy, "P2P: request_ie_len = %zu\n", request->ie_len);

	return wland_vif_set_mgmt_ie(vif, WLAND_VNDR_IE_PRBREQ_FLAG,
		request->ie, request->ie_len);
}

struct wland_remain_on_channel_para {
	u8 chnum;
	u32 duration;
} __packed;

/*
 * wland_p2p_discover_listen() - set firmware to discover listen state.
 *
 * @p2p: p2p device.
 * @channel: channel nr for discover listen.
 * @duration: time in ms to stay on channel.
 *
 */
static s32 wland_p2p_discover_listen(struct wland_p2p_info *p2p, u8 channel,
	u32 duration)
{
	struct wland_cfg80211_vif *vif;
	struct wland_chan ch;
	struct wland_remain_on_channel_para ch_para;
	s32 err = 0;

	wiphy_dbg(p2p->cfg->wiphy, "discover listen: channel %u, duration %u\n",
		  channel, duration);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	if (!vif) {
		wiphy_err(p2p->cfg->wiphy, "discovery is not set\n");
		err = -EPERM;
		goto exit;
	}

	if (test_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status)) {
		wiphy_err(p2p->cfg->wiphy, "previous listen not completed\n");
		/* Report success so the supplicant's cookie stays in step */
		goto exit;
	}

	ch.chnum = channel;
	ch.bw = CHAN_BW_20;

	p2p->cfg->d11inf.encchspec(&ch);

	ch_para.chnum = channel;
	ch_para.duration = cpu_to_le32(duration);

	err = wland_fil_set_cmd_data(vif->ifp, WID_P2P_START_LISTEN_REQ,
		&ch_para, sizeof(struct wland_remain_on_channel_para));

	if (!err) {
		set_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status);
		p2p->remain_on_channel_cookie++;
	}
exit:
	return err;
}

/*
 * wland_cfg80211_p2p_remain_on_channel() - put device on channel and stay
 * there.
 *
 * @wiphy   : wiphy device.
 * @channel : channel to stay on.
 * @duration: time in ms to remain on channel.
 *
 */

int wland_cfg80211_p2p_remain_on_channel(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 struct ieee80211_channel *channel,
					 unsigned int duration,
					 u64 *cookie)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;
	u8 channel_nr = ieee80211_frequency_to_channel(channel->center_freq);

	struct wland_cfg80211_vif *vif0 = cfg->pub->iflist[0]->vif;
	struct wland_cfg80211_vif *vif1 = cfg->pub->iflist[1]->vif;

	set_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

	atomic_set(&p2p->p2p_alive_timer_count, 0);

	if (timer_pending(&vif0->conn_info.connect_restorework_timeout) ||
	    timer_pending(&vif1->conn_info.connect_restorework_timeout) ||
	    test_bit(VIF_STATUS_CONNECTING, &vif0->sme_state) ||
	    test_bit(VIF_STATUS_CONNECTING, &vif1->sme_state)) {
		wiphy_dbg(wiphy, "getting IP, delay scan\n");
		p2p->remain_on_channel_cookie++;
		*cookie = p2p->remain_on_channel_cookie;
		memcpy(&p2p->remain_on_channel, channel, sizeof(*channel));
		schedule_delayed_work(&p2p->delay_remain_onchannel_work,
				      msecs_to_jiffies(duration));
	} else {
		if (p2p->afx_hdl.my_listen_chan == 0)
			p2p->afx_hdl.my_listen_chan = channel_nr;
		else if (p2p->afx_hdl.my_listen_chan != channel_nr) {
			wiphy_err(wiphy,
				  "listen channel mismatch: %d, using %d\n",
				  p2p->afx_hdl.my_listen_chan, channel_nr);
			p2p->afx_hdl.my_listen_chan = channel_nr;
		}

		if (atomic_read(&p2p->p2p_state) == 0)
			wland_p2p_enable(cfg, 0);
		else if (atomic_read(&p2p->p2p_state) == 2)
			wland_p2p_enable(cfg, 1);

		err = wland_p2p_enable_discovery(p2p);
		if (err) {
			wiphy_dbg(wiphy, "failed to enable P2P discovery: %d\n",
				  err);
			goto exit;
		}

		err = wland_p2p_discover_listen(p2p, channel_nr, duration);
		if (err) {
			wiphy_dbg(wiphy, "failed to start P2P listen: %d\n",
				  err);
			goto exit;
		}

		memcpy(&p2p->remain_on_channel, channel, sizeof(*channel));
		*cookie = p2p->remain_on_channel_cookie;
	}

	cfg80211_ready_on_channel(wdev, *cookie, channel, duration,
				  GFP_KERNEL);

exit:
	return err;
}

/*
 * wland_notify_p2p_listen_complete() - p2p listen has completed.
 *
 * @ifp             : interfac control.
 * @e: event message. Not used, to make it usable for fweh event dispatcher.
 * @data            : payload of message. Not used.
 *
 */
s32 wland_notify_p2p_listen_complete(struct wland_if *ifp,
				     const struct wland_event_msg *e,
				     void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wireless_dev *wdev = &ifp->vif->wdev;

	if (test_and_clear_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status)) {
		if (test_and_clear_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN,
				       &p2p->status)) {
			clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
				  &p2p->status);
			wiphy_dbg(cfg->wiphy,
				  "listen done, wake up wait_next_af\n");
			complete(&p2p->wait_next_af);
		}
		cfg80211_remain_on_channel_expired(
			wdev, p2p->remain_on_channel_cookie,
			&p2p->remain_on_channel, GFP_KERNEL);
	}
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

	return 0;
}

/*
 * wland_p2p_cancel_remain_on_channel() - cancel p2p listen state.
 *
 * @ifp: interfac control.
 *
 */
void wland_p2p_cancel_remain_on_channel(struct wland_if *ifp)
{
	struct wland_cfg80211_info *cfg;

	if (!ifp)
		return;
	cfg = ifp->drvr->config;
	wland_p2p_set_discover_state(ifp, WL_P2P_DISC_ST_SCAN, 0, 0);

	wland_notify_p2p_listen_complete(ifp, NULL, NULL);
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);
}

/*
 * wland_p2p_act_frm_search() - search function for action frame.
 *
 * @p2p: p2p device.
 * channel: channel on which action frame is to be trasmitted.
 *
 * search function to reach at common channel to send action frame. When
 * channel is 0 then all social channels will be used to send af
 */
static s32 wland_p2p_act_frm_search(struct wland_p2p_info *p2p, u16 channel)
{
	s32 err;
	u32 channel_cnt, i;
	u16 *default_chan_list;
	struct wland_chan ch;

	if (channel)
		channel_cnt = AF_PEER_SEARCH_CNT;
	else
		channel_cnt = SOCIAL_CHAN_CNT;

	default_chan_list = kcalloc(channel_cnt, sizeof(*default_chan_list),
				    GFP_KERNEL);
	if (!default_chan_list) {
		err = -ENOMEM;
		goto exit;
	}
	ch.bw = CHAN_BW_20;

	if (channel) {
		ch.chnum = channel;
		p2p->cfg->d11inf.encchspec(&ch);
		for (i = 0; i < channel_cnt; i++)
			default_chan_list[i] = ch.chspec;
	} else {
		ch.chnum = SOCIAL_CHAN_1;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[0] = ch.chspec;
		ch.chnum = SOCIAL_CHAN_2;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[1] = ch.chspec;
		ch.chnum = SOCIAL_CHAN_3;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[2] = ch.chspec;
	}
	err = wland_p2p_escan(p2p,
		channel_cnt,
		default_chan_list,
		WL_P2P_DISC_ST_SEARCH, SCAN_ACTION_START);
	kfree(default_chan_list);
exit:
	return err;
}

/*
 * wland_p2p_afx_handler() - afx worker thread.
 *
 * @work: the afx_work member of struct afx_hdl.
 */
static void wland_p2p_afx_handler(struct work_struct *work)
{
	struct afx_hdl *afx_hdl = container_of(work, struct afx_hdl, afx_work);
	struct wland_p2p_info *p2p =
		container_of(afx_hdl, struct wland_p2p_info, afx_hdl);
	s32 err;

	if (!afx_hdl->is_active)
		return;

	wiphy_dbg(p2p->cfg->wiphy,
		  "afx_hdl->is_listen = %d, afx_hdl->my_listen_chan = %d\n",
		  afx_hdl->is_listen, afx_hdl->my_listen_chan);

	if (afx_hdl->is_listen && afx_hdl->my_listen_chan)
		/* Listen for a random 100, 200 or 300 ms */
		err = wland_p2p_discover_listen(p2p, afx_hdl->my_listen_chan,
						100 * (1 + prandom_u32() % 3));
	else
		err = wland_p2p_act_frm_search(p2p, afx_hdl->peer_listen_chan);

	if (err) {
		wiphy_err(p2p->cfg->wiphy,
			  "failed to transmit action frame: %d\n", err);

		if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status))
			complete(&afx_hdl->act_frm_scan);
	}
}

/*
 * wland_p2p_af_searching_channel() - search channel.
 *
 * @p2p: p2p device info struct.
 *
 */
static s32 wland_p2p_af_searching_channel(struct wland_p2p_info *p2p)
{
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_cfg80211_vif *pri_vif =
		p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;
	ulong duration;
	s32 retry = 0;

	reinit_completion(&afx_hdl->act_frm_scan);

	set_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status);

	afx_hdl->is_active = true;
	afx_hdl->peer_chan = P2P_INVALID_CHANNEL;

	/*
	 * Loop to wait until we find a peer's channel or the pending action
	 * frame tx is cancelled.
	 */
	duration = msecs_to_jiffies(P2P_AF_FRM_SCAN_MAX_WAIT);

	while ((retry < P2P_CHANNEL_SYNC_RETRY) &&
	       (afx_hdl->peer_chan == P2P_INVALID_CHANNEL)) {
		afx_hdl->is_listen = false;
		wiphy_dbg(p2p->cfg->wiphy,
			  "scheduling action frame transmission (%d)\n",
			  retry);
		schedule_work(&afx_hdl->afx_work);
		wait_for_completion_timeout(&afx_hdl->act_frm_scan, duration);

		if ((afx_hdl->peer_chan != P2P_INVALID_CHANNEL) ||
		    (!test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
			       &p2p->status))) {
			break;
		}

		retry++;

		if (test_bit(VIF_STATUS_CONNECTED, &pri_vif->sme_state) ||
		    test_bit(VIF_STATUS_CONNECTING, &pri_vif->sme_state))
			msleep(P2P_DEFAULT_SLEEP_TIME_VSDB);
	}

	wiphy_dbg(p2p->cfg->wiphy, "completed search/listen peer_chan=%d\n",
		  afx_hdl->peer_chan);
	afx_hdl->is_active = false;

	clear_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status);

	return afx_hdl->peer_chan;
}
/*
 * wland_p2p_scan_finding_common_channel() - was escan used for finding channel
 *
 * @cfg : common configuration struct.
 * @bi  : bss info struct, result from scan.
 *
 */
bool wland_p2p_scan_finding_common_channel(struct wland_cfg80211_info *cfg,
					   struct wland_bss_info_le *bi)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_chan ch;
	s32 err = 0;
	u8 p2p_dev_addr[ETH_ALEN];

	if (!test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status))
		return false;

	if (!bi) {
		wiphy_dbg(cfg->wiphy, "action frame scan done\n");
		if (afx_hdl->peer_chan == P2P_INVALID_CHANNEL)
			complete(&afx_hdl->act_frm_scan);
		return true;
	}

	memset(p2p_dev_addr, 0, sizeof(p2p_dev_addr));
	err = cfg80211_get_p2p_attr(bi->ie,
				    bi->ie_length,
				    IEEE80211_P2P_ATTR_DEVICE_INFO,
				    p2p_dev_addr, sizeof(p2p_dev_addr));
	if (err < 0)
		err = cfg80211_get_p2p_attr(bi->ie,
					    bi->ie_length,
					    IEEE80211_P2P_ATTR_DEVICE_ID,
					    p2p_dev_addr, sizeof(p2p_dev_addr));
	if ((err >= 0)
		&& (!memcmp(p2p_dev_addr, afx_hdl->tx_dst_addr, ETH_ALEN))) {
		if (!bi->ctl_ch) {
			ch.chspec = bi->chanspec;
			cfg->d11inf.decchspec(&ch);
			bi->ctl_ch = ch.chnum;
		}
		afx_hdl->peer_chan = bi->ctl_ch;
		wiphy_dbg(cfg->wiphy,
			  "action frame scan: peer %pM found, channel: %d\n",
			  afx_hdl->tx_dst_addr, afx_hdl->peer_chan);
		complete(&afx_hdl->act_frm_scan);
	}
	return true;
}

/*
 * wland_p2p_stop_wait_next_action_frame() - finish scan if af tx complete.
 *
 * @cfg: common configuration struct.
 */
static void
wland_p2p_stop_wait_next_action_frame(struct wland_cfg80211_info *cfg)
{
	struct wland_p2p_info *p2p = &cfg->p2p;

	if (test_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status) &&
	    (test_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status) ||
	     test_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status))) {
		wiphy_dbg(cfg->wiphy, "abort actframe iovar\n");
	} else if (test_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN, &p2p->status)) {
		clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
			  &p2p->status);
		wiphy_dbg(cfg->wiphy,
			  "RX frame done, wake up wait_next_af\n");
		complete(&p2p->wait_next_af);
	}
}

/*
 * wland_p2p_gon_req_collision() - Check if go negotiaton collission
 *
 * @p2p: p2p device info struct.
 *
 * return true if recevied action frame is to be dropped.
 */
static bool wland_p2p_gon_req_collision(struct wland_p2p_info *p2p, u8 *mac)
{
	struct wland_cfg80211_info *cfg = p2p->cfg;
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;

	if (!test_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status) ||
	    !p2p->gon_req_action)
		return false;

	wiphy_dbg(cfg->wiphy, "GO negotiation request collision\n");

	/*
	 * if sa(peer) addr is less than da(my) addr, then this device
	 * process peer's gon request and block to send gon req.
	 * if not (sa addr > da addr), this device will process gon request
	 * and drop gon req of peer.
	 */
	if (memcmp(mac, ifp->mac_addr, ETH_ALEN) < 0) {
		wiphy_dbg(cfg->wiphy,
			  "block transmit of GO negotiation request\n");
		p2p->block_gon_req_tx = true;
		/*
		 * if we are finding a common channel for sending af, do not
		 * scan more to block to send current gon req
		 */
		if (test_and_clear_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
				       &p2p->status))
			complete(&p2p->afx_hdl.act_frm_scan);
		if (test_and_clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
				       &p2p->status))
			wland_p2p_stop_wait_next_action_frame(cfg);

		return false;
	}

	wiphy_dbg(cfg->wiphy, "drop received GO negotiation request\n");

	return true;
}

/*
 * wland_notify_p2p_action_frame_rx() - received action frame.
 *
 * @ifp : interfac control.
 * @e   : event message. Not used, to make it usable for fweh event dispatcher.
 * @data: payload of message, containing action frame data.
 *
 */
s32 wland_notify_p2p_action_frame_rx(struct wland_if *ifp,
				     const struct wland_event_msg *e,
				     void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	u8 *local_data = (u8 *)data;
	u16 wid_len;
	u8 channel_num;
	u32 mgmt_frame_len;
	struct wland_p2p_pub_act_frame *act_frm;
	struct wland_p2psd_gas_pub_act_frame *sd_act_frm;
	struct ieee80211_mgmt *mgmt_frame =
		(struct ieee80211_mgmt *)(local_data + 10);
	struct wland_cfg80211_vif *vif = ifp->vif;
	void *payload;
	u32 payload_len;
	s32 freq;
	u16 mgmt_type;
	u8 action;

	/* The action frame follows the WID header and a channel byte */
	if (e->datalen < 10)
		return -EINVAL;
	wid_len = local_data[6] | local_data[7] << 8;
	if (wid_len < MAC_HDR_LEN || wid_len > e->datalen - 10)
		return -EINVAL;
	channel_num = local_data[9];
	mgmt_frame_len = wid_len;

	wiphy_dbg(cfg->wiphy, "mgmt_frame_len: 0x%04x, channel: 0x%04x\n",
		  mgmt_frame_len, channel_num);
	wiphy_dbg(cfg->wiphy, "ifp->vif->mgmt_rx_reg 0x%04x\n",
		  vif->mgmt_rx_reg);

	mgmt_type = (IEEE80211_STYPE_ACTION & IEEE80211_FCTL_STYPE) >> 4;

	if ((vif->mgmt_rx_reg & BIT(mgmt_type)) == 0)
		return 0;

	action = P2P_PAF_SUBTYPE_INVALID;
	payload = (void *)mgmt_frame + offsetof(struct ieee80211_mgmt, u);
	payload_len = mgmt_frame_len - MAC_HDR_LEN;

	if (wland_p2p_is_pub_action(payload, payload_len)) {
		act_frm = (struct wland_p2p_pub_act_frame *)payload;
		action = act_frm->subtype;

		wiphy_dbg(cfg->wiphy, "public action frame received: %d\n",
			  action);

		if (action == P2P_PAF_GON_REQ &&
		    wland_p2p_gon_req_collision(p2p, (u8 *)e->addr)) {
			if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
				     &p2p->status) &&
			    (memcmp(afx_hdl->tx_dst_addr, e->addr,
				    ETH_ALEN) == 0)) {
				wiphy_dbg(cfg->wiphy,
					  "GO negotiation request: peer found, channel: %d\n",
					  channel_num);
				afx_hdl->peer_chan = channel_num;
				complete(&afx_hdl->act_frm_scan);
			}
			return 0;
		}

		if (action == P2P_PAF_GON_CONF) {
			wiphy_dbg(cfg->wiphy,
				  "P2P: GO_NEG_PHASE status cleared\n");
			clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		}
	} else if (wland_p2p_is_gas_action(payload, payload_len)) {
		sd_act_frm = (struct wland_p2psd_gas_pub_act_frame *)payload;
		action = sd_act_frm->action;
		wiphy_dbg(cfg->wiphy, "GAS action frame received: %u\n",
			  action);
	}

	if (test_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status) &&
	    (p2p->next_af_subtype == action)) {
		wiphy_dbg(cfg->wiphy, "received expected next frame (%d)\n",
			  action);
		clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);
		wland_p2p_stop_wait_next_action_frame(cfg);
	}

	freq = ieee80211_channel_to_frequency(
		channel_num,
		(channel_num <= CH_MAX_2G_CHANNEL) ?
		NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);

	print_hex_dump_debug("RX ACTION FRAME: ", DUMP_PREFIX_OFFSET,
			     16, 1, mgmt_frame, mgmt_frame_len, true);

	cfg80211_rx_mgmt(&vif->wdev, freq, 0, (u8 *)mgmt_frame,
			 mgmt_frame_len, 0);

	return 0;
}

/*
 * wland_notify_p2p_action_tx_complete() - transmit action frame complete
 *
 * @ifp : interfac control.
 * @e   : event message. Not used, to make it usable for fweh event dispatcher.
 * @data: not used.
 *
 */
s32 wland_notify_p2p_action_tx_complete(struct wland_if *ifp,
					const struct wland_event_msg *e,
					void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;

	wiphy_dbg(cfg->wiphy, "event %s, status=%d\n",
		  e->event_code == WLAND_E_ACT_FRAME_OFF_CHAN_COMPLETE ?
		  "ACTION_FRAME_OFF_CHAN_COMPLETE" : "ACTION_FRAME_COMPLETE",
		  e->status);

	if (!test_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status))
		return 0;

	if (e->event_code == WLAND_E_ACT_FRAME_COMPLETE) {
		if (e->status == STATUS_SUCCESS) {
			set_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
		} else {
			set_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);
			/*
			 * If there is no ack, we don't need to wait for
			 * WLC_E_ACTION_FRAME_OFFCHAN_COMPLETE event
			 */
			wland_p2p_stop_wait_next_action_frame(cfg);
		}
	}

	complete(&p2p->send_af_done);

	return 0;
}

/*
 * wland_p2p_tx_action_frame() - send action frame over fil.
 *
 * @p2p      : p2p info struct for vif.
 * @af_params: action frame data/info.
 *
 * Send an action frame immediately without doing channel synchronization.
 *
 * This function waits for a completion event before returning.
 * The WLC_E_ACTION_FRAME_COMPLETE event will be received when the action
 * frame is transmitted.
 */
static s32 wland_p2p_tx_action_frame(struct wland_p2p_info *p2p,
				     struct wland_fil_af_params_le *af_params)
{
	struct wland_cfg80211_vif *vif;
	s32 err = 0;

	reinit_completion(&p2p->send_af_done);

	clear_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
	clear_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	wiphy_dbg(p2p->cfg->wiphy, "tx af channel = %x\n", af_params->channel);

	err = wland_fil_set_cmd_data(vif->ifp, WID_P2P_ACTION_TX, af_params,
				     WLAND_FIL_AF_PARAMS_HDR_LEN +
				     WLAND_FIL_ACTION_FRAME_HDR_LEN +
				     af_params->action_frame.len);

	print_hex_dump_debug("TX ACTION FRAME: ", DUMP_PREFIX_OFFSET,
			     16, 1, af_params,
			     (WLAND_FIL_AF_PARAMS_HDR_LEN +
			      WLAND_FIL_ACTION_FRAME_HDR_LEN +
			      af_params->action_frame.len), true);
	if (err < 0) {
		wiphy_err(p2p->cfg->wiphy,
			  "failed to send action frame: %d\n", err);
		goto exit;
	}

	p2p->af_sent_channel = le32_to_cpu(af_params->channel);
	p2p->af_tx_sent_jiffies = jiffies;

	wait_for_completion_timeout(&p2p->send_af_done,
				    msecs_to_jiffies(P2P_AF_MAX_WAIT_TIME));

	if (test_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status)) {
		wiphy_dbg(p2p->cfg->wiphy,
			  "action frame transmission succeeded\n");
	} else {
		err = -EIO;
		wiphy_err(p2p->cfg->wiphy,
			  "failed to transmit action frame\n");
	}

	clear_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
	clear_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);

exit:
	return err;
}

/*
 * wland_p2p_pub_af_tx() - public action frame tx routine.
 *
 * @cfg             : driver private data for cfg80211 interface.
 * @af_params       : action frame data/info.
 * @config_af_params: configuration data for action frame.
 *
 * routine which transmits ation frame public type.
 */
static s32 wland_p2p_pub_af_tx(struct wland_cfg80211_info *cfg,
			       struct wland_fil_af_params_le *af_params,
			       struct wland_config_af_params *config_af_params)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_fil_action_frame_le *action_frame =
		&af_params->action_frame;
	struct wland_p2p_pub_act_frame *act_frm =
		(struct wland_p2p_pub_act_frame *)(action_frame->data);
	s32 err = 0;
	u16 ie_len;

	config_af_params->extra_listen = true;

	switch (act_frm->subtype) {
	case P2P_PAF_GON_REQ:
		wiphy_dbg(cfg->wiphy, "P2P: GO_NEG_PHASE status set\n");
		set_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		config_af_params->search_channel = true;

		p2p->next_af_subtype = act_frm->subtype + 1;
		p2p->gon_req_action = true;
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_GON_RSP:
		p2p->next_af_subtype = act_frm->subtype + 1;
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		wiphy_dbg(cfg->wiphy, "sending P2P_PAF_GON_RSP\n");
		break;
	case P2P_PAF_GON_CONF:
		wiphy_dbg(cfg->wiphy, "P2P: GO_NEG_PHASE status cleared\n");
		clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_INVITE_REQ:
		config_af_params->search_channel = true;
		p2p->next_af_subtype = act_frm->subtype + 1;
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_INVITE_RSP:
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_DEVDIS_REQ:
		config_af_params->search_channel = true;
		p2p->next_af_subtype = act_frm->subtype + 1;
		af_params->dwell_time = cpu_to_le32(P2P_AF_LONG_DWELL_TIME);
		break;
	case P2P_PAF_DEVDIS_RSP:
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_PROVDIS_REQ:
		ie_len = le16_to_cpu(action_frame->len) -
			offsetof(struct wland_p2p_pub_act_frame, elts);
		if (cfg80211_get_p2p_attr(&act_frm->elts[0], ie_len,
					  IEEE80211_P2P_ATTR_GROUP_ID,
					  NULL, 0) < 0)
			config_af_params->search_channel = true;
		p2p->next_af_subtype = act_frm->subtype + 1;
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_PROVDIS_RSP:
		/* wpa_supplicant sends GO neg req right after prov disc */
		p2p->next_af_subtype = P2P_PAF_GON_REQ;
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		config_af_params->extra_listen = false;
		wiphy_dbg(cfg->wiphy, "sending P2P_PAF_PROVDIS_RSP\n");
		break;
	default:
		wiphy_err(cfg->wiphy,
			  "unknown P2P public action frame subtype: %d\n",
			  act_frm->subtype);
		err = -EINVAL;
		break;
	}
	return err;
}

/*
 * wland_p2p_send_action_frame() - send action frame .
 *
 * @cfg			: driver private data for cfg80211 interface.
 * @ndev		: net device to transmit on.
 * @af_params	: configuration data for action frame.
 */
bool wland_p2p_send_action_frame(struct wland_cfg80211_info *cfg,
				 struct net_device *ndev,
				 struct wland_fil_af_params_le *af_params)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_fil_action_frame_le *action_frame;
	struct wland_config_af_params config_af_params;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	u16 action_frame_len;
	bool ack = false;
	u8 category, action;
	s32 tx_retry;

	action_frame = &af_params->action_frame;
	action_frame_len = le16_to_cpu(action_frame->len);

	if (action_frame_len < 2) {
		netdev_err(ndev, "action frame too short: %u\n",
			   action_frame_len);
		return false;
	}

	/*
	 * Add the default dwell time. Dwell time to stay off-channel
	 * to wait for a response action frame after transmitting an
	 * GO Negotiation action frame
	 */
	af_params->dwell_time = cpu_to_le32(P2P_AF_DWELL_TIME);

	category = action_frame->data[DOT11_ACTION_CAT_OFF];
	action = action_frame->data[DOT11_ACTION_ACT_OFF];

	p2p->next_af_subtype = P2P_PAF_SUBTYPE_INVALID;
	p2p->gon_req_action = false;

	config_af_params.search_channel = false;
	config_af_params.extra_listen = false;

	if (wland_p2p_is_pub_action(action_frame->data, action_frame_len)) {
		if (wland_p2p_pub_af_tx(cfg, af_params, &config_af_params)) {
			/*
			 * Just send unknown subtype frame with
			 * default parameters.
			 */
			netdev_err(ndev,
				   "unknown P2P public action frame subtype\n");
		}
	} else if (wland_p2p_is_gas_action(action_frame->data,
			action_frame_len)) {
		if (action == P2PSD_ACTION_ID_GAS_IREQ ||
		    action == P2PSD_ACTION_ID_GAS_CREQ) {
			config_af_params.search_channel = true;
			p2p->next_af_subtype = action + 1;
			af_params->dwell_time =
				cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		} else if (action == P2PSD_ACTION_ID_GAS_IRESP ||
			   action == P2PSD_ACTION_ID_GAS_CRESP) {
			af_params->dwell_time =
				cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		} else {
			netdev_err(ndev, "unknown action type: %d\n", action);
			goto exit;
		}
	} else if (wland_p2p_is_p2p_action(action_frame->data,
			action_frame_len)) {
		/* Sent with default configuration */
	} else {
		netdev_err(ndev,
			   "unknown action frame: category 0x%x, action 0x%x\n",
			   category, action);
		return false;
	}

	/*
	 * if connecting on primary iface, sleep for a while before sending
	 * af tx for VSDB
	 */
	if (test_bit(VIF_STATUS_CONNECTING,
		     &p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->sme_state))
		msleep(50);

	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
		wland_abort_scanning(cfg);

	memcpy(afx_hdl->tx_dst_addr, action_frame->da, ETH_ALEN);

	if (p2p->next_af_subtype != P2P_PAF_SUBTYPE_INVALID)
		set_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);

	p2p->af_sent_channel = 0;

	set_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status);

	netdev_dbg(ndev, "config_af_params.search_channel = %d\n",
		   config_af_params.search_channel);

	if (config_af_params.search_channel &&
	    IS_P2P_SOCIAL_CHANNEL(le32_to_cpu(af_params->channel)) &&
	    p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->saved_ie.probe_req_ie_len) {
		afx_hdl = &p2p->afx_hdl;
		afx_hdl->peer_listen_chan = le32_to_cpu(af_params->channel);

		if (wland_p2p_af_searching_channel(p2p) ==
		    P2P_INVALID_CHANNEL) {
			netdev_err(ndev,
				   "failed to find peer channel, using default: %d\n",
				   le32_to_cpu(af_params->channel));
		} else {
			/*
			 * Abort the scan here as well: the firmware aborts it
			 * only after its piggyback check, also for VSDB.
			 */
			wland_notify_escan_complete(cfg, ifp, true, true);

			af_params->channel = cpu_to_le32(afx_hdl->peer_chan);
		}
	}
	tx_retry = 0;

	while (!p2p->block_gon_req_tx && (ack == 0) &&
	       (tx_retry < P2P_AF_TX_MAX_RETRY)) {
		ack = !wland_p2p_tx_action_frame(p2p, af_params);
		if (ack == 0) {
			netdev_err(ndev,
				   "failed to send action frame (retry %d)\n",
				   tx_retry);
			afx_hdl = &p2p->afx_hdl;
			afx_hdl->peer_listen_chan =
				le32_to_cpu(af_params->channel);
			if (wland_p2p_af_searching_channel(p2p) ==
			    P2P_INVALID_CHANNEL) {
				netdev_err(ndev,
					   "no peer channel, using default: %d\n",
					   le32_to_cpu(af_params->channel));
			}
		}
		tx_retry++;
	}

	if (!ack)
		clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);

exit:
	clear_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status);

	if (p2p->block_gon_req_tx) {
		/* Reporting an ACK makes the supplicant wait another 100 ms */
		p2p->block_gon_req_tx = false;
		ack = true;
	}

	clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);

	return ack;
}

/*
 * wland_notify_p2p_rx_mgmt_probereq() - Event handler for p2p probe req.
 *
 * @ifp : interface pointer for which event was received.
 * @e   : even message.
 * @data: payload of event message (probe request).
 */
s32 wland_notify_p2p_rx_mgmt_probereq(struct wland_if *ifp,
				      const struct wland_event_msg *e,
				      void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_rx_async_mgmt_data *rxframe = data;
	u8 *frame = (u8 *)(data + rxframe->offset);
	u32 mgmt_frame_len = rxframe->length;
	s32 freq;
	u16 mgmt_type;

	if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status) &&
	    !memcmp(afx_hdl->tx_dst_addr, e->addr, ETH_ALEN)) {
		afx_hdl->peer_chan = rxframe->chnum;
		wiphy_dbg(cfg->wiphy,
			  "probe request: peer found, channel: %d\n",
			  afx_hdl->peer_chan);
		complete(&afx_hdl->act_frm_scan);
	}

	/*
	 * The firmware reports each probe request once per bsscfg; only the
	 * copies for nonzero bsscfg indices are passed to the supplicant.
	 */
	if (e->bsscfgidx == 0)
		return 0;

	if (test_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status)) {
		wiphy_dbg(cfg->wiphy,
			  "filtering P2P probe request in GO negotiation phase\n");
		return 0;
	}

	wiphy_dbg(cfg->wiphy, "vif->mgmt_rx_reg 0x%04x\n", vif->mgmt_rx_reg);

	mgmt_type = (IEEE80211_STYPE_PROBE_REQ & IEEE80211_FCTL_STYPE) >> 4;

	if ((vif->mgmt_rx_reg & BIT(mgmt_type)) == 0)
		return 0;

	freq = ieee80211_channel_to_frequency(
		rxframe->chnum,
		(rxframe->chnum <= CH_MAX_2G_CHANNEL) ?
		NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);

	cfg80211_rx_mgmt(&vif->wdev, freq, 0, frame, mgmt_frame_len, 0);

	wiphy_dbg(cfg->wiphy,
		  "mgmt_frame_len(%d), datalen(%d), freq(%d)\n",
		  mgmt_frame_len, e->datalen, freq);

	return 0;
}

/*
 * wland_p2p_get_current_chanspec() - Get current operation channel.
 *
 * @p2p		: P2P specific data.
 * @chanspec: chanspec to be returned.
 */
static void wland_p2p_get_current_chanspec(struct wland_p2p_info *p2p,
					   u16 *chanspec)
{
	struct wland_chan ch;
	struct wland_bss_info_le *bi;
	u8 *buf;
	u8 mac_addr[ETH_ALEN];
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->ifp;

	if (wland_fil_iovar_data_get(ifp, "get_bssid",
				     mac_addr, ETH_ALEN) > 0) {
		buf = kzalloc(WLAND_BSS_INFO_MAX, GFP_KERNEL);

		if (buf) {
			*(__le32 *)buf = cpu_to_le32(WLAND_BSS_INFO_MAX);

			if (wland_fil_iovar_data_get(ifp, "get_bss_info", buf,
						     WLAND_BSS_INFO_MAX) > 0) {
				bi = (struct wland_bss_info_le *)(buf + 4);
				*chanspec = le16_to_cpu(bi->chanspec);
				kfree(buf);
				return;
			}
			kfree(buf);
		}
	}

	ch.chnum = WLAND_P2P_TEMP_CHAN;
	ch.bw = CHAN_BW_20;
	p2p->cfg->d11inf.encchspec(&ch);
	*chanspec = ch.chspec;
}

/*
 * Change a P2P Role.
 * Parameters:
 * @mac     : MAC address of the BSS to change a role
 * Returns 0 if success.
 */
s32 wland_p2p_ifchange(struct wland_cfg80211_info *cfg,
		       enum wland_fil_p2p_if_types if_type)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;
	struct wland_fil_p2p_if_le if_request;
	s32 err;
	u16 chanspec;

	if (!vif) {
		wiphy_err(cfg->wiphy,
			  "vif for P2PAPI_BSSCFG_PRIMARY does not exist\n");
		return -EPERM;
	}

	wland_notify_escan_complete(cfg, vif->ifp, true, true);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	if (!vif) {
		wiphy_err(cfg->wiphy,
			  "vif for P2PAPI_BSSCFG_CONNECTION does not exist\n");
		return -EPERM;
	}
	/*
	 * The STA may already be associated, so start the virtual interface
	 * on the current channel of the primary interface.
	 */
	wland_p2p_get_current_chanspec(p2p, &chanspec);

	if_request.type = cpu_to_le16((u16)if_type);
	if_request.channel = cpu_to_le16(chanspec & 0xff);

	memcpy(if_request.addr, vif->ifp->mac_addr, ETH_ALEN);

	wland_cfg80211_arm_vif_event(cfg, vif);

	if_request.bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	if_request.ifidx = 0;

	wland_fil_set_cmd_data(vif->ifp, WID_P2P_CHANGE_INTERFACE, &if_request,
			       sizeof(if_request));

	err = wland_cfg80211_wait_vif_event_timeout(cfg, WLAND_ACTION_IF_CHANGE,
						    msecs_to_jiffies(1500));

	wland_cfg80211_arm_vif_event(cfg, NULL);
	if (!err) {
		wiphy_err(cfg->wiphy, "no interface change event received\n");
		return -EIO;
	}

	return err >= 0 ? 0 : -1;
}

s32 wland_cfg80211_p2p_start_device(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	s32 err;
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);

	mutex_lock(&cfg->usr_sync);
	err = wland_p2p_enable_discovery(p2p);
	if (!err)
		set_bit(VIF_STATUS_READY, &vif->sme_state);
	mutex_unlock(&cfg->usr_sync);

	return err;
}

void wland_cfg80211_p2p_stop_device(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);

	mutex_lock(&cfg->usr_sync);
	wland_p2p_deinit_discovery(p2p);
	wland_abort_scanning(cfg);
	clear_bit(VIF_STATUS_READY, &vif->sme_state);
	mutex_unlock(&cfg->usr_sync);
}

static void
wland_cfg80211_delay_remain_on_channel_worker(struct work_struct *work)
{
	struct wland_p2p_info *p2p =
		container_of(work, struct wland_p2p_info,
			     delay_remain_onchannel_work.work);
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;
	struct wland_cfg80211_info *cfg = ifp->drvr->config;

	cfg80211_remain_on_channel_expired(&ifp->vif->wdev,
					   p2p->remain_on_channel_cookie,
					   &p2p->remain_on_channel,
					   GFP_KERNEL);
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);
}

static void wland_p2p_alive_timeout_worker(struct work_struct *work)
{
	u8 val = 0;
	struct wland_p2p_info *p2p =
		container_of(work, struct wland_p2p_info,
			     p2p_alive_timeout_work);
	struct wland_if *ifp = p2p->cfg->pub->iflist[P2PAPI_BSSCFG_PRIMARY];

	del_timer_sync(&p2p->p2p_alive_timer);

	wland_fil_set_cmd_data(ifp, WID_P2P_ENABLE, &val, sizeof(val));
}

static void wland_p2p_alive_timeout(struct timer_list *t)
{
	struct wland_p2p_info *p2p = from_timer(p2p, t, p2p_alive_timer);
	struct wland_if *p2p_ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;

	if (!wland_check_vif_up(p2p_ifp->vif))
		return;

	atomic_inc(&p2p->p2p_alive_timer_count);

	if (atomic_read(&p2p->p2p_alive_timer_count) < P2P_ALIVE_TIME_COUNT) {
		mod_timer(&p2p->p2p_alive_timer,
			  jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
		return;
	}
	atomic_set(&p2p->p2p_alive_timer_count, 0);

	wiphy_dbg(p2p->cfg->wiphy,
		  "P2P alive timer expired: state %d, mode %d, sme_state: 0x%x\n",
		  atomic_read(&p2p->p2p_state), p2p_ifp->vif->mode,
		  (u32)p2p_ifp->vif->sme_state);

	if (atomic_read(&p2p->p2p_state) != 1)
		wiphy_err(p2p->cfg->wiphy, "invalid P2P state: %d, mode: %d\n",
			  atomic_read(&p2p->p2p_state), p2p_ifp->vif->mode);

	if (test_bit(VIF_STATUS_CONNECTED, &p2p_ifp->vif->sme_state) ||
	    test_bit(VIF_STATUS_AP_CREATED, &p2p_ifp->vif->sme_state)) {
		mod_timer(&p2p->p2p_alive_timer,
			  jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
	} else {
		wiphy_dbg(p2p->cfg->wiphy, "disabling P2P\n");
		atomic_set(&p2p->p2p_state, 2);
		schedule_work(&p2p->p2p_alive_timeout_work);
	}
}

/*
 * cfg80211_p2p_attach() - attach for P2P.
 *
 * @cfg: driver private data for cfg80211 interface.
 */
s32 cfg80211_p2p_attach(struct wland_cfg80211_info *cfg)
{
	struct wland_if *pri_ifp = NULL;
	struct wland_if *p2p_ifp = NULL;
	struct wland_cfg80211_vif *p2p_vif = NULL;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_private *drvr = cfg->pub;
	s32 err = 0;
	u8 enable = 1;

	p2p->cfg = cfg;

	pri_ifp = drvr->iflist[P2PAPI_BSSCFG_PRIMARY];
	p2p_ifp = drvr->iflist[P2PAPI_BSSCFG_DEVICE];

	p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif = pri_ifp->vif;

	INIT_DELAYED_WORK(&p2p->delay_remain_onchannel_work,
			  wland_cfg80211_delay_remain_on_channel_worker);

	if (p2p_ifp) {
		p2p_vif = wland_alloc_vif(cfg, NL80211_IFTYPE_STATION, false);
		if (IS_ERR(p2p_vif)) {
			wiphy_err(cfg->wiphy,
				  "failed to create discovery vif\n");
			err = -ENOMEM;
			goto exit;
		}
		p2p_vif->mode = WL_MODE_P2P;
		p2p_vif->ifp = p2p_ifp;
		p2p_ifp->vif = p2p_vif;
		p2p_vif->wdev.netdev = p2p_ifp->ndev;
		p2p_ifp->ndev->ieee80211_ptr = &p2p_vif->wdev;

		SET_NETDEV_DEV(p2p_ifp->ndev, wiphy_dev(cfg->wiphy));

		p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif = p2p_vif;

		wland_p2p_generate_bss_mac(p2p, NULL);

		memcpy(p2p_ifp->mac_addr, p2p->dev_addr, ETH_ALEN);

		wland_p2p_set_firmware(pri_ifp, p2p->dev_addr);

		err = wland_fil_iovar_data_set(pri_ifp, "p2p_disc", &enable,
					       sizeof(u8));
		if (err < 0) {
			wiphy_err(cfg->wiphy,
				  "failed to set P2P discovery: %d\n", err);
			wland_free_vif(cfg, p2p_vif);
			goto exit;
		}

		init_completion(&p2p->send_af_done);
		INIT_WORK(&p2p->afx_hdl.afx_work, wland_p2p_afx_handler);
		init_completion(&p2p->afx_hdl.act_frm_scan);
		init_completion(&p2p->wait_next_af);

		atomic_set(&p2p->p2p_state, 0);
		atomic_set(&p2p->p2p_alive_timer_count, 0);

		timer_setup(&p2p->p2p_alive_timer, wland_p2p_alive_timeout, 0);
		INIT_WORK(&p2p->p2p_alive_timeout_work,
			  wland_p2p_alive_timeout_worker);
	}
exit:
	return err;
}

/*
 * cfg80211_p2p_detach() - detach P2P.
 *
 * @p2p: P2P specific data.
 */
void cfg80211_p2p_detach(struct wland_p2p_info *p2p)
{
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	cancel_delayed_work_sync(&p2p->delay_remain_onchannel_work);
	cancel_work_sync(&p2p->afx_hdl.afx_work);

	del_timer_sync(&p2p->p2p_alive_timer);
	cancel_work_sync(&p2p->p2p_alive_timeout_work);

	if (vif) {
		wland_p2p_cancel_remain_on_channel(vif->ifp);
		wland_p2p_deinit_discovery(p2p);
		wland_free_vif(p2p->cfg, vif);
		p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif = NULL;
	}
	memset(p2p, '\0', sizeof(*p2p));
}
