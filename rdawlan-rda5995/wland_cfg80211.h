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

#ifndef _WLAND_CFG80211_H_
#define _WLAND_CFG80211_H_

#include <net/cfg80211.h>
#include "wland_p2p.h"
#include "../include/wland_d11.h"
#include "wland_defs.h"

#define MAXPMKID			16

#define ROAM_TRIGGER_LEVEL		-75
#define ROAM_DELTA			20

#define SCAN_IE_LEN_MAX			1024
#define SCAN_NUM_MAX			4

#define SCAN_VERSION_NUM		0x5995

#define SCAN_TIMER_INTERVAL_MS		(5 * 1000)	/* E-Scan timeout */
#define SCAN_TIMER2_INTERVAL_MS		(25 * 1000)

#define SCAN_ACTION_START		1

#define CONNECT_TIMER_MAX		6000
#define CONNECT_RETRY_TIMES_MAX		5
#define CONNECT_RESTOREWORK_TIMER_MS	(10 * 1000)

#define P2P_ALIVE_TIME_MS		(1 * 1000)
#define P2P_ALIVE_TIME_COUNT		20

#define IE_MAX_LEN			512

#define TLV_LEN_OFF			1
#define TLV_HDR_LEN			2
#define TLV_BODY_OFF			2
#define TLV_OUI_LEN			3

#define WLAND_BSS_INFO_MAX		1024
#define WLAND_ASSOC_INFO_MAX		512
#define WLAND_EXTRA_BUF_MAX		1024
#define WLAND_BEACON_TIMEOUT		3

/* 802.11 Mgmt Packet flags */
#define WLAND_VNDR_IE_BEACON_FLAG	0x01
#define WLAND_VNDR_IE_PRBRSP_FLAG	0x02
#define WLAND_VNDR_IE_ASSOCRSP_FLAG	0x04
#define WLAND_VNDR_IE_PRBREQ_FLAG	0x10
#define WLAND_VNDR_IE_ASSOCREQ_FLAG	0x20
#define WLAND_VNDR_IE_RSN_INFO_FLAG	0x40

#define WLAND_PNO_VERSION		2
#define WLAND_PNO_TIME			30
#define WLAND_PNO_REPEAT		4
#define WLAND_PNO_FREQ_EXPO_MAX		3
#define WLAND_PNO_ENABLE_ADAPTSCAN_BIT	6
#define WLAND_PNO_HIDDEN_BIT		2
#define WLAND_PNO_WPA_AUTH_ANY		0xFFFFFFFF
#define WLAND_PNO_SCAN_COMPLETE		1

#define WLAND_IFACE_MAX_CNT		3

#define VS_IE_FIXED_HDR_LEN		6
#define WPA_IE_VERSION_LEN		2
#define WPA_IE_MIN_OUI_LEN		4

#define VNDR_IE_VSIE_OFFSET		12
#define VNDR_IE_PARSE_LIMIT		5

/*
 * enum wland_scan_status - scan engine status
 *
 * @SCAN_STATUS_BUSY    : scanning in progress on dongle.
 * @SCAN_STATUS_ABORT   : scan being aborted on dongle.
 * @SCAN_STATUS_SUPPRESS: scanning is suppressed in driver.
 */
enum wland_scan_status {
	SCAN_STATUS_BUSY,
	SCAN_STATUS_ABORT,
	SCAN_STATUS_SUPPRESS,
};

/*
 * enum wland_vif_status - bit indices for vif status.
 *
 * @VIF_STATUS_READY        : ready for operation.
 * @VIF_STATUS_CONNECTING   : connect/join in progress.
 * @VIF_STATUS_CONNECTED    : connected/joined successfully.
 * @VIF_STATUS_DISCONNECTING: disconnect/disable in progress.
 * @VIF_STATUS_AP_CREATING  : interface configured for AP operation.
 * @VIF_STATUS_AP_CREATED   : AP operation started.
 * @VIF_STATUS_TESTING      : chip enter test mode.
 */
enum wland_vif_status {
	VIF_STATUS_READY,
	VIF_STATUS_CONNECTING,
	VIF_STATUS_CONNECTED,
	VIF_STATUS_CHANGEING,
	VIF_STATUS_DISCONNECTING,
	VIF_STATUS_AP_CREATING,
	VIF_STATUS_AP_CREATED,
	VIF_STATUS_TESTING,
	VIF_STATUS_P2P,
};

/*
 * enum wland_mode - driver mode of virtual interface.
 *
 * @WL_MODE_BSS : connects to BSS.
 * @WL_MODE_IBSS: operate as ad-hoc.
 * @WL_MODE_AP  : operate as access-point.
 * @WL_MODE_P2P: provide P2P discovery.
 */
enum wland_mode {
	WL_MODE_BSS,
	WL_MODE_IBSS,
	WL_MODE_AP,
	WL_MODE_P2P
};

/* dongle configuration */
struct wland_cfg80211_conf {
	u32 frag_threshold;
	u32 rts_threshold;
	u32 retry_short;
	u32 retry_long;
	s32 tx_power;
	struct ieee80211_channel channel;
};

struct pmkid {
	u8 BSSID[ETH_ALEN];
	u8 PMKID[WLAN_PMKID_LEN];
};

struct pmkid_list {
	__le32 npmkid;
	struct pmkid pmkid[1];
};

/* basic structure of scan request */
struct wland_cfg80211_scan_req {
	struct wland_ssid_le ssid_le;
};

/*
 * struct vif_saved_ie - holds saved IEs for a virtual interface.
 *
 * @probe_req_ie    : IE info for probe request.
 * @probe_res_ie    : IE info for probe response.
 * @beacon_ie       : IE info for beacon frame.
 * @probe_req_ie_len: IE info length for probe request.
 * @probe_res_ie_len: IE info length for probe response.
 * @beacon_ie_len   : IE info length for beacon frame.
 */
struct vif_saved_ie {
	u8 probe_req_ie[IE_MAX_LEN];
	u8 probe_res_ie[IE_MAX_LEN];
	u8 beacon_ie[IE_MAX_LEN];
	u8 assoc_req_ie[IE_MAX_LEN];
	u8 assoc_rsp_ie[IE_MAX_LEN];
	u8 rsn_ie[IE_MAX_LEN];
	u32 probe_req_ie_len;
	u32 probe_res_ie_len;
	u32 beacon_ie_len;
	u32 assoc_req_ie_len;
	u32 assoc_rsp_ie_len;
	u32 rsn_ie_len;
};

struct wland_addba_msg {
	u8 action;	/* 1: add, 0: del */
	u8 tid;
	u8 mac_addr[ETH_ALEN];
};

/* association inform */
/* Protected by conn_info.sta_info_lock, including each AP station's state. */
struct wland_ba_state {
	u8 active;
	u8 pending;
	unsigned long deadline[8];
	unsigned long retry_at[8];
};

struct wland_if;
void wland_queue_addba(struct wland_if *ifp, u8 tid, const u8 *peer);

struct wland_cfg80211_connect_info {
	u8 *req_ie;
	s32 req_ie_len;
	u8 *resp_ie;
	s32 resp_ie_len;

	struct net_device *ndev;
	struct timer_list timer;
	struct timer_list connect_restorework_timeout;
	u8 retry_times;
	bool timer_on;
	struct work_struct work;
	struct work_struct connect_fail_work;
	struct workqueue_struct *connect_wq;
	struct work_struct connect_restorework_timeout_work;
	atomic_t tid_map;
	struct wland_ba_state ba;
	unsigned long tid_jiffies[8];
	int tid_num[8];

	/* protects sta_info_list and ba state */
	spinlock_t sta_info_lock;
	struct list_head sta_info_list;
	u8 wmm_enable;
	u8 n_enable;
	void *data;
};

/*
 * struct wland_cfg80211_vif - virtual interface specific information.
 *
 * @ifp         : lower layer interface pointer
 * @wdev        : wireless device.
 * @profile     : profile information.
 * @mode        : operating mode.
 * @roam_off    : roaming state.
 * @sme_state   : SME state using enum wland_vif_status bits.
 * @pm_block    : power-management blocked.
 * @list        : linked list.
 * @mgmt_rx_reg : registered rx mgmt frame types.
 */
struct wland_cfg80211_vif {
	struct wland_if *ifp;
	struct wireless_dev wdev;
	struct wland_cfg80211_connect_info conn_info;
	struct wland_cfg80211_profile profile;
	s32 mode;
	s32 roam_off;
	unsigned long sme_state;
	bool pm_block;
	struct vif_saved_ie saved_ie;
	struct list_head list;
	u16 mgmt_rx_reg;
};

/*
 * struct sta_info - info of station connected to this AP (AP mode only)
 * @connect: whether sta is connected (0: disconnected, 1: connected)
 * @aid		: aid of sta, from firmware. 0 is invalid aid
 * @mac_addr: mac address of sta
 * @assoc_req_ie: assoc request frame ies
 * @assoc_req_ie_len: length of assoc request frame ies
 * @list        : linked list.
 */
struct wland_sta_info {
	u8 connect;
	u8 aid;
	u8 mac_addr[ETH_ALEN];
	u8 wmm_enable;
	u8 n_enable;
	u8 *assoc_req_ie;
	s32 assoc_req_ie_len;
	atomic_t tid_map;
	struct wland_ba_state ba;
	unsigned long tid_jiffies[8];
	int tid_num[8];
	struct list_head list;
};

/* wpa2 pmk list */
struct wland_cfg80211_pmk_list {
	struct pmkid_list pmkids;
	struct pmkid foo[MAXPMKID - 1];
};

/* dongle scan state */
enum wland_scan_state {
	SCAN_STATE_IDLE,
	SCAN_STATE_SCANNING
};

/* dongle escan controller */
struct wland_scan_info {
	u32 escan_state;
	struct wiphy *wiphy;
	struct wland_if *ifp;
	s32 (*run)(struct wland_cfg80211_info *cfg, struct wland_if *ifp,
		   struct cfg80211_scan_request *request, u16 action);
};

/*
 * struct wland_pno_param_le - PNO scan configuration parameters
 *
 * @version     : PNO parameters version.
 * @scan_freq   : scan frequency.
 * @lost_network_timeout: #sec. to declare discovered network as lost.
 * @flags       : Bit field to control features of PFN such as sort
 *                criteria auto enable switch and background scan.
 * @rssi_margin : Margin to avoid jitter for choosing a PFN by RSSI.
 * @bestn       : number of best networks in each scan.
 * @mscan       : number of scans recorded.
 * @repeat      : min scan intervals before frequency changes in scan.
 * @exp         : exponent of 2 for maximum scan interval.
 * @slow_freq   : slow scan period.
 */
struct wland_pno_param_le {
	__le32 version;
	__le32 scan_freq;
	__le32 lost_network_timeout;
	__le16 flags;
	__le16 rssi_margin;
	u8 bestn;
	u8 mscan;
	u8 repeat;
	u8 exp;
	__le32 slow_freq;
};

/*
 * struct wland_pno_net_param_le - scan parameters per preferred network.
 *
 * @ssid    : ssid name and its length.
 * @flags   : bit2: hidden.
 * @infra   : BSS vs IBSS.
 * @auth    : Open vs Closed.
 * @wpa_auth: WPA type.
 * @wsec    : wsec value.
 */
struct wland_pno_net_param_le {
	struct wland_ssid_le ssid;
	__le32 flags;
	__le32 infra;
	__le32 auth;
	__le32 wpa_auth;
	__le32 wsec;
};

/*
 * struct wland_pno_net_info_le - information per found network.
 *
 * @bssid       : BSS network identifier.
 * @channel     : channel number only.
 * @SSID_len    : length of ssid.
 * @SSID        : ssid characters.
 * @RSSI        : receive signal strength (in dBm).
 * @timestamp   : age in seconds.
 */
struct wland_pno_net_info_le {
	u8 bssid[ETH_ALEN];
	u8 channel;
	u8 SSID_len;
	u8 SSID[32];
	__le16 RSSI;
	__le16 timestamp;
};

/*
 * struct wland_pno_scanresults_le - result returned in PNO NET FOUND event.
 *
 * @version : PNO version identifier.
 * @status  : indicates completion status of PNO scan.
 * @count   : amount of wland_pno_net_info_le entries appended.
 */
struct wland_pno_scanresults_le {
	__le32 version;
	__le32 status;
	__le32 count;
};

/*
 * struct wland_cfg80211_vif_event - virtual interface event information.
 *
 * @vif_wq          : waitqueue awaiting interface event from firmware.
 * @vif_event_lock  : protects other members in this structure.
 * @vif_complete    : completion for net attach.
 * @action          : either add, change, or delete.
 * @vif             : virtual interface object related to the event.
 */
struct wland_cfg80211_vif_event {
	wait_queue_head_t vif_wq;
	/* protects vif event fields */
	struct mutex vif_event_lock;
	u8 action;
	struct wland_cfg80211_vif *vif;
};

/*
 * struct wland_cfg80211_info - dongle private data of cfg80211 interface
 *
 * @wiphy       : wiphy object for cfg80211 interface.
 * @conf        : dongle configuration.
 * @p2p         : peer-to-peer specific information.
 * @scan_request: cfg80211 scan request object.
 * @usr_sync    : mainly for dongle up/down synchronization.
 * @bss_list    : bss_list holding scanned ap information.
 * @scan_req_int: internal scan request object.
 * @ie          : information element object for internal purpose.
 * @conn_info   : association info.
 * @pmk_list    : wpa2 pmk list.
 * @scan_status : scan activity on the dongle.
 * @pub         : common driver information.
 * @channel     : current channel.
 * @active_scan : current scan mode.
 * @sched_escan : e-scan for scheduled scan support running.
 * @ibss_starter: indicates this sta is ibss starter.
 * @pwr_save    : power save state requested through cfg80211.
 * @dongle_up   : indicate whether dongle up or not.
 * @roam_on     : on/off switch for dongle self-roaming.
 * @scan_tried  : indicates if first scan attempted.
 * @extra_buf   : mainly to grab assoc information.
 * @scan_buf    : scan information for escan or iscan.
 * @scan_info   : escan information.
 * @scan_timeout       : Timer for catch scan timeout.
 * @scan_report_work  : scan report worker.
 * @vif_list    : linked list of vif instances.
 * @vif_cnt     : number of vif instances.
 * @vif_event   : vif event signalling.
 */
struct wland_cfg80211_info {
	struct wiphy *wiphy;
	struct wland_cfg80211_conf *conf;
	struct wland_cfg80211_pmk_list *pmk_list;
	struct wland_private *pub;
	struct cfg80211_scan_request *scan_request;

	struct cfg80211_scan_info escan_info;

	struct wland_cfg80211_scan_req scan_req_int;
	struct wland_p2p_info p2p;
	unsigned long scan_status;
	u32 channel;
	bool active_scan;
	bool sched_escan;
	bool ibss_starter;
	bool pwr_save;
	bool dongle_up;
	bool roam_on;
	bool scan_tried;
	u8 *extra_buf;
	struct wland_scan_info scan_info;
	struct timer_list scan_timeout;
	struct work_struct scan_report_work;
	struct list_head vif_list;
	u8 vif_cnt;
	struct wland_cfg80211_vif_event vif_event;
	struct completion vif_disabled;
	/* serialize user requests */
	struct mutex usr_sync;
	struct wland_d11inf d11inf;
	bool in_disconnecting;
	bool in_waiting;
	struct completion disconnecting_wait;

	struct wland_scan_results scan_results;
	/* protects scan result list */
	struct mutex scan_result_lock;
	struct list_head scan_result_list;

	u8 scannum;
	bool ctrl_scan_wait;
	wait_queue_head_t scanid_wait;
};

/*
 * struct wland_tlv - tag_ID/length/value_buffer tuple.
 *
 * @id  : tag identifier.
 * @len : number of bytes in value buffer.
 * @data: value buffer.
 */
struct wland_tlv {
	u8 id;
	u8 len;
	u8 data[1];
};

static inline struct wiphy *cfg_to_wiphy(struct wland_cfg80211_info *cfg)
{
	return cfg->wiphy;
}

static inline struct wland_cfg80211_info *wiphy_to_cfg(struct wiphy *w)
{
	return wiphy_priv(w);
}

static inline struct wland_cfg80211_info *wdev_to_cfg(struct wireless_dev *wd)
{
	return wdev_priv(wd);
}

static inline struct net_device *cfg_to_ndev(struct wland_cfg80211_info *cfg)
{
	struct wland_cfg80211_vif *vif =
		list_first_entry(&cfg->vif_list, struct wland_cfg80211_vif,
				 list);

	return vif->wdev.netdev;
}

static inline struct wland_cfg80211_info *ndev_to_cfg(struct net_device *ndev)
{
	return wdev_to_cfg(ndev->ieee80211_ptr);
}

static inline struct wland_cfg80211_profile *ndev_to_prof(struct net_device *nd)
{
	struct wland_if *ifp = netdev_priv(nd);

	return &ifp->vif->profile;
}

static inline struct wland_cfg80211_vif *ndev_to_vif(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	return ifp->vif;
}

struct wland_cfg80211_info *wland_cfg80211_attach(struct wland_private *drvr,
						  struct device *busdev);
void wland_cfg80211_detach(struct wland_cfg80211_info *cfg);

s32 wland_cfg80211_up(struct net_device *ndev);
s32 wland_cfg80211_down(struct net_device *ndev);

struct wland_cfg80211_vif *wland_alloc_vif(struct wland_cfg80211_info *cfg,
					   enum nl80211_iftype type,
					   bool pm_block);
void wland_free_vif(struct wland_cfg80211_info *cfg,
		    struct wland_cfg80211_vif *vif);

struct wland_tlv *wland_parse_tlvs(const void *buf, int buflen,
				   unsigned int key);
u16 wland_channel_to_chanspec(struct wland_d11inf *d11inf,
			      struct ieee80211_channel *ch);

void wland_cfg80211_arm_vif_event(struct wland_cfg80211_info *cfg,
				  struct wland_cfg80211_vif *vif);
bool wland_cfg80211_vif_event_armed(struct wland_cfg80211_info *cfg);
int wland_cfg80211_wait_vif_event_timeout(struct wland_cfg80211_info *cfg,
					  u8 action, unsigned long timeout);
s32 wland_notify_escan_complete(struct wland_cfg80211_info *cfg,
				struct wland_if *ifp, bool aborted,
				bool fw_abort);
void wland_abort_scanning(struct wland_cfg80211_info *cfg);
void wland_clear_scan_busy(struct wland_cfg80211_info *cfg);

bool wland_vif_get_state_all(struct wland_cfg80211_info *cfg,
			     unsigned long state);
s32 wland_vif_clear_mgmt_ies(struct wland_cfg80211_vif *vif);
s32 wland_vif_set_mgmt_ie(struct wland_cfg80211_vif *vif, s32 pktflag,
			  const u8 *vndr_ie_buf, u32 vndr_ie_len);
s32 wland_get_assoc_ies_from_frame(struct wland_if *ifp,
				   u8 *frame, u16 frame_len, u8 frame_stype);
bool wland_check_vif_up(struct wland_cfg80211_vif *vif);
s32 wland_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
			      u16 reason_code);
s32 wland_cfg80211_updata_mac(struct wland_cfg80211_info *cfg);
#endif /* _WLAND_CFG80211_H_ */
