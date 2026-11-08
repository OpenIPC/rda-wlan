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
#ifndef _WLAND_DEV_H_
#define _WLAND_DEV_H_

#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "wland_usb.h"
#include "wland_fweh.h"

#ifndef FCS_LEN
#define FCS_LEN				4
#endif

#define ALIGNMENT			4

#define WLAN_EID_HT_CAP			45

/* Max valid buffer size that can be sent to the dongle */
#define CDC_MAX_MSG_SIZE		(ETH_FRAME_LEN + ETH_FCS_LEN)

#ifndef MAX_RATES
#define MAX_RATES			16	/* max # of rates in rateset */
#endif

#define MAX_WSEC_KEY			4	/* max # of keys in keyset */

#define AUTH_OPEN			0	/* d11 open authentication */

#define CAPABILITY_ESS			BIT(0)
#define CAPABILITY_IBSS			BIT(1)

#define WLAND_FIL_AF_PARAMS_HDR_LEN	16
#define WLAND_FIL_ACTION_FRAME_HDR_LEN	12
#define WLAND_FIL_ACTION_FRAME_SIZE	1800

#define MCSSET_LEN			16

#define WL_PRIMARY_KEY			BIT(1)

#define WLAND_MAX_IFS			4

#define WLAND_STA_ASSOC			0x10

#define CRYPTO_ALGO_OFF			0
#define CRYPTO_ALGO_WEP1		1
#define CRYPTO_ALGO_WEP128		3

#define WEP_ENABLED			0x0001
#define TKIP_ENABLED			0x0002
#define AES_ENABLED			0x0004
#define SMS4_ENABLED			0x0100

#define WLAND_DCMD_MEDLEN		1536
#define ROUND_UP_MARGIN			32

#define MAKE_WORD16(lsb, msb)		((((u16)(msb) << 8) & 0xFF00) | (lsb))

enum wland_current_mode {
	WLAND_B_MODE,
	WLAND_G_MODE,
	WLAND_N_MODE,
	WLAND_ERR_MODE,
};

/* User set ps mode for save power */
enum user_ps_mode {
	NO_POWERSAVE = 0,
	MIN_FAST_PS = 1,
	MAX_FAST_PS = 2,
	MIN_PSPOLL_PS = 3,
	MAX_PSPOLL_PS = 4,
};

enum site_survey {
	SITE_SURVEY_1CH = 0,
	SITE_SURVEY_ALL_CH = 1,
	SITE_SURVEY_OFF = 2,
	P2P_SITE_SURVEY_SOCIAL = 3,
	SITE_SURVEY_NA_CH = 4,
	SITE_SURVEY_EU_CH = 5,
};

enum g_operating_mode {
	B_ONLY_MODE = 0,
	G_ONLY_MODE,
	G_MIXED_11B_1_MODE,
	G_MIXED_11B_2_MODE,
	NUM_G_OPERATING_MODE,
};

enum wland_fil_p2p_if_types {
	FIL_P2P_IF_CLIENT,
	FIL_P2P_IF_GO,
	FIL_P2P_IF_DYNBCN_GO,
	FIL_P2P_IF_DEV,
};

struct wland_fil_p2p_if_le {
	u8 addr[ETH_ALEN];
	u8 ifidx;
	u8 bsscfgidx;
	__le16 type;
	__le16 channel;
};

struct wland_fil_action_frame_le {
	u8 da[ETH_ALEN];
	__le16 len;
	__le32 packet_id;
	u8 data[WLAND_FIL_ACTION_FRAME_SIZE];
};

struct wland_fil_af_params_le {
	__le32 channel;
	__le32 dwell_time;
	u8 bssid[ETH_ALEN];
	u8 pad[2];
	struct wland_fil_action_frame_le action_frame;
};

#define WLC_CNTRY_BUF_SZ		4

struct wland_country {
	/* nul-terminated country code used in the Country IE */
	char country_abbrev[WLC_CNTRY_BUF_SZ];
	/* revision specifier for ccode on set, -1 indicates unspecified */
	int rev;
	/* nul-terminated built-in country code */
	char ccode[WLC_CNTRY_BUF_SZ];
};

/*
 * struct wland_tdls_iovar_le - common structure for tdls iovars.
 *
 * @ea: ether address of peer station.
 * @mode: mode value depending on specific tdls iovar.
 * @chanspec: channel specification.
 * @pad: unused (for future use).
 */
struct wland_tdls_iovar_le {
	u8 ea[ETH_ALEN];	/* Station address */
	u8 mode;		/* mode: depends on iovar */
	__le16 chanspec;
	__le32 pad;		/* future */
};

enum wland_tdls_manual_ep_ops {
	TDLS_MANUAL_EP_CREATE = 1,
	TDLS_MANUAL_EP_DELETE = 3,
	TDLS_MANUAL_EP_DISCOVERY = 6,
};

/*
 * BSS info structure
 * Applications MUST CHECK ie_offset field and length field to access IEs and
 * next bss_info structure in a vector (in struct wland_scan_results)
 */
struct wland_bss_info_le {
	struct wland_cfg80211_vif *vif;
	/* byte length of data in this record, starting at version and IEs */
	u32 length;
	u8 BSSID[ETH_ALEN];
	u16 beacon_period;	/* units are Kusec */
	u16 capability;		/* Capability information */
	u8 SSID_len;
	u8 SSID[32];
	struct {
		u8 count;	/* # rates in this set */
		/* rates in 500kbps units w/hi bit set if basic */
		u8 rates[MAX_RATES + 2];
	} rateset;		/* supported rates */
	u16 chanspec;		/* chanspec for bss */
	u16 atim_window;	/* units are Kusec */
	u8 dtim_period;		/* DTIM period */
	s8 RSSI;		/* receive signal strength (in dBm) */
	s8 phy_noise;		/* noise (in dBm) */
	u8 wmm_enable;		/* BSS is QOS enable */
	u8 n_enable;
	/* 802.11N BSS Capabilities (based on HT_CAP_*) */
	u32 nbss_cap;
	u8 ctl_ch;		/* 802.11N BSS control channel number */
	u8 basic_mcs[MCSSET_LEN];	/* 802.11N BSS required MCS set */
	u8 *ie;
	u32 ie_length;		/* byte length of Information Elements */
	s16 SNR;		/* average SNR during frame reception */
	unsigned long time;
	struct list_head list;
};

struct wland_ssid {
	u32 SSID_len;
	u8 SSID[32];
};

struct wland_ssid_le {
	u32 SSID_len;
	u8 SSID[32];
};

#define DOT11_MAX_DEFAULT_KEYS	4

struct wland_scan_params_le {
	struct wland_ssid_le ssid_le;	/* default: {0, ""} */
	u8 bssid[ETH_ALEN];	/* default: bcast */
	/* default: any, DOT11_BSSTYPE_ANY/INFRASTRUCTURE/INDEPENDENT */
	s8 bss_type;
	u8 scan_type;		/* flags, 0 use default */
	/* -1 use default, number of probes per channel */
	__le32 nprobes;
	/* -1 use default, dwell time per channel for active scanning */
	__le32 active_time;
	/* -1 use default, dwell time per channel for passive scanning */
	__le32 passive_time;
	/* -1 use default, dwell time for home channel between scans */
	__le32 home_time;
	/*
	 * count of channels and ssids that follow:
	 * low half: count of channels in channel_list, 0 means default
	 * high half: entries in struct wland_ssid array that follows
	 */
	__le32 channel_num;
	u16 channel_list[15];	/* list of chanspecs */
};

struct wland_scan_results {
	u32 version;
	u32 count;
	u16 beacon_period;
};

#define P2P_WILDCARD_SSID		"DIRECT-"
#define P2P_WILDCARD_SSID_LEN		(sizeof(P2P_WILDCARD_SSID) - 1)

#define SOCIAL_CHAN_1			1
#define SOCIAL_CHAN_2			6
#define SOCIAL_CHAN_3			11

#define IS_P2P_SOCIAL_CHANNEL(channel) \
	(((channel) == SOCIAL_CHAN_1) || \
	 ((channel) == SOCIAL_CHAN_2) || \
	 ((channel) == SOCIAL_CHAN_3))

#define WLAND_P2P_TEMP_CHAN		SOCIAL_CHAN_3
#define SOCIAL_CHAN_CNT			3
#define AF_PEER_SEARCH_CNT		2
#define P2P_FULL_CHAN_CNT		14
#define P2P_FULL_CHAN_CNT_11		11

/* Used for association with a specific BSSID and chanspec list */
struct wland_assoc_params_le {
	/* 00:00:00:00:00:00: broadcast scan */
	u8 bssid[ETH_ALEN];
	/* 0: all available channels, otherwise count of chanspecs */
	__le32 chanspec_num;
	__le16 chanspec_list[1];
};

struct wland_join_params {
	struct wland_ssid_le ssid_le;
	struct wland_assoc_params_le params_le;
};

struct wland_wsec_key {
	u32 index;
	u32 len;
	u8 data[WLAN_MAX_KEY_LEN];
	u32 algo;
	u32 flags;
	u32 iv_initialized;
	struct {
		u32 hi;
		u16 lo;
	} rxiv;
	u8 ea[ETH_ALEN];
};

struct wland_ptkey {
	u8 ea[ETH_ALEN];
	u8 ken_len;
	u8 key[WLAN_MAX_KEY_LEN];
};

struct wland_rx_gtkey {
	u8 ea[ETH_ALEN];
	u8 keyRSC[8];
	u8 key_idx;
	u8 ken_len;
	u8 key[WLAN_MAX_KEY_LEN];
};

/* Used to get specific STA parameters */
struct wland_scb_val_le {
	s16 val;
	u8 ea[ETH_ALEN];
	u8 aid;
};

struct wland_11n_action {
	u8 category;
	u8 action;
	u8 bssid[ETH_ALEN];
	u8 tid;
	u8 max_msdu;
	u8 ack_policy;
	u8 ba_policy;
	__le16 buff_size;
	__le16 ba_timeout;
	__le16 add_ba_timeout;
};

/* security information with currently associated ap */
struct wland_cfg80211_security {
	u32 wpa_versions;
	u32 auth_type;
	int n_ciphers_pairwise;
	u32 ciphers_pairwise[NL80211_MAX_NR_CIPHER_SUITES];
	u32 cipher_pairwise;
	int n_akm_suites;
	u32 akm_suites[NL80211_MAX_NR_AKM_SUITES];
	u8 akm;
	u32 cipher_group;
	u32 wpa_auth;
	u8 security;
	u8 security_group;
	u8 firmware_autype;
};

/*
 * struct wland_cfg80211_profile - profile information.
 *
 * @ssid: ssid of associated/associating ap.
 * @bssid: bssid of joined/joining ibss.
 * @sec: security information.
 * @wepkey_idx: wep_default_index.
 * @wepkeys: wep-keys.
 */
struct wland_cfg80211_profile {
	int channel;
	struct wland_ssid ssid;
	u8 bssid[ETH_ALEN];
	u8 hidden_ssid;
	struct wland_cfg80211_security sec;
	u32 wepkey_idx;
	struct wland_wsec_key wepkeys[MAX_WSEC_KEY];
	u32 beacon;		/* beacon interval */
	u32 dtim;		/* dtim period */
	u16 rsn_cap;		/* RSN Capabilities */
	bool valid_bssid;
	bool wmm_enable;
	u8 *wps_ie;
	u16 wps_ie_len;
	u8 mode;
	u8 band_width;		/* 0:20M 1:40M */
};

struct wland_sta_info_le {
	__le16 ver;		/* version of this struct */
	__le16 len;		/* length in bytes of this structure */
	__le16 cap;		/* sta's advertised capabilities */
	__le32 flags;		/* flags defined below */
	__le32 idle;		/* time since data pkt rx'd from sta */
	u8 ea[ETH_ALEN];	/* Station address */
	__le32 count;		/* # rates in this set */
	u8 rates[MAX_RATES];	/* rates in 500kbps units */
	/* w/hi bit set if basic */
	__le32 in;		/* seconds elapsed since associated */
	__le32 listen_interval_inms;	/* Min Listen interval in ms for STA */
	__le32 tx_pkts;		/* # of packets transmitted */
	__le32 tx_failures;	/* # of packets failed */
	__le32 rx_ucast_pkts;	/* # of unicast packets received */
	__le32 rx_mcast_pkts;	/* # of multicast packets received */
	__le32 tx_rate;		/* Rate of last successful tx frame */
	__le32 rx_rate;		/* Rate of last successful rx frame */
	__le32 rx_decrypt_succeeds;	/* # of packet decrypted successfully */
	__le32 rx_decrypt_failures;	/* # of packet decrypted failed */
};

struct wland_chanspec_list {
	__le32 count;		/* # of entries */
	__le32 element[1];	/* variable length u32 list */
};

struct wland_rx_async_mgmt_data {
	u8  offset;
	u16 length;
	u8  rssi;
	u8  chnum;
};

/* Bus independent dongle command */
struct wland_dcmd {
	__le16 wid_pkg_length;	/*
				 * bit[0:11] : store pkg_length
				 * bit[12:15]: store host_msg_type
				 *        PKT_TYPE_DATAOUT      0x1
				 *        PKT_TYPE_DATAIN       0x2
				 *        PKT_TYPE_CFG_RSP      0x3
				 *        PKT_TYPE_CFG_REQ      0x4
				 *        HOST_MSG_ASYNCEVENT   0x5
				 */
	u8 wid_msg_type;	/*
				 * 'Q' -- request for wid query
				 * 'W' -- request for wid write
				 * 'R' -- response for write or query
				 * 'I' -- mac status indication
				 * 'N' -- network info: scan AP list
				 */
	u8 wid_msg_id;
	__le16 wid_msg_length;
};

struct wland_proto {
	u8 reqid;
	u16 rsplen;
	u32 cmd;
	u32 offset;
	struct wland_dcmd msg;
	u8 buf[WLAND_DCMD_MEDLEN + ROUND_UP_MARGIN];
};

struct wland_cfg80211_vif;
struct wland_mac_descriptor;
struct wland_fw_info;

/*
 * struct wland_if - interface control information.
 *
 * @drvr: points to device related information.
 * @vif: points to cfg80211 specific interface information.
 * @ndev: associated network device.
 * @stats: interface specific network statistics.
 * @setmacaddr_work: worker object for setting mac address.
 * @multicast_work: worker object for multicast provisioning.
 * @fws_desc: interface specific firmware-signalling descriptor.
 * @ifidx: interface index in device firmware.
 * @bssidx: index of bss associated with this interface.
 * @mac_addr: assigned mac address.
 * @netif_stop: bitmap indicates reason why netif queues are stopped.
 * @netif_stop_lock: spinlock for update netif_stop from multiple sources.
 * @pend_8021x_cnt: tracks outstanding number of 802.1x frames.
 * @pend_8021x_wait: used for signalling change in count.
 * @tx_flowblock: flow control flag.
 */
struct wland_if {
	struct wland_private *drvr;
	struct wland_cfg80211_vif *vif;
	struct net_device *ndev;
	struct net_device_stats stats;
	struct work_struct setmacaddr_work;
	struct work_struct multicast_work;
	struct wland_mac_descriptor *fws_desc;
	s32 ifidx;
	s32 bssidx;
	u8 mac_addr[ETH_ALEN];
	u8 netif_stop;
	spinlock_t netif_stop_lock;
	atomic_t pend_8021x_cnt;
	wait_queue_head_t pend_8021x_wait;
	bool tx_flowblock;
};

/* Common structure for module and instance linkage */
struct wland_private {
	struct wland_bus *bus_if;
	struct wland_proto *prot;
	struct wland_cfg80211_info *config;

	uint hdrlen;		/* Total WLAND header length (proto + bus) */
	uint maxctl;		/* Max size rxctl request from proto to bus */
	u8 wme_dp;		/* wme discard priority */
	bool p2p_enable;

	u32 drv_version;
	u8 mac[ETH_ALEN];

	u32 tx_multicast;
	u8 channel;

	struct wland_if *iflist[WLAND_MAX_IFS];

	/* Serializes protocol commands */
	struct mutex proto_block;

	struct wland_fw_info fweh;
	struct wland_fws_info *fws;

	struct dentry *dbgfs_dir;

	/* Serializes RF result reads */
	struct mutex rf_result_block;
	unsigned long long pkt_rx_complete;
	unsigned long long pkt_fcs_success;
	u8 power_g_n_offset;
	u8 current_mode;
	u8 country_code;

	u8 power_11f;
	u8 power_120;
	u8 rates[ALL_RATE_NUM];
};

int wland_netdev_wait_pend8021x(struct net_device *ndev);
char *wland_ifname(struct wland_private *drvr, int idx);
int wland_netdev_attach(struct wland_if *ifp);
int wland_netdev_p2p_attach(struct wland_if *ifp);
struct wland_if *wland_add_if(struct wland_private *drvr, s32 bssidx,
			      s32 ifidx, char *name, u8 *mac_addr);
void wland_del_if(struct wland_private *drvr, s32 bssidx);

u8 wland_check_test_mode(void);
void wland_set_test_mode(u8 mode);

/* Read the board MAC address from /etc/WLANMAC. */
int wland_get_mac_address(char *buf);

#endif /* _WLAND_DEV_H_ */
