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
#ifndef _WLAND_FWEH_H_
#define _WLAND_FWEH_H_

struct wland_if;
struct wland_private;

/* Length of the WID message header (type, id, length) */
#define FMW_HEADER_LEN		4

/* firmware event codes sent by the dongle */
enum wland_fweh_event_code {
	WLAND_E_ESCAN_RESULT = 0,
	WLAND_E_CONNECT_IND,
	WLAND_E_DISCONNECT_IND,
	WLAND_E_ROAM,
	WLAND_E_PFN_NET_FOUND,
	WLAND_E_P2P_DISC_LISTEN_COMPLETE,
	WLAND_E_ACT_FRAME_COMPLETE,
	WLAND_E_ACT_FRAME_OFF_CHAN_COMPLETE,
	WLAND_E_P2P_PROBEREQ_MSG,
	WLAND_E_FIFO_CREDIT_MAP,
	WLAND_E_ACTION_FRAME_RX,
	WLAND_E_IF_ADD,
	WLAND_E_IF_DEL,
	WLAND_E_IF_CHANGE = 13,
	WLAND_E_ARP_OFFLOAD,
	WLAND_E_MIC_ERROR,
	WLAND_E_ADDBA,
	WLAND_E_RESET_FW,
	WLAND_E_LAST
};

enum wland_fweh_event_action {
	WLAND_ACTION_NULL,
	WLAND_ACTION_IF_ADD,
	WLAND_ACTION_IF_DEL,
	WLAND_ACTION_IF_CHANGE,
	WLAND_ACTION_AP_CONNECTED,
	WLAND_ACTION_AP_DISCONNECTED,

	WLAND_ACTION_ADDBA_SEND, /* driver initiate */
	WLAND_ACTION_ADDBA_DONE, /* receive from fw */
	WLAND_ACTION_DELBA,      /* receive from fw */

	WLAND_ACTION_LAST
};

/*
 * struct wland_event_msg - firmware event message.
 *
 * @event_code: firmware event code.
 * @status:     status information.
 * @reason:     reason code.
 * @auth_type:  authentication type.
 * @datalen:    length of event data buffer.
 * @addr:       ether address.
 * @ifname:     interface name.
 * @ifidx:      interface index.
 * @bsscfgidx:  bsscfg index.
 */
struct wland_event_msg {
	u32 event_code;
	u32 status;
	u32 reason;
	s32 auth_type;
	u32 datalen;
	u8 addr[ETH_ALEN];
	char ifname[IFNAMSIZ];
	u8 action;
	u8 role;
	u8 ifidx;
	u8 bsscfgidx;
};

/*
 * struct wland_fweh_queue_item - event item on event queue.
 *
 * @q       : list element for queuing.
 * @code    : event code.
 * @ifidx   : interface index related to this event.
 * @ifaddr  : ethernet address for interface.
 * @emsg    : common parameters of the firmware event message.
 * @data    : event specific data part of the firmware event.
 */
struct wland_fweh_queue_item {
	struct list_head q;
	enum wland_fweh_event_code code;
	u8 ifidx;
	u8 ifaddr[ETH_ALEN];
	struct wland_event_msg emsg;
	u8 data[];
};

typedef s32 (*fw_handler_t)(struct wland_if *ifp,
	const struct wland_event_msg *evtmsg, void *data);

/*
 * struct wland_fw_info - firmware event handling information.
 *
 * @event_work:  event worker.
 * @evt_q_lock:  lock for event queue protection.
 * @event_q:     event queue.
 * @evt_handler: registered event handlers.
 */
struct wland_fw_info {
	struct work_struct event_work;
	spinlock_t evt_q_lock;
	struct list_head event_q;
	fw_handler_t evt_handler[WLAND_E_LAST];
};

void wland_netif_rx(struct wland_if *ifp, struct sk_buff *skb);

void wland_fweh_push_event(struct wland_private *drvr,
	struct wland_event_msg *event_packet, void *data);

int wland_fweh_register(struct wland_private *drvr,
	enum wland_fweh_event_code code, fw_handler_t handler);
void wland_fweh_unregister(struct wland_private *drvr,
	enum wland_fweh_event_code code);

void wland_fweh_attach(struct wland_private *drvr);
void wland_fweh_detach(struct wland_private *drvr);

#endif /* _WLAND_FWEH_H_ */
