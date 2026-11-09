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

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_cfg80211.h"
#include "wland_rx.h"
#include "wland_rf.h"

void wland_dhd_os_sdlock_rxq(struct wland_rx_info *rx_info,
			     unsigned long *flags)
{
	if (rx_info)
		spin_lock_irqsave(&rx_info->rxqlock, *flags);
}

void wland_dhd_os_sdunlock_rxq(struct wland_rx_info *rx_info,
			       unsigned long *flags)
{
	if (rx_info)
		spin_unlock_irqrestore(&rx_info->rxqlock, *flags);
}

static s32 wland_handle_mac_status(struct wland_private *drvr,
				   struct wland_event_msg *event_packet,
				   u8 *buffer)
{
	struct device *dev = drvr->bus_if->dev;
	u8 msg_type, mac_status;
	u16 wid_id;

	/* Layout: type 'I', msg id, 16-bit length, WID_STATUS, WID length, value */
	msg_type = buffer[0];

	if (msg_type != WLAND_WID_MSG_MAC_STATUS) {
		dev_err_ratelimited(dev, "invalid message type: 0x%02x\n",
				    msg_type);
		return -EBADE;
	}

	wid_id = MAKE_WORD16(buffer[4], buffer[5]);

	if (wid_id != WID_STATUS) {
		dev_err_ratelimited(dev, "invalid message WID: 0x%04x\n",
				    wid_id);
		return -EBADE;
	}

	mac_status = buffer[7];

	event_packet->status = STATUS_SUCCESS;

	if (mac_status == MAC_CONNECTED) {
		event_packet->event_code = WLAND_E_CONNECT_IND;
	} else if (mac_status == MAC_DISCONNECTED) {
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
	} else if (mac_status == P2P_MAC_CONNECTED) {
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	} else if (mac_status == P2P_MAC_DISCONNECTED) {
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	} else {
		dev_err_ratelimited(dev, "invalid MAC status: 0x%02x\n",
				    mac_status);
		return -EBADE;
	}

	wland_fweh_push_event(drvr, event_packet, buffer);

	return 0;
}

static s32 wland_handle_network_link_event(struct wland_private *drvr,
					   struct wland_event_msg *event_packet,
					   u8 *buffer)
{
	struct device *dev = drvr->bus_if->dev;
	struct wland_addba_msg addba_msg;
	u8 msg_type, event_type;
	u16 event_len;
	s32 ret = 0;
	int i;

	if (event_packet->datalen < 4)
		return -EINVAL;
	msg_type = buffer[0];

	if (msg_type != WLAND_WID_MSG_EVENT) {
		dev_err_ratelimited(dev, "invalid message type: 0x%02x\n",
				    msg_type);
		return -EBADE;
	}

	event_type = buffer[1];
	event_len = MAKE_WORD16(buffer[2], buffer[3]);

	event_packet->action = event_type;

	switch (event_type) {
	case EVENT_AUTH_IND:
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		break;
	case EVENT_DEAUTH_IND:
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		break;
	case EVENT_ASSOC_IND:
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		memcpy(event_packet->addr, &buffer[16], ETH_ALEN);
		break;
	case EVENT_REASSOC_IND:
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		break;
	case EVENT_DISASSOC_IND:
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		break;
	case EVENT_P2P_LISTEN_COMP_IND:
		event_packet->event_code = WLAND_E_P2P_DISC_LISTEN_COMPLETE;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		if (event_len != ETH_ALEN)
			dev_err_ratelimited(dev,
					    "P2P listen complete event invalid length: %u\n",
					    event_len);
		for (i = 0; i < WLAND_MAX_IFS; ++i) {
			if (drvr->iflist[i] &&
			    !memcmp(drvr->iflist[i]->mac_addr, buffer + 4,
				    ETH_ALEN)) {
				event_packet->bsscfgidx =
					drvr->iflist[i]->bssidx;
				break;
			}
		}
		if (i == WLAND_MAX_IFS)
			dev_err_ratelimited(dev,
					    "P2P listen complete event unknown MAC: %pM\n",
					    buffer + 4);
		break;

	case EVENT_ADD_P2P_IF_EVENT:
		event_packet->event_code = WLAND_E_IF_ADD;
		event_packet->action = WLAND_ACTION_IF_ADD;
		event_packet->bsscfgidx = buffer[4];
		memcpy(event_packet->addr, buffer + 5, ETH_ALEN);
		break;

	case EVENT_P2P_SCAN_COMP_EVENT:
		event_packet->event_code = WLAND_E_ESCAN_RESULT;
		event_packet->status = STATUS_TIMEOUT;
		memcpy(event_packet->addr, buffer + 4, ETH_ALEN);
		break;
	case EVENT_P2P_IF_CHANGE_COMP_EVENT:
		event_packet->event_code = WLAND_E_IF_CHANGE;
		event_packet->action = WLAND_ACTION_IF_CHANGE;
		event_packet->bsscfgidx = buffer[4];
		memcpy(event_packet->addr, buffer + 5, ETH_ALEN);
		break;
	case EVENT_P2P_ACTION_TX_COMP_EVENT:
		event_packet->event_code = WLAND_E_ACT_FRAME_COMPLETE;
		event_packet->status = buffer[4];
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		memcpy(event_packet->addr, buffer + 5, ETH_ALEN);
		break;
	case EVENT_MICHAEL_MIC_FAILURE:
		event_packet->event_code = WLAND_E_MIC_ERROR;
		event_packet->status = buffer[2];
		break;
	case EVENT_ADDBA:
		/* Interface, peer and TID identify the asynchronous completion. */
		if (event_packet->datalen < 13 || buffer[4] >= WLAND_MAX_IFS ||
		    buffer[11] >= 8)
			return -EINVAL;
		memset(&addba_msg, 0, sizeof(addba_msg));
		event_packet->event_code = WLAND_E_ADDBA;
		event_packet->bsscfgidx = buffer[4];
		event_packet->action = buffer[12] ?
			WLAND_ACTION_ADDBA_DONE : WLAND_ACTION_DELBA;
		addba_msg.tid = buffer[11];
		if (event_packet->datalen > 13)
			addba_msg.action = buffer[13];
		memcpy(addba_msg.mac_addr, buffer + 5, ETH_ALEN);
		event_packet->datalen = sizeof(addba_msg);
		wland_fweh_push_event(drvr, event_packet, &addba_msg);
		return 0;
	case EVENT_SOFTWARE_RESET:
		dev_warn_ratelimited(dev, "software reset event: 0x%x\n",
				     buffer[4]);
		if (buffer[4])
			atomic_set(&drvr->bus_if->software_reset, 1);
		else
			atomic_set(&drvr->bus_if->software_reset, 0);
		return 0;
	case EVENT_HOST_RESET_COMPLATE:
		if (atomic_read(&drvr->bus_if->software_reset) == 2) {
			event_packet->event_code = WLAND_E_RESET_FW;
			event_packet->status = STATUS_SUCCESS;
			wland_fweh_push_event(drvr, event_packet, buffer);
			atomic_set(&drvr->bus_if->software_reset, 0);
		}
		return 0;
	default:
		ret = -EBADE;
		dev_err_ratelimited(dev, "invalid event type: 0x%02x\n",
				    event_type);
		break;
	}

	wland_fweh_push_event(drvr, event_packet, buffer);

	return ret;
}

static s32 wland_handle_async_info(struct wland_private *drvr,
				   struct wland_event_msg *event_packet,
				   u8 *p_buffer)
{
	s32 ret = 0;
	u16 wid_id = 0, frame_len = 0;
	u8 *p_frame, sub_type = 0;
	u8 wid_value = 0;
	int i;

	/* Type, ID, message length, WID and WID length, then the value */
	if (event_packet->datalen < 8)
		return -EINVAL;
	wid_id = p_buffer[4] | (p_buffer[5] << 8);

	switch (wid_id) {
	case WID_P2P_ACTION_TO_HOST:
		event_packet->event_code = WLAND_E_ACTION_FRAME_RX;
		event_packet->status = STATUS_SUCCESS;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		wland_fweh_push_event(drvr, event_packet, p_buffer);
		break;
	case WID_NETWORK_INFO:
		/* The value is an RSSI byte and a received management frame */
		frame_len = p_buffer[6] | (p_buffer[7] << 8);
		if (frame_len < 1 + MAC_HDR_LEN ||
		    frame_len > event_packet->datalen - 8)
			return -EINVAL;
		p_frame = &p_buffer[9]; /* initial position of mac_header */
		sub_type = p_frame[0] & 0xFC;
		switch (sub_type) {
		case BEACON:
		case PROBE_RSP:
			event_packet->event_code = WLAND_E_ESCAN_RESULT;
			event_packet->status = STATUS_SUCCESS;
			event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;
			wland_fweh_push_event(drvr, event_packet, p_buffer);
			break;
		case ASSOC_REQ:
		case ASSOC_RSP:
			for (i = 0; i < P2PAPI_BSSCFG_MAX; ++i) {
				if (drvr->iflist[i] &&
				    !memcmp(drvr->iflist[i]->mac_addr,
					    p_frame + 4, ETH_ALEN))
					break;
			}
			if (i != P2PAPI_BSSCFG_MAX) {
				wland_get_assoc_ies_from_frame(drvr->iflist[i],
							       p_frame,
							       frame_len - 1,
							       sub_type);
			}
			break;
		default:
			break;
		}
		break;
	case WID_STA_JOIN_INFO_91H:
		/*
		 * Format of STA JOIN INFO message:
		 * | Last AID | MAC addr | Type (11a/b/g/n) | 11g info | Sec |
		 * | 1 byte   | 6 bytes  | 1 byte           | 1 byte   | 1 B |
		 */
		if (drvr->bus_if->chip == WLAND_VER_91_H) {
			p_frame = &p_buffer[8];
			memcpy(event_packet->addr, p_frame + 1, ETH_ALEN);

			event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;

			sub_type = p_frame[7];
			if (sub_type) {
				event_packet->event_code = WLAND_E_CONNECT_IND;
				event_packet->action =
					WLAND_ACTION_AP_CONNECTED;
			} else {
				event_packet->event_code =
					WLAND_E_DISCONNECT_IND;
				event_packet->action =
					WLAND_ACTION_AP_DISCONNECTED;
			}
			wland_fweh_push_event(drvr, event_packet, p_buffer);
		}
		break;
	case WID_GO_JOIN_INFO:
		if (drvr->bus_if->chip == WLAND_VER_91_H) {
			p_frame = &p_buffer[8];
			memcpy(event_packet->addr, p_frame + 1, ETH_ALEN);

			event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;

			sub_type = p_frame[7];
			if (sub_type) {
				event_packet->event_code = WLAND_E_CONNECT_IND;
				event_packet->action =
					WLAND_ACTION_AP_CONNECTED;
			} else {
				event_packet->event_code =
					WLAND_E_DISCONNECT_IND;
				event_packet->action =
					WLAND_ACTION_AP_DISCONNECTED;
			}
			wland_fweh_push_event(drvr, event_packet, p_buffer);
		}
		break;
	case WID_SCAN_CONNECT_RESULT:
		if (drvr->bus_if->chip == WLAND_VER_91_H) {
			wid_value = p_buffer[7];
			switch (wid_value) {
			case RESULT_SCAN_COMP:
				event_packet->event_code = WLAND_E_ESCAN_RESULT;
				event_packet->status = STATUS_TIMEOUT;
				event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;
				wland_fweh_push_event(drvr, event_packet, NULL);
				break;
			case RESULT_CONN_FAIL:
				event_packet->event_code = WLAND_E_CONNECT_IND;
				event_packet->status = STATUS_TIMEOUT;
				wland_fweh_push_event(drvr, event_packet, NULL);
				break;
			case RESULT_P2P_CONN_FAIL:
				event_packet->event_code = WLAND_E_CONNECT_IND;
				event_packet->status = STATUS_TIMEOUT;
				event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
				wland_fweh_push_event(drvr, event_packet, NULL);
				break;
			default:
				break;
			}
		}
		break;
	default:
		dev_err_ratelimited(drvr->bus_if->dev,
				    "invalid async event WID: 0x%04x\n",
				    wid_id);
		break;
	}

	return ret;
}

/* Snoop DHCP ACKs to learn the lease address and the server details. */
static void wland_rx_parse_dhcp(struct wland_if *ifp, struct sk_buff *skb)
{
	struct wland_event_msg event_packet;
	struct iphdr *iph;
	struct udphdr *udph;
	struct dhcp_msg *dhcph;
	unsigned int ip_hl;
	u32 udp_len, length;
	u16 offset = 0;
	u8 *option;

	if (ifp->bssidx != P2PAPI_BSSCFG_PRIMARY ||
	    skb->pkt_type == PACKET_OTHERHOST ||
	    skb->protocol != htons(ETH_P_IP) ||
	    skb->len < sizeof(struct iphdr))
		return;

	iph = (struct iphdr *)skb->data;
	ip_hl = iph->ihl << 2;
	if (iph->protocol != IPPROTO_UDP || iph->ihl < 5 ||
	    skb->len < ip_hl + sizeof(struct udphdr) + sizeof(struct dhcp_msg))
		return;

	udph = (struct udphdr *)((u8 *)iph + ip_hl);
	if (udph->source != htons(SERVER_PORT) ||
	    udph->dest != htons(CLIENT_PORT))
		return;

	dhcph = (struct dhcp_msg *)((u8 *)udph + sizeof(struct udphdr));
	udp_len = ntohs(udph->len);
	if (udp_len < sizeof(struct udphdr) +
		      offsetof(struct dhcp_msg, options) ||
	    dhcph->cookie != htonl(DHCP_MAGIC) || dhcph->op != 2 ||
	    memcmp(dhcph->chaddr, ifp->mac_addr, ETH_ALEN) != 0)
		return;

	length = min_t(u32, udp_len - sizeof(struct udphdr) -
		       offsetof(struct dhcp_msg, options),
		       sizeof(dhcph->options));
	option = dhcph->options;

	while (offset < length && option[offset] != DHCP_OPTION_END) {
		if (option[offset] == 0) {
			/* PAD option is 1 byte without length */
			offset++;
			continue;
		}
		if (offset + 1 >= length || option[offset + 1] == 0 ||
		    offset + 2 + option[offset + 1] > length)
			break;

		if (option[offset] == DHCP_OPTION_MESSAGE_TYPE) {
			if (option[offset + 1] >= 1 &&
			    option[offset + 2] == DHCP_ACK) {
				memset(&event_packet, 0, sizeof(event_packet));
				event_packet.event_code = WLAND_E_ARP_OFFLOAD;
				event_packet.datalen = 4;
				wland_fweh_push_event(ifp->drvr,
						      &event_packet,
						      (void *)&dhcph->yiaddr);
			}
		}
		offset += 2 + option[offset + 1];
	}
}

void wland_netif_rx(struct wland_if *ifp, struct sk_buff *skb)
{
	skb->dev = ifp->ndev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = CHECKSUM_NONE;

	if (skb->pkt_type == PACKET_MULTICAST)
		ifp->stats.multicast++;

	/* free skb if interface is down */
	if (!(ifp->ndev->flags & IFF_UP)) {
		wland_pkt_buf_free_skb(skb);
		return;
	}

	wland_rx_parse_dhcp(ifp, skb);

	ifp->stats.rx_bytes += skb->len;
	ifp->stats.rx_packets++;

	if (in_interrupt())
		netif_rx(skb);
	else
		netif_rx_ni(skb);
}

/* Receive frame for delivery to OS. Callee disposes of rxp. */
void wland_process_8023_pkt(struct wland_bus *bus_if, struct sk_buff *skb)
{
	s32 ifidx = 0;
	int ret;
	struct wland_private *drvr = bus_if->drvr;
	struct wland_if *ifp;

	ret = wland_proto_hdrpull(drvr, &ifidx, skb);
	ifp = skb->dev ? netdev_priv(skb->dev) : NULL;

	if (ret || !ifp || !ifp->ndev) {
		if ((ret != -ENODATA) && ifp)
			ifp->stats.rx_errors++;
		dev_err_ratelimited(bus_if->dev, "RX packet error: %d\n", ret);
		wland_pkt_buf_free_skb(skb);
	} else {
		wland_netif_rx(ifp, skb);
	}
}

static struct recv_frame *wland_free_recv_queue_init(struct list_head *q,
						     int qsize)
{
	int i;
	struct recv_frame *req, *reqs;

	reqs = vmalloc(qsize * sizeof(struct recv_frame));
	if (!reqs)
		return NULL;

	req = reqs;
	for (i = 0; i < qsize; i++) {
		INIT_LIST_HEAD(&req->list2);
		list_add(&req->list2, q);
		req->len = 0;
		req++;
	}

	return reqs;
}

static void wland_recvframe_free_q(struct list_head *q)
{
	struct recv_frame *req, *next;

	list_for_each_entry_safe(req, next, q, list2)
		list_del_init(&req->list2);
}

void wland_recvframe_enq(spinlock_t *lock, struct list_head *q,
			 struct list_head *list, u8 *counter)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	list_add_tail(list, q);
	if (counter)
		(*counter)++;
	spin_unlock_irqrestore(lock, flags);
}

static struct recv_frame *wland_recvframe_deq(spinlock_t *lock,
					      struct list_head *q,
					      u8 list_count, u8 *counter)
{
	unsigned long flags;
	struct recv_frame *req;

	spin_lock_irqsave(lock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(lock, flags);
		return NULL;
	}
	if (list_count == 1) { /* for uc_pending_queue */
		req = list_entry(q->next, struct recv_frame, list);
	} else if (list_count == 2) { /* for free_recv_queue */
		req = list_entry(q->next, struct recv_frame, list2);
	} else {
		spin_unlock_irqrestore(lock, flags);
		return NULL;
	}
	list_del_init(q->next);
	if (counter)
		(*counter)--;

	spin_unlock_irqrestore(lock, flags);
	return req;
}

static int wland_is_mcast(const unsigned char *da)
{
	return (*da) & 0x01;
}

static void wland_recv_indicatepkts_pkt_loss_cnt(struct wland_rx_info *rx_info,
						 u64 prev_seq, u64 current_seq)
{
	if (current_seq < prev_seq)
		rx_info->dbg_rx_ampdu_loss_count +=
			(4096 + current_seq - prev_seq);
	else
		rx_info->dbg_rx_ampdu_loss_count += (current_seq - prev_seq);
}

static int wland_recv_indicatepkt(struct wland_rx_info *rx_info,
				  struct recv_frame *precv_frame)
{
	struct list_head *pfree_recv_queue = &rx_info->free_recv_queue;
	struct sk_buff *skb = precv_frame->pkt;
	struct device *dev = rx_info->devinfo->dev;
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	if (!skb) {
		dev_err_ratelimited(dev, "RX frame skb is NULL\n");
		goto fail;
	}

	skb->data = precv_frame->rx_data;
	skb_set_tail_pointer(skb, precv_frame->len);
	skb->len = precv_frame->len;

	wland_process_8023_pkt(bus_if, skb);

	precv_frame->pkt = NULL;

fail:
	wland_recvframe_enq(&rx_info->free_recv_lock, pfree_recv_queue,
			    &precv_frame->list2, &rx_info->free_recv_cnt);

	return 0;
}

static bool
wland_recv_indicatepkts_in_order(struct wland_rx_info *rx_info,
				 struct recv_reorder_ctrl *preorder_ctrl,
				 int bforced)
{
	struct list_head *phead, *plist;
	struct recv_frame *prframe;
	struct rx_pkt_attrib *pattrib;
	bool pkt_in_buf = false;
	unsigned long flags;
	spinlock_t *lock = &preorder_ctrl->pending_recvframe_queue_lock;

	spin_lock_irqsave(lock, flags);
	if (bforced) {
		u16 ind_seq;

		phead = &preorder_ctrl->pending_recvframe_queue;
		if (list_empty(phead)) {
			spin_unlock_irqrestore(lock, flags);
			return false;
		}

		plist = phead->next;
		prframe = list_entry(plist, struct recv_frame, list);
		pattrib = &prframe->attrib;
		ind_seq = preorder_ctrl->indicate_seq;

		wland_recv_indicatepkts_pkt_loss_cnt(rx_info, ind_seq,
						     pattrib->seq_num);
		preorder_ctrl->indicate_seq = pattrib->seq_num;
	}

	phead = &preorder_ctrl->pending_recvframe_queue;
	while (1) {
		if (list_empty(phead))
			break;

		plist = phead->next;
		prframe = list_entry(plist, struct recv_frame, list);
		pattrib = &prframe->attrib;

		if (!SN_LESS(preorder_ctrl->indicate_seq, pattrib->seq_num)) {
			list_del_init(&prframe->list);

			if (SN_EQUAL(preorder_ctrl->indicate_seq,
				     pattrib->seq_num))
				preorder_ctrl->indicate_seq =
					(preorder_ctrl->indicate_seq + 1) &
					0xFFF;

			if (!pattrib->amsdu)
				wland_recv_indicatepkt(rx_info, prframe);
		} else {
			pkt_in_buf = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);

	return pkt_in_buf;
}

static void wland_reordering_ctrl_timeout_worker(struct work_struct *work)
{
	struct recv_reorder_ctrl *preorder_ctrl =
		container_of(work, struct recv_reorder_ctrl,
			     reordering_ctrl_timer_work);
	struct wland_rx_info *rx_info = preorder_ctrl->rx_info;

	if (!READ_ONCE(preorder_ctrl->enable))
		return;

	if (wland_recv_indicatepkts_in_order(rx_info, preorder_ctrl, true)) {
		unsigned long flags;
		spinlock_t *lock = &preorder_ctrl->pending_recvframe_queue_lock;

		spin_lock_irqsave(lock, flags);
		if (preorder_ctrl->enable)
			mod_timer(&preorder_ctrl->reordering_ctrl_timer,
				  jiffies +
				  msecs_to_jiffies(REORDER_WAIT_TIME));
		spin_unlock_irqrestore(lock, flags);
	}
}

static void wland_reordering_ctrl_timeout_handler(struct timer_list *t)
{
	struct recv_reorder_ctrl *preorder_ctrl =
		from_timer(preorder_ctrl, t, reordering_ctrl_timer);

	schedule_work(&preorder_ctrl->reordering_ctrl_timer_work);
}

static inline u8 *wland_recvframe_put(struct recv_frame *precvframe, int sz)
{
	if (!precvframe)
		return NULL;

	precvframe->rx_tail += sz;
	if (precvframe->rx_tail > precvframe->rx_end) {
		precvframe->rx_tail -= sz;
		return NULL;
	}

	precvframe->len += sz;
	return precvframe->rx_tail;
}

static int wland_check_indicate_seq(struct recv_reorder_ctrl *preorder_ctrl,
				    u16 seq_num)
{
	u8 wsize = preorder_ctrl->wsize_b;
	u16 wend = (preorder_ctrl->indicate_seq + wsize - 1) & 0xFFF;

	if (preorder_ctrl->indicate_seq == 0xFFFF)
		preorder_ctrl->indicate_seq = seq_num;

	if (SN_LESS(seq_num, preorder_ctrl->indicate_seq))
		return -1;

	if (SN_EQUAL(seq_num, preorder_ctrl->indicate_seq)) {
		preorder_ctrl->indicate_seq =
			(preorder_ctrl->indicate_seq + 1) & 0xFFF;
	} else if (SN_LESS(wend, seq_num)) {
		if (seq_num >= (wsize - 1))
			preorder_ctrl->indicate_seq = seq_num - (wsize - 1);
		else
			preorder_ctrl->indicate_seq =
				0xFFF - (wsize - (seq_num + 1)) + 1;
	}

	return 0;
}

static int
wland_enqueue_reorder_recvframe(struct recv_reorder_ctrl *preorder_ctrl,
				struct recv_frame *prframe)
{
	struct rx_pkt_attrib *pattrib = &prframe->attrib;
	struct list_head *ppending_recvframe_queue =
		&preorder_ctrl->pending_recvframe_queue;
	struct list_head *phead, *plist;
	struct recv_frame *pnextrframe;
	struct rx_pkt_attrib *pnextattrib;
	unsigned long flags;
	spinlock_t *lock = &preorder_ctrl->pending_recvframe_queue_lock;

	phead = ppending_recvframe_queue;
	spin_lock_irqsave(lock, flags);

	plist = phead->next;
	while (phead != plist) {
		pnextrframe = list_entry(plist, struct recv_frame, list);
		pnextattrib = &pnextrframe->attrib;

		if (SN_LESS(pnextattrib->seq_num, pattrib->seq_num)) {
			plist = plist->next;
			continue;
		}
		if (SN_EQUAL(pnextattrib->seq_num, pattrib->seq_num)) {
			spin_unlock_irqrestore(lock, flags);
			return -1;
		}
		break;
	}

	list_add_tail(&prframe->list, plist);
	spin_unlock_irqrestore(lock, flags);

	return 0;
}

struct rx_reorder_msg *wland_rx_reorder_msg_init(struct wland_rx_info *rx_info,
						 const u8 *mac_addr)
{
	u8 i = 0;
	struct recv_reorder_ctrl *preorder_ctrl = NULL;
	u16 rx_seq_init_val = 0xffff;
	struct wland_bus *bus_if = NULL;
	struct rx_reorder_msg *reorder_msg;

	if (!rx_info)
		return NULL;

	bus_if = rx_info->devinfo->bus_pub.bus;
	if (bus_if->state == WLAND_BUS_DOWN)
		return NULL;

	reorder_msg = kmalloc(sizeof(*reorder_msg), GFP_ATOMIC);
	if (!reorder_msg)
		return NULL;

	INIT_LIST_HEAD(&reorder_msg->list);
	memcpy(reorder_msg->mac_addr, mac_addr, ETH_ALEN);

	for (i = 0; i < 16; i++) {
		preorder_ctrl = &reorder_msg->preorder_ctrl[i];

		preorder_ctrl->enable = true;
		preorder_ctrl->indicate_seq = 0xffff;
		preorder_ctrl->wend_b = 0xffff;
		preorder_ctrl->wsize_b = WLAND_REORDER_WINSIZE;
		preorder_ctrl->rx_info = rx_info;
		preorder_ctrl->tid_rxseq = rx_seq_init_val;

		INIT_LIST_HEAD(&preorder_ctrl->pending_recvframe_queue);
		spin_lock_init(&preorder_ctrl->pending_recvframe_queue_lock);

		timer_setup(&preorder_ctrl->reordering_ctrl_timer,
			    wland_reordering_ctrl_timeout_handler, 0);

		INIT_WORK(&preorder_ctrl->reordering_ctrl_timer_work,
			  wland_reordering_ctrl_timeout_worker);
	}

	return reorder_msg;
}

void wland_rx_reorder_msg_deinit(struct wland_rx_info *rx_info,
				 struct rx_reorder_msg *reorder_msg)
{
	u8 i = 0;
	unsigned long flags;
	struct recv_reorder_ctrl *preorder_ctrl = NULL;

	if (!rx_info)
		return;

	if (!list_empty(&reorder_msg->list))
		list_del_init(&reorder_msg->list);

	for (i = 0; i < 16; i++) {
		struct recv_frame *req, *next;
		spinlock_t *lock;
		struct list_head *queue;

		preorder_ctrl = &reorder_msg->preorder_ctrl[i];
		lock = &preorder_ctrl->pending_recvframe_queue_lock;
		queue = &preorder_ctrl->pending_recvframe_queue;

		/* Stop the timer producer before draining its work item. */
		spin_lock_irqsave(lock, flags);
		preorder_ctrl->enable = false;
		spin_unlock_irqrestore(lock, flags);
		del_timer_sync(&preorder_ctrl->reordering_ctrl_timer);
		cancel_work_sync(&preorder_ctrl->reordering_ctrl_timer_work);
		spin_lock_irqsave(lock, flags);
		preorder_ctrl->enable = false;
		list_for_each_entry_safe(req, next, queue, list) {
			list_del_init(&req->list);
			if (req->pkt)
				dev_kfree_skb(req->pkt);
			req->pkt = NULL;
			wland_recvframe_enq(&rx_info->free_recv_lock,
					    &rx_info->free_recv_queue,
					    &req->list2,
					    &rx_info->free_recv_cnt);
		}
		spin_unlock_irqrestore(lock, flags);
	}
	kfree(reorder_msg);
}

static int wland_process_8023_pkt_reorder(struct wland_rx_info *rx_info,
					  struct sk_buff *skb)
{
	struct device *dev = rx_info->devinfo->dev;
	u8 *buf;
	int ret = 0;
	struct rx_pkt_attrib *pattrib = NULL;
	struct recv_frame *precvframe = NULL;
	struct list_head *pfree_recv_queue = &rx_info->free_recv_queue;
	struct wland_if *ifp = skb->dev ? netdev_priv(skb->dev) : NULL;
	u8 *mac;
	u32 mtu;
	unsigned long flags;
	struct ethhdr *eh = (struct ethhdr *)(skb->data + WID_HEADER_LEN_RX);
	struct rx_reorder_msg *reorder_msg;
	struct recv_reorder_ctrl *order;
	spinlock_t *order_lock;
	struct timer_list *order_timer;

	if (!ifp) {
		dev_err_ratelimited(dev, "RX packet interface is NULL\n");
		dev_kfree_skb(skb);
		return -EINVAL;
	}

	mtu = USB_MAX_PKT_SIZE;

	precvframe = wland_recvframe_deq(&rx_info->free_recv_lock,
					 pfree_recv_queue, 2,
					 &rx_info->free_recv_cnt);
	if (!precvframe) {
		dev_kfree_skb(skb);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&precvframe->list);
	pattrib = &precvframe->attrib;

	buf = skb->data;
	pattrib->seq_num = (buf[5] << 4) | ((buf[4] & 0xF0) >> 4);
	pattrib->qos = (wland_get_sub_type(buf + 2) & BIT7) ? 1 : 0;
	pattrib->eth_type = ntohs(eh->h_proto);
	pattrib->priority = buf[4] & 0x0F;
	pattrib->pkt_len = (u16)(buf[0] | ((buf[1] & 0x0F) << 8)) -
		WID_HEADER_LEN_RX;
	skb_pull(skb, WID_HEADER_LEN_RX);

	precvframe->rx_data = skb->data;
	precvframe->rx_tail = skb->data;
	precvframe->rx_end = skb->data + mtu;
	precvframe->pkt = skb;
	precvframe->len = 0;
	pattrib->amsdu = 0;

	if (!wland_recvframe_put(precvframe, pattrib->pkt_len)) {
		dev_err_ratelimited(dev,
				    "RX frame buffer overflow (len %u > MTU %u)\n",
				    pattrib->pkt_len, mtu);
		ret = -EMSGSIZE;
		goto fail;
	}

	if (!pattrib->amsdu) {
		if (pattrib->qos != 1 || pattrib->eth_type == ETH_P_PAE ||
		    wland_is_mcast(eh->h_dest))
			return wland_recv_indicatepkt(rx_info, precvframe);
	}

	if (ifp->vif->mode == WL_MODE_BSS) {
		mac = eh->h_dest;
	} else if (ifp->vif->mode == WL_MODE_AP) {
		mac = eh->h_source;
	} else {
		dev_err_ratelimited(dev, "invalid interface mode: %d\n",
				    ifp->vif->mode);
		ret = -EINVAL;
		goto fail;
	}

	spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);

	list_for_each_entry(reorder_msg, &rx_info->rx_reorder_msg_list, list) {
		if (!memcmp(mac, reorder_msg->mac_addr, ETH_ALEN)) {
			precvframe->preorder_ctrl =
				&reorder_msg->preorder_ctrl[pattrib->priority];
			break;
		}
	}
	if (&reorder_msg->list == &rx_info->rx_reorder_msg_list) {
		reorder_msg = wland_rx_reorder_msg_init(rx_info, mac);
		if (!reorder_msg) {
			spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock,
					       flags);
			ret = -ENOMEM;
			goto fail;
		}
		list_add_tail(&reorder_msg->list,
			      &rx_info->rx_reorder_msg_list);
		precvframe->preorder_ctrl =
			&reorder_msg->preorder_ctrl[pattrib->priority];
	}

	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);

	order = precvframe->preorder_ctrl;
	order_lock = &order->pending_recvframe_queue_lock;
	order_timer = &order->reordering_ctrl_timer;

	if (!pattrib->amsdu) {
		if (!order->enable) {
			order->indicate_seq = pattrib->seq_num;
			wland_recv_indicatepkt(rx_info, precvframe);
			order->indicate_seq = (order->indicate_seq + 1) % 4096;
			return 0;
		}
	}

	spin_lock_irqsave(order_lock, flags);
	if (wland_check_indicate_seq(order, pattrib->seq_num)) {
		spin_unlock_irqrestore(order_lock, flags);
		goto fail;
	}
	spin_unlock_irqrestore(order_lock, flags);

	if (wland_enqueue_reorder_recvframe(order, precvframe))
		goto fail;

	if (wland_recv_indicatepkts_in_order(rx_info, order, false)) {
		if (!timer_pending(order_timer))
			mod_timer(order_timer,
				  jiffies +
				  msecs_to_jiffies(REORDER_WAIT_TIME));
	} else {
		if (timer_pending(order_timer))
			del_timer_sync(order_timer);
	}

	return 0;

fail:
	if (precvframe->pkt) {
		dev_kfree_skb(precvframe->pkt);
		precvframe->pkt = NULL;
	}
	wland_recvframe_enq(&rx_info->free_recv_lock,
			    &rx_info->free_recv_queue,
			    &precvframe->list2, &rx_info->free_recv_cnt);
	return ret;
}

static void wland_process_rx_datapkt(struct wland_bus *bus_if,
				     struct wland_rx_info *rx_info,
				     struct sk_buff *pkt, u16 rx_len)
{
	struct wland_if *ifp = netdev_priv(pkt->dev);
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;

	if (rx_len < WID_HEADER_LEN_RX + ETH_HLEN) {
		dev_err_ratelimited(bus_if->dev, "RX frame too short: %u\n",
				    rx_len);
		wland_pkt_buf_free_skb(pkt);
		return;
	}

	if (vif->wdev.iftype == NL80211_IFTYPE_STATION &&
	    conn_info->wmm_enable && conn_info->n_enable &&
	    !timer_pending(&conn_info->connect_restorework_timeout)) {
		wland_process_8023_pkt_reorder(rx_info, pkt);
	} else if (vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT ||
		   vif->wdev.iftype == NL80211_IFTYPE_P2P_GO) {
		wland_process_8023_pkt_reorder(rx_info, pkt);
	} else {
		skb_pull(pkt, WID_HEADER_LEN_RX);
		wland_process_8023_pkt(bus_if, pkt);
	}
}

static int wland_process_rxframes(struct wland_rx_info *rx_info)
{
	struct wland_usbdev_info *devinfo = rx_info->devinfo;
	struct device *dev = devinfo->dev;
	int ret = 0;
	u8 rx_type, msg_type, *buf;
	u16 size = 0, rx_len = 0, wid = 0;
	unsigned long flags = 0;
	struct sk_buff *skb = NULL;
	struct wland_event_msg event_packet;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr = bus_if->drvr;

	if (bus_if->state == WLAND_BUS_DOWN)
		return ret;

	while (wland_pktq_mlen(&rx_info->rxq, ~rx_info->flowcontrol)) {
		wland_dhd_os_sdlock_rxq(rx_info, &flags);
		skb = wland_pktq_mdeq(&rx_info->rxq);
		wland_dhd_os_sdunlock_rxq(rx_info, &flags);
		atomic_dec(&rx_info->rx_dpc_tskcnt);
		if (!skb)
			break;

		buf = skb->data;
		size = skb->len;
		if (size < WID_HEADER_LEN) {
			wland_pkt_buf_free_skb(skb);
			ret = -EINVAL;
			continue;
		}
		rx_len = (u16)(buf[0] | ((buf[1] & 0x0F) << 8));

		if (rx_len < WID_HEADER_LEN || rx_len > size) {
			dev_err_ratelimited(dev,
					    "invalid RX payload length (rx_len %u, size %u)\n",
					    rx_len, size);
			wland_pkt_buf_free_skb(skb);
			ret = -EIO;
			continue;
		}
		rx_type = (u8)buf[1] >> 4;

		if (rx_type == PKT_TYPE_IND || rx_type == PKT_TYPE_DATA_MAC1) {
			struct wland_if *ifp =
				drvr->iflist[rx_type == PKT_TYPE_DATA_MAC1 ? 1 : 0];

			if (!ifp || !ifp->ndev) {
				wland_pkt_buf_free_skb(skb);
				continue;
			}
			skb->dev = ifp->ndev;
			wland_process_rx_datapkt(bus_if, rx_info, skb, rx_len);

		} else if (rx_type == PKT_TYPE_AGGR_MAC0 ||
			   rx_type == PKT_TYPE_AGGR_MAC1) {
			dev_err_ratelimited(dev,
					    "aggregated packets received but unsupported\n");
			wland_pkt_buf_free_skb(skb);
			ret = -EBADE;

		} else if (rx_type == PKT_TYPE_CFG_RSP ||
			   rx_type == PKT_TYPE_CFG_MAC1) {
			if (rx_len < WID_HEADER_LEN + 4 ||
			    rx_len > rx_info->rxblen) {
				wland_pkt_buf_free_skb(skb);
				return -EINVAL;
			}
			msg_type = buf[2];
			memset(&event_packet, 0, sizeof(event_packet));

			event_packet.datalen = rx_len - WID_HEADER_LEN;
			buf += WID_HEADER_LEN;

			switch (msg_type) {
			case WLAND_WID_MSG_RESP:
				spin_lock_bh(&rx_info->rxctl_lock);
				rx_info->rxctl = rx_info->rxbuf;
				rx_info->rxlen = rx_len;
				memcpy(rx_info->rxctl, skb->data, rx_len);
				spin_unlock_bh(&rx_info->rxctl_lock);
				wland_usb_data_resp_wake(devinfo);
				wland_pkt_buf_free_skb(skb);
				break;
			case WLAND_WID_MSG_NETINFO:
				wland_handle_async_info(bus_if->drvr,
							&event_packet, buf);
				wland_pkt_buf_free_skb(skb);
				break;
			case WLAND_WID_MSG_EVENT:
				wland_handle_network_link_event(bus_if->drvr,
								&event_packet,
								buf);
				wland_pkt_buf_free_skb(skb);
				break;
			case WLAND_WID_MSG_MAC_STATUS:
				wid = MAKE_WORD16(buf[4], buf[5]);
				if (wid == WID_STATUS)
					wland_handle_mac_status(bus_if->drvr,
								&event_packet,
								buf);
				else
					dev_err_ratelimited(dev,
							    "unexpected MAC status WID: 0x%04x\n",
							    wid);
				wland_pkt_buf_free_skb(skb);
				break;
			default:
				dev_err_ratelimited(dev,
						    "invalid RX frame message type: 0x%02x\n",
						    msg_type);
				wland_pkt_buf_free_skb(skb);
				ret = -EBADE;
				break;
			}
		} else {
			dev_err_ratelimited(dev,
					    "invalid RX packet type: %u\n",
					    rx_type);
			wland_pkt_buf_free_skb(skb);
			ret = -EBADE;
		}
	}
	return ret;
}

static void wland_rx_dpc(struct wland_rx_info *rx_info)
{
	struct wland_bus *bus_if = rx_info->devinfo->bus_pub.bus;

	if (bus_if->state == WLAND_BUS_DOWN)
		return;

	wland_process_rxframes(rx_info);
}

static void wland_rx_worker(struct work_struct *work)
{
	struct wland_rx_info *rx_info =
		container_of(work, struct wland_rx_info, rx_work);

	if (rx_info && atomic_read(&rx_info->rx_dpc_tskcnt) > 0)
		wland_rx_dpc(rx_info);
}

struct wland_rx_info *wland_rx_init(void *arg)
{
	struct wland_rx_info *rx_info;

	rx_info = kzalloc(sizeof(*rx_info), GFP_KERNEL);
	if (!rx_info)
		return NULL;

	rx_info->flowcontrol = 0;

	rx_info->devinfo = (struct wland_usbdev_info *)arg;

	wland_pktq_init(&rx_info->rxq, (PRIOMASK + 1), RXQLEN);

	INIT_WORK(&rx_info->rx_work, wland_rx_worker);
	rx_info->wland_rxwq = create_singlethread_workqueue("wland_rxwq");
	if (!rx_info->wland_rxwq) {
		dev_err(rx_info->devinfo->dev,
			"failed to create RX workqueue\n");
		kfree(rx_info);
		return NULL;
	}

	spin_lock_init(&rx_info->rxqlock);
	spin_lock_init(&rx_info->rxctl_lock);
	atomic_set(&rx_info->rx_dpc_tskcnt, 0);

	INIT_LIST_HEAD(&rx_info->free_recv_queue);
	spin_lock_init(&rx_info->free_recv_lock);

	rx_info->recv_frames =
		wland_free_recv_queue_init(&rx_info->free_recv_queue,
					   NR_RECVFRAME);

	if (!rx_info->recv_frames) {
		destroy_workqueue(rx_info->wland_rxwq);
		kfree(rx_info);
		return NULL;
	}
	rx_info->free_recv_cnt = NR_RECVFRAME;

	spin_lock_init(&rx_info->rx_reorder_msg_lock);
	INIT_LIST_HEAD(&rx_info->rx_reorder_msg_list);

	return rx_info;
}

/* Call after transport completion producers have been stopped. */
void wland_rx_quiesce(struct wland_rx_info *rx_info)
{
	unsigned long flags;
	struct rx_reorder_msg *reorder_msg;

	cancel_work_sync(&rx_info->rx_work);

	for (;;) {
		spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);
		if (list_empty(&rx_info->rx_reorder_msg_list)) {
			spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock,
					       flags);
			break;
		}
		reorder_msg = list_first_entry(&rx_info->rx_reorder_msg_list,
					       struct rx_reorder_msg, list);
		list_del_init(&reorder_msg->list);
		spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
		/* del_timer_sync/cancel_work_sync may sleep. */
		wland_rx_reorder_msg_deinit(rx_info, reorder_msg);
	}
}

void wland_rx_uinit(struct wland_rx_info *rx_info)
{
	wland_rx_quiesce(rx_info);
	if (rx_info->wland_rxwq)
		destroy_workqueue(rx_info->wland_rxwq);

	wland_pktq_flush(&rx_info->rxq, true, NULL, NULL);
	spin_lock_bh(&rx_info->rxctl_lock);
	rx_info->rxlen = 0;
	spin_unlock_bh(&rx_info->rxctl_lock);

	wland_recvframe_free_q(&rx_info->free_recv_queue);

	if (rx_info->recv_frames)
		vfree(rx_info->recv_frames);

	kfree(rx_info->rxbuf);
	rx_info->rxctl = NULL;
	rx_info->rxbuf = NULL;
	rx_info->rxlen = 0;

	kfree(rx_info);
}
