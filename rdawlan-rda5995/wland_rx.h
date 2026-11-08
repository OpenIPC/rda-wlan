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
#ifndef _WLAND_RX_H_
#define _WLAND_RX_H_

#define PRIOMASK			7
#define RXQLEN				200	/* bulk rx queue length */

struct dhcp_msg {
	u8 op;
	u8 htype;
	u8 hlen;
	u8 hops;
	u32 xid;
	u16 secs;
	u16 flags;
	u32 ciaddr;
	u32 yiaddr;
	u32 siaddr;
	u32 giaddr;
	u8 chaddr[16];
	u8 sname[64];
	u8 file[128];
	u32 cookie;
	u8 options[308]; /* 312 - cookie */
};

#define SERVER_PORT			67
#define CLIENT_PORT			68
#define DHCP_MAGIC			0x63825363
#define DHCP_ACK			5
/* RFC 2132 9.6, important for DHCP */
#define DHCP_OPTION_MESSAGE_TYPE	53
#define DHCP_OPTION_END			255

#define NR_RECVFRAME			250
#define SN_LESS(a, b)			((((a) - (b)) & 0x800) != 0)
#define SN_EQUAL(a, b)			((a) == (b))

#define REORDER_WAIT_TIME		120 /* (ms) */

#define WLAND_REORDER_WINSIZE		32

struct rx_pkt_attrib {
	u16	pkt_len;
	u8	amsdu;
	u8	qos;
	u8	priority;
	u16	seq_num;
	u16	eth_type;
};

/* for Rx reordering buffer control */
struct recv_reorder_ctrl {
	struct wland_rx_info *rx_info;
	u8 enable;
	u16 indicate_seq; /* =wstart_b, init_value=0xffff */
	u16 wend_b;
	u8 wsize_b;
	u16 tid_rxseq;
	/* Protects pending_recvframe_queue */
	spinlock_t pending_recvframe_queue_lock;
	struct list_head pending_recvframe_queue;
	struct timer_list reordering_ctrl_timer;
	struct work_struct reordering_ctrl_timer_work;
};

struct rx_reorder_msg {
	u8 mac_addr[ETH_ALEN];
	struct recv_reorder_ctrl preorder_ctrl[16];
	struct list_head list;
};

struct recv_frame {
	struct list_head	list; /* used for uc_sw_dec_pending_queue */
	struct list_head	list2; /* used for free_recv_queue */

	struct sk_buff		*pkt;

	struct rx_pkt_attrib attrib;

	unsigned int len;
	u8 *rx_head;
	u8 *rx_data;
	u8 *rx_tail;
	u8 *rx_end;

	struct recv_reorder_ctrl *preorder_ctrl;
};

struct wland_rx_info {
	struct wland_usbdev_info *devinfo;

	struct workqueue_struct *wland_rxwq;
	struct work_struct rx_work;
	atomic_t rx_dpc_tskcnt;
	/* Protects rxq */
	spinlock_t rxqlock;

	u8 *rxbuf;		/* Buffer for receiving control packets */
	unsigned int rxblen;	/* Allocated length of rxbuf */
	u8 *rxctl;		/* Aligned pointer into rxbuf */

	unsigned int rxlen;		/* Length of valid data in buffer */
	/* Protects rxctl */
	spinlock_t rxctl_lock;

	struct pktq rxq;
	u8 flowcontrol;		/* per prio flow control bitmask */

	/* Protects free_recv_queue */
	spinlock_t free_recv_lock;
	struct list_head free_recv_queue;
	u8 free_recv_cnt;
	struct list_head rx_reorder_msg_list;
	/* Protects rx_reorder_msg_list */
	spinlock_t rx_reorder_msg_lock;
	u32 dbg_rx_ampdu_loss_count;
	struct recv_frame *recv_frames;
};

struct rx_reorder_msg *wland_rx_reorder_msg_init(struct wland_rx_info *rx_info,
						 const u8 *mac_addr);
void wland_rx_reorder_msg_deinit(struct wland_rx_info *rx_info,
				 struct rx_reorder_msg *reorder_msg);
void wland_recvframe_enq(spinlock_t *lock,
			 struct list_head *q, struct list_head *list,
			 u8 *counter);

struct wland_rx_info *wland_rx_init(void *arg);
void wland_rx_uinit(struct wland_rx_info *rx_info);
void wland_rx_quiesce(struct wland_rx_info *rx_info);

void wland_dhd_os_sdlock_rxq(struct wland_rx_info *rx_info,
			     unsigned long *flags);
void wland_dhd_os_sdunlock_rxq(struct wland_rx_info *rx_info,
			       unsigned long *flags);
void wland_process_8023_pkt(struct wland_bus *bus_if, struct sk_buff *skb);

#endif /* _WLAND_RX_H_ */
