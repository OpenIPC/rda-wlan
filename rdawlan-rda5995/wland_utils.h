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

#ifndef	_WLAND_UTILS_H_
#define	_WLAND_UTILS_H_

#include <linux/delay.h>
#include <linux/skbuff.h>
#include "../include/80211.h"

/* Multi-precedence packet queue */
#define PKTQ_MAX_PREC           16	/* Maximum precedence levels */

struct pktq_prec {
	struct sk_buff_head skblist;
	u16 max;		/* maximum number of queued packets */
};

/* multi-priority pkt queue */
struct pktq {
	u16 num_prec;	/* number of precedences in use */
	u16 hi_prec;	/* rapid dequeue hint (>= highest non-empty prec) */
	u16 max;	/* total max packets */
	u16 len;	/* total number of packets */
	/* q array must be last (# elements is PKTQ_MAX_PREC or 1) */
	struct pktq_prec q[PKTQ_MAX_PREC];
};

static inline bool pktq_pfull(struct pktq *pq, int prec)
{
	return pq->q[prec].skblist.qlen >= pq->q[prec].max;
}

static inline bool pktq_full(struct pktq *pq)
{
	return pq->len >= pq->max;
}

struct sk_buff *wland_pktq_penq(struct pktq *pq, int prec,
				struct sk_buff *p);
struct sk_buff *wland_pktq_pdeq(struct pktq *pq, int prec);
struct sk_buff *wland_pktq_pdeq_tail(struct pktq *pq, int prec);
struct sk_buff *wland_pktq_pdeq_match(struct pktq *pq, int prec,
				      bool (*match_fn)(struct sk_buff *p,
						       void *arg),
				      void *arg);

/* packet primitives */
void wland_pkt_buf_free_skb(struct sk_buff *skb);

/* operations on a set of precedences in packet queue */
int wland_pktq_mlen(struct pktq *pq, uint prec_bmp);
struct sk_buff *wland_pktq_mdeq(struct pktq *pq);

void wland_pktq_init(struct pktq *pq, int num_prec, int max_len);
/* prec_out may be NULL if caller is not interested in return value */
struct sk_buff *wland_pktq_peek_tail(struct pktq *pq, int *prec_out);
void wland_pktq_flush(struct pktq *pq, bool dir,
		      bool (*fn)(struct sk_buff *, void *), void *arg);
bool wland_prec_enq(struct device *dev, struct pktq *q,
		    struct sk_buff *pkt, int prec);

u16 wland_get_cap_info(u8 *data);
void wland_get_ssid(u8 *data, u8 *ssid, u8 *p_ssid_len);
void wland_get_BSSID(u8 *data, u8 *bssid);
u8 wland_get_current_channel(u8 *data, u16 rx_len);
u8 *wland_get_data_rate(u8 *data, u16 rx_len, u8 type, u8 *rate_size);
u8 *wland_get_tim_elm(u8 *data, u16 rx_len, u16 tag_param_offset);
u16 wland_get_beacon_period(u8 *data);
u8 wland_get_sub_type(u8 *header);

#endif /* _WLAND_UTILS_H_ */

