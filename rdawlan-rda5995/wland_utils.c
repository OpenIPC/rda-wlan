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
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <asm/unaligned.h>

#include "wland_defs.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_utils.h"

void wland_pkt_buf_free_skb(struct sk_buff *skb)
{
	if (WARN_ON(!skb))
		return;

	dev_kfree_skb_any(skb);
}

/*
 * osl multiple-precedence packet queue
 * hi_prec is always >= the number of the highest non-empty precedence
 */
struct sk_buff *wland_pktq_penq(struct pktq *pq, int prec, struct sk_buff *p)
{
	struct sk_buff_head *q;

	if (pktq_full(pq) || pktq_pfull(pq, prec))
		return NULL;

	q = &pq->q[prec].skblist;
	__skb_queue_tail(q, p);
	pq->len++;

	if (pq->hi_prec < prec)
		pq->hi_prec = (u8)prec;

	return p;
}

struct sk_buff *wland_pktq_pdeq(struct pktq *pq, int prec)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p = skb_dequeue(q);

	if (!p)
		return NULL;

	pq->len--;
	return p;
}

/*
 * precedence based dequeue with match function. Passing a NULL pointer
 * for the match function parameter is considered to be a wildcard so
 * any packet on the queue is returned. In that case it is no different
 * from wland_pktq_pdeq() above.
 */
struct sk_buff *wland_pktq_pdeq_match(struct pktq *pq, int prec,
				      bool (*match_fn)(struct sk_buff *skb,
						       void *arg),
				      void *arg)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p, *next;

	skb_queue_walk_safe(q, p, next) {
		if (!match_fn || match_fn(p, arg)) {
			skb_unlink(p, q);
			pq->len--;
			return p;
		}
	}
	return NULL;
}

struct sk_buff *wland_pktq_pdeq_tail(struct pktq *pq, int prec)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p = skb_dequeue_tail(q);

	if (!p)
		return NULL;

	pq->len--;
	return p;
}

/* Empty the queue at particular precedence level */
/* callback function fn(pkt, arg) returns true if pkt belongs to if */

static void wland_pktq_pflush(struct pktq *pq, int prec, bool dir,
			      bool (*fn)(struct sk_buff *, void *), void *arg)
{
	struct sk_buff_head *q;
	struct sk_buff *p, *next;

	q = &pq->q[prec].skblist;

	skb_queue_walk_safe(q, p, next) {
		if (!fn || (*fn)(p, arg)) {
			skb_unlink(p, q);
			wland_pkt_buf_free_skb(p);
			pq->len--;
		}
	}
}

void wland_pktq_flush(struct pktq *pq, bool dir,
		      bool (*fn)(struct sk_buff *, void *), void *arg)
{
	int prec;

	for (prec = 0; prec < pq->num_prec; prec++)
		wland_pktq_pflush(pq, prec, dir, fn, arg);
}

void wland_pktq_init(struct pktq *pq, int num_prec, int max_len)
{
	int prec;

	/*
	 * pq is variable size; only zero out what's requested
	 */
	memset(pq, 0, offsetof(struct pktq, q) +
		      (sizeof(struct pktq_prec) * num_prec));

	pq->num_prec = (u16)num_prec;
	pq->max = (u16)max_len;

	for (prec = 0; prec < num_prec; prec++) {
		pq->q[prec].max = pq->max;
		skb_queue_head_init(&pq->q[prec].skblist);
	}
}

struct sk_buff *wland_pktq_peek_tail(struct pktq *pq, int *prec_out)
{
	int prec;

	if (pq->len == 0)
		return NULL;

	for (prec = 0; prec < pq->hi_prec; prec++)
		if (!skb_queue_empty(&pq->q[prec].skblist))
			break;

	if (prec_out)
		*prec_out = prec;

	return skb_peek_tail(&pq->q[prec].skblist);
}

/* Return sum of lengths of a specific set of precedences */
int wland_pktq_mlen(struct pktq *pq, uint prec_bmp)
{
	int prec, len = 0;

	for (prec = 0; prec <= pq->hi_prec; prec++)
		if (prec_bmp & (1 << prec))
			len += pq->q[prec].skblist.qlen;

	return len;
}

/* Priority dequeue from a specific set of precedences */
struct sk_buff *wland_pktq_mdeq(struct pktq *pq)
{
	struct sk_buff_head *q;
	struct sk_buff *p;
	int prec;

	if (pq->len == 0)
		return NULL;

	while ((prec = pq->hi_prec) > 0 &&
	       skb_queue_empty(&pq->q[prec].skblist))
		pq->hi_prec--;

	q = &pq->q[prec].skblist;
	p = __skb_dequeue(q);
	if (!p)
		return NULL;

	pq->len--;

	return p;
}

bool wland_prec_enq(struct device *dev, struct pktq *q, struct sk_buff *pkt,
		    int prec)
{
	struct sk_buff *p;
	int eprec = -1;		/* precedence to evict from */
	bool discard_oldest = false;

	if (!pktq_pfull(q, prec) && !pktq_full(q)) {
		wland_pktq_penq(q, prec, pkt);
		return true;
	}
	dev_err_ratelimited(dev, "packet queue overflow\n");

	if (pktq_pfull(q, prec)) {
		eprec = prec;
	} else if (pktq_full(q)) {
		p = wland_pktq_peek_tail(q, &eprec);
		if (eprec > prec)
			return false;
	}

	if (eprec >= 0) {
		if (eprec == prec && !discard_oldest)
			return false;

		p = discard_oldest ? wland_pktq_pdeq(q, eprec) :
				     wland_pktq_pdeq_tail(q, eprec);
		if (!p) {
			dev_err_ratelimited(dev,
					    "failed to evict packet (oldest %d)\n",
					    discard_oldest);
			return false;
		}

		wland_pkt_buf_free_skb(p);
	}

	p = wland_pktq_penq(q, prec, pkt);
	if (!p)
		dev_err_ratelimited(dev, "failed to enqueue packet\n");

	return !!p;
}

/* Beacon period of a beacon or probe response (frame body). */
u16 wland_get_beacon_period(u8 *data)
{
	return get_unaligned_le16(data);
}

/* Frame type and subtype bits of the frame control field. */
u8 wland_get_sub_type(u8 *header)
{
	return header[0] & 0xFC;
}

static u8 wland_get_to_ds(u8 *header)
{
	return header[1] & 0x01;
}

static u8 wland_get_from_ds(u8 *header)
{
	return (header[1] & 0x02) >> 1;
}

static void wland_get_address1(u8 *data, u8 *addr)
{
	memcpy(addr, data + 4, 6);
}

static void wland_get_address2(u8 *data, u8 *addr)
{
	memcpy(addr, data + 10, 6);
}

static void wland_get_address3(u8 *data, u8 *addr)
{
	memcpy(addr, data + 16, 6);
}

/* BSSID of a received frame, selected by the To DS / From DS bits. */
void wland_get_BSSID(u8 *data, u8 *bssid)
{
	if (wland_get_from_ds(data) == 1)
		wland_get_address2(data, bssid);
	else if (wland_get_to_ds(data) == 1)
		wland_get_address1(data, bssid);
	else
		wland_get_address3(data, bssid);
}

/* SSID of a beacon or probe response. */
void wland_get_ssid(u8 *data, u8 *ssid, u8 *p_ssid_len)
{
	u8 len, i, j;

	len = data[MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN +
		CAP_INFO_LEN + 1];
	j = MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN + CAP_INFO_LEN +
		2;

	/* A bogus SSID length is treated as an empty SSID. */
	if (len >= MAX_SSID_LEN)
		len = 0;

	for (i = 0; i < len; i++, j++)
		ssid[i] = data[j];

	ssid[len] = '\0';

	*p_ssid_len = len;
}

/* Capability info of a beacon, probe response or association frame. */
u16 wland_get_cap_info(u8 *data)
{
	u16 index = MAC_HDR_LEN;
	u8 st = wland_get_sub_type(data);

	/* The capability field sits at a different offset in beacons. */
	if (st == BEACON || st == PROBE_RSP)
		index += TIME_STAMP_LEN + BEACON_INTERVAL_LEN;

	return get_unaligned_le16(&data[index]);
}
