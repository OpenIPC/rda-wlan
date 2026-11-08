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

/* Get the next event from the queue, or NULL if it is empty. */
static struct wland_fweh_queue_item *
wland_fweh_dequeue_event(struct wland_fw_info *fweh)
{
	struct wland_fweh_queue_item *event = NULL;
	ulong flags;

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	if (!list_empty(&fweh->event_q)) {
		event = list_first_entry(&fweh->event_q,
			struct wland_fweh_queue_item, q);
		list_del(&event->q);
	}
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	return event;
}

static void wland_fweh_event_worker(struct work_struct *work)
{
	struct wland_fw_info *fweh =
		container_of(work, struct wland_fw_info, event_work);
	struct wland_private *drvr =
		container_of(fweh, struct wland_private, fweh);
	struct device *dev = drvr->bus_if->dev;
	struct wland_fweh_queue_item *event;
	struct wland_event_msg *emsg_be;
	struct wland_if *ifp = NULL;
	int err = 0;

	while ((event = wland_fweh_dequeue_event(fweh))) {
		emsg_be = &event->emsg;

		/* Special handling of interface events */
		if (emsg_be->ifidx >= WLAND_MAX_IFS ||
		    emsg_be->bsscfgidx >= WLAND_MAX_IFS) {
			dev_err(dev, "invalid interface index: %u\n",
				emsg_be->ifidx);
			goto event_free;
		}

		ifp = drvr->iflist[emsg_be->bsscfgidx];

		if (event->code == WLAND_E_IF_ADD) {
			ifp = wland_add_if(drvr, emsg_be->bsscfgidx,
				emsg_be->ifidx, emsg_be->ifname, emsg_be->addr);
			if (IS_ERR(ifp))
				goto event_free;
			wland_fws_add_interface(ifp);
		} else if (!ifp) {
			goto event_free;
		} else if (event->code == WLAND_E_IF_CHANGE) {
			wland_fws_macdesc_init(ifp->fws_desc, ifp->mac_addr,
				ifp->ifidx);
		} else if (event->code == WLAND_E_IF_DEL) {
			wland_fws_del_interface(ifp);
			wland_del_if(drvr, emsg_be->bsscfgidx);
			/* ifp is freed with its netdev; no handler may run. */
			goto event_free;
		}

		if (emsg_be->event_code < WLAND_E_LAST &&
		    fweh->evt_handler[emsg_be->event_code])
			err = fweh->evt_handler[emsg_be->event_code](
				ifp, emsg_be, event->data);
		else
			dev_err(dev, "unhandled event %u\n",
				emsg_be->event_code);

		if (err < 0) {
			dev_err(dev, "event %u handler failed: %d\n",
				event->code, err);
			err = 0;
		}
event_free:
		kfree(event);
	}
}

/* Queue an event for the worker; @data is copied (datalen bytes). */
void wland_fweh_push_event(struct wland_private *drvr,
	struct wland_event_msg *event_packet, void *data)
{
	struct wland_fw_info *fweh = &drvr->fweh;
	struct device *dev = drvr->bus_if->dev;
	struct wland_fweh_queue_item *event;
	ulong flags;

	if (event_packet->event_code >= WLAND_E_LAST) {
		dev_err(dev, "invalid event code %u\n",
			event_packet->event_code);
		return;
	}

	if (!fweh->evt_handler[event_packet->event_code]) {
		dev_err(dev, "unregistered event code %u\n",
			event_packet->event_code);
		return;
	}

	event = kzalloc(sizeof(*event) + event_packet->datalen, GFP_ATOMIC);
	if (!event)
		return;

	event->code = event_packet->event_code;
	event->ifidx = event_packet->ifidx;

	memcpy(&event->emsg, event_packet, sizeof(event->emsg));
	if (data)
		memcpy(event->data, data, event_packet->datalen);
	memcpy(event->ifaddr, event_packet->addr, ETH_ALEN);

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	list_add_tail(&event->q, &fweh->event_q);
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	schedule_work(&fweh->event_work);
}

int wland_fweh_register(struct wland_private *drvr,
	enum wland_fweh_event_code code, fw_handler_t handler)
{
	if (code >= WLAND_E_LAST)
		return -EINVAL;

	if (drvr->fweh.evt_handler[code]) {
		dev_err(drvr->bus_if->dev, "event code %u already registered\n",
			code);
		return -ENOSPC;
	}
	drvr->fweh.evt_handler[code] = handler;
	return 0;
}

void wland_fweh_unregister(struct wland_private *drvr,
	enum wland_fweh_event_code code)
{
	if (code < WLAND_E_LAST)
		drvr->fweh.evt_handler[code] = NULL;
}

void wland_fweh_attach(struct wland_private *drvr)
{
	struct wland_fw_info *fweh = &drvr->fweh;

	INIT_WORK(&fweh->event_work, wland_fweh_event_worker);
	spin_lock_init(&fweh->evt_q_lock);
	INIT_LIST_HEAD(&fweh->event_q);
}

/* Cancel the worker and drain queued events. */
void wland_fweh_detach(struct wland_private *drvr)
{
	struct wland_fw_info *fweh = &drvr->fweh;
	struct wland_fweh_queue_item *event;

	cancel_work_sync(&fweh->event_work);
	while ((event = wland_fweh_dequeue_event(fweh)))
		kfree(event);
	memset(fweh->evt_handler, 0, sizeof(fweh->evt_handler));
}
