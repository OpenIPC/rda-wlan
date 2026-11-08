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
#include <linux/firmware.h>
#include <linux/usb.h>
#include <linux/vmalloc.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_bus.h"
#include "wland_usb.h"
#include "wland_wid.h"
#include "wland_cfg80211.h"
#include "wland_p2p.h"
#include "wland_fweh.h"
#include "wland_rx.h"

static struct wland_usbreq *wland_usb_deq(struct wland_usbdev_info *devinfo,
					  struct list_head *q, int *counter,
					  spinlock_t *qlock)
{
	unsigned long flags;
	struct wland_usbreq *req;

	spin_lock_irqsave(qlock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(qlock, flags);
		return NULL;
	}
	req = list_entry(q->next, struct wland_usbreq, list);
	list_del_init(q->next);
	if (counter)
		(*counter)--;
	spin_unlock_irqrestore(qlock, flags);

	return req;
}

static void wland_usb_enq(struct wland_usbdev_info *devinfo,
			  struct list_head *q, struct wland_usbreq *req,
			  int *counter, spinlock_t *qlock)
{
	unsigned long flags;

	spin_lock_irqsave(qlock, flags);
	list_add_tail(&req->list, q);
	if (counter)
		(*counter)++;
	spin_unlock_irqrestore(qlock, flags);
}

static void wland_usb_finish_tx(struct device *dev, struct sk_buff *skb,
				bool success)
{
	if (!skb)
		return;
	if (skb->len >= WID_HEADER_LEN)
		skb_pull(skb, WID_HEADER_LEN);
	wland_txcomplete(dev, skb, success);
}

static void wland_usb_tx_flush(struct wland_usbdev_info *devinfo)
{
	struct wland_usbreq *req;

	while (!list_empty(&devinfo->tx_postq)) {
		req = wland_usb_deq(devinfo, &devinfo->tx_postq,
				    &devinfo->tx_postcount,
				    &devinfo->tx_postq_lock);
		/*
		 * Complete dropped frames through the TX path so that
		 * pend_8021x_cnt stays balanced for EAPOL frames.
		 */
		wland_usb_finish_tx(devinfo->dev, req->skb, false);
		req->skb = NULL;
		wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
			      &devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	}
}

void wland_tx_pkt_reinit(struct wland_rx_info *rx_info)
{
	wland_usb_tx_flush(rx_info->devinfo);
}

static void wland_usb_tx_dpc(struct wland_usbdev_info *devinfo)
{
	struct wland_usbreq *req;
	int ret = 0;
	struct device *dev = devinfo->dev;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_if *ifp;
	struct wland_cfg80211_info *cfg;

	if (!bus_if || !bus_if->drvr)
		return;
	ifp = bus_if->drvr->iflist[0];
	cfg = (ifp && ifp->drvr) ? ifp->drvr->config : NULL;

	/* Hold data frames back while a scan is running. */
	while (!list_empty(&devinfo->tx_postq) &&
	       !(cfg && test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))) {
		if (devinfo->bus_pub.state != USB_STATE_UP)
			return;

		if (atomic_read(&bus_if->software_reset)) {
			msleep(100);
			break;
		}

		req = wland_usb_deq(devinfo, &devinfo->tx_postq,
				    &devinfo->tx_postcount,
				    &devinfo->tx_postq_lock);
		if (!req)
			return;
		if (!req->skb) {
			wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
				      &devinfo->tx_freecount,
				      &devinfo->tx_freeq_lock);
			continue;
		}

		ret = usb_submit_urb(req->urb, GFP_ATOMIC);
		if (ret) {
			dev_err_ratelimited(dev,
					    "failed to submit TX URB: %d\n",
					    ret);
			goto fail;
		}
		continue;

fail:
		wland_usb_finish_tx(dev, req->skb, false);
		req->skb = NULL;
		wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
			      &devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	}
}

static void wland_usb_tx_worker(struct work_struct *work)
{
	struct wland_usbdev_info *devinfo =
		container_of(work, struct wland_usbdev_info, tx_work);

	if (devinfo->tx_postcount > 0)
		wland_usb_tx_dpc(devinfo);
}

static const struct usb_device_id wland_usb_devid_table[] = {
	{ USB_DEVICE(USB_VENDOR_ID_RDAMICRO, USB_DEVICE_ID_RDA599X) },
	{}
};

static struct wland_usbdev_info *wland_usb_get_businfo(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	return bus_if->bus_priv.usb->devinfo;
}

static int wland_usb_ctl_error(struct wland_usbdev_info *devinfo)
{
	if (READ_ONCE(devinfo->disconnecting) || READ_ONCE(devinfo->rx_dead))
		return -ENODEV;
	if (READ_ONCE(devinfo->bus_pub.state) != USB_STATE_UP)
		return -EIO;
	return 0;
}

static void wland_usb_mark_dead(struct wland_usbdev_info *devinfo,
				bool disconnecting)
{
	unsigned long flags;

	spin_lock_irqsave(&devinfo->q_lock, flags);
	if (disconnecting)
		WRITE_ONCE(devinfo->disconnecting, true);
	WRITE_ONCE(devinfo->rx_dead, true);
	WRITE_ONCE(devinfo->bus_pub.state, USB_STATE_DOWN);
	WRITE_ONCE(devinfo->bus_pub.bus->state, WLAND_BUS_DOWN);
	spin_unlock_irqrestore(&devinfo->q_lock, flags);
	wake_up_all(&devinfo->ioctl_resp_wait);
	wake_up_all(&devinfo->data_resp_wait);
}

static void wland_usb_rx_schedule(struct wland_usbdev_info *devinfo)
{
	unsigned long flags;

	spin_lock_irqsave(&devinfo->q_lock, flags);
	if (!wland_usb_ctl_error(devinfo))
		schedule_work(&devinfo->rx_refill_work);
	spin_unlock_irqrestore(&devinfo->q_lock, flags);
}

static int wland_usb_ioctl_resp_wait(struct wland_usbdev_info *devinfo)
{
	return wait_event_timeout(devinfo->ioctl_resp_wait,
		wland_usb_ctl_error(devinfo) || READ_ONCE(devinfo->ctl_completed),
		msecs_to_jiffies(IOCTL_RESP_TIMEOUT));
}

void wland_usb_request_recovery(struct device *dev)
{
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_bus *bus = dev_get_drvdata(dev);
	int i;

	if (READ_ONCE(devinfo->disconnecting) || READ_ONCE(devinfo->rx_dead) ||
	    test_and_set_bit(0, &devinfo->recovery_pending))
		return;
	atomic_set(&bus->software_reset, 1);
	if (bus->drvr) {
		for (i = 0; i < ARRAY_SIZE(bus->drvr->iflist); i++) {
			struct wland_if *ifp = bus->drvr->iflist[i];

			if (ifp && ifp->ndev) {
				netif_carrier_off(ifp->ndev);
				netif_stop_queue(ifp->ndev);
			}
		}
	}
	dev_warn(dev, "control transport failed; scheduling USB reset/rebind\n");
	/*
	 * Without pre/post_reset callbacks the USB core unbinds and probes
	 * afresh. Only a queued reset is safe under rtnl/proto_block.
	 */
	usb_queue_reset_device(devinfo->intf);
}

void wland_usb_data_resp_wake(struct wland_usbdev_info *devinfo)
{
	wake_up(&devinfo->data_resp_wait);
}

static void wland_usb_ioctl_resp_wake(struct wland_usbdev_info *devinfo)
{
	wake_up(&devinfo->ioctl_resp_wait);
}

static int wland_usb_data_resp_wait(struct wland_usbdev_info *devinfo)
{
	return wait_event_timeout(devinfo->data_resp_wait,
		wland_usb_ctl_error(devinfo) || READ_ONCE(devinfo->rx_info->rxlen),
		msecs_to_jiffies(IOCTL_RESP_TIMEOUT));
}

static void wland_usb_ctl_complete(struct wland_usbdev_info *devinfo, int type,
				   int status)
{
	if (unlikely(!devinfo))
		return;

	if (type == WLAND_USB_CBCTL_READ) {
		if (status == 0)
			devinfo->bus_pub.stats.rx_ctlpkts++;
		else
			devinfo->bus_pub.stats.rx_ctlerrs++;
	} else if (type == WLAND_USB_CBCTL_WRITE) {
		if (status == 0)
			devinfo->bus_pub.stats.tx_ctlpkts++;
		else
			devinfo->bus_pub.stats.tx_ctlerrs++;
	}

	devinfo->ctl_urb_status = status;
	devinfo->ctl_completed = true;

	wland_usb_ioctl_resp_wake(devinfo);
}

static void wland_usb_ctlwrite_complete(struct urb *urb)
{
	struct wland_usbdev_info *devinfo =
		(struct wland_usbdev_info *)urb->context;

	wland_usb_ctl_complete(devinfo, WLAND_USB_CBCTL_WRITE, urb->status);
}

static int wland_usb_send_ctl(struct wland_usbdev_info *devinfo, u8 *buf,
			      int len)
{
	struct wland_bus *bus_if;

	if (!devinfo || !buf || len == 0 || !devinfo->bulk_urb)
		return -EINVAL;

	bus_if = dev_get_drvdata(devinfo->dev);
	if (bus_if->chip_ready != 1 && len > 64) {
		u16 adjust_len = len;

		if (adjust_len % 512)
			len += 512 - adjust_len % 512;
		len += 4;
	}

	usb_fill_bulk_urb(devinfo->bulk_urb,
			  devinfo->usbdev,
			  devinfo->tx_pipe,
			  buf, len,
			  (usb_complete_t)wland_usb_ctlwrite_complete,
			  devinfo);
	devinfo->bulk_urb->transfer_flags |= URB_ZERO_PACKET;

	return usb_submit_urb(devinfo->bulk_urb, GFP_ATOMIC);
}

static int wland_usb_bus_txctl(struct device *dev, u8 *buf, u32 len)
{
	int err = 0, timeout = 0;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	err = wland_usb_ctl_error(devinfo);
	if (err)
		return err;

	if (atomic_read(&bus_if->software_reset)) {
		dev_dbg(dev, "software reset in progress\n");
		msleep(100);
		return -EIO;
	}

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		dev_dbg(dev, "control frame busy, cannot tx\n");
		return -EIO;
	}

	devinfo->ctl_completed = false;

	err = wland_usb_send_ctl(devinfo, buf, len);
	if (err) {
		dev_err(dev, "failed to send ctl (%d bytes): %d\n", len, err);
		goto out;
	}

	timeout = wland_usb_ioctl_resp_wait(devinfo);
	err = wland_usb_ctl_error(devinfo);
	if (err) {
		/* The URB still owns the protocol buffer until completion. */
		usb_kill_urb(devinfo->bulk_urb);
		goto out;
	}
	if (!timeout) {
		/*
		 * Keep ctl_op set through recovery scheduling to prevent another
		 * caller from reusing bulk_urb before the clear below.
		 */
		if (devinfo->bulk_urb)
			usb_kill_urb(devinfo->bulk_urb);
		dev_err(dev, "txctl wait timed out\n");
		err = -ETIMEDOUT;
	} else {
		err = devinfo->ctl_urb_status;
	}

out:
	/* The failed command is never replayed: it may have reached firmware.
	 * Clear a halted bulk endpoint so the next caller can recover/retry.
	 */
	if (err == -EPIPE) {
		int clear_ret = usb_clear_halt(devinfo->usbdev,
					       devinfo->tx_pipe);

		if (clear_ret) {
			dev_warn(devinfo->dev,
				 "cannot clear control TX halt: %d\n",
				 clear_ret);
			wland_usb_request_recovery(dev);
		}
	}
	if (err == -ETIMEDOUT || err == -EPROTO || err == -EILSEQ)
		wland_usb_request_recovery(dev);
	clear_bit(0, &devinfo->ctl_op);
	return err;
}

static int wland_usb_bus_rxctl(struct device *dev, u8 *buf, u32 len)
{
	int err = 0, timeout = 0;
	u32 rxlen = 0;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_rx_info *rx_info = devinfo->rx_info;

	err = wland_usb_ctl_error(devinfo);
	if (err)
		return err;

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		dev_dbg(dev, "control frame busy, cannot rx\n");
		return -EIO;
	}

	devinfo->ctl_completed = false;

	timeout = wland_usb_data_resp_wait(devinfo);
	err = wland_usb_ctl_error(devinfo);
	if (err) {
		clear_bit(0, &devinfo->ctl_op);
		return err;
	}

	if (timeout == 0) {
		dev_err(dev, "rxctl wait timed out\n");
		wland_usb_request_recovery(dev);
		clear_bit(0, &devinfo->ctl_op);
		return -ETIMEDOUT;
	}
	clear_bit(0, &devinfo->ctl_op);
	if (rx_info->rxlen > 0 &&
		   devinfo->bus_pub.state == USB_STATE_UP) {
		spin_lock_bh(&rx_info->rxctl_lock);
		rxlen = rx_info->rxlen;
		if (rxlen > len)
			err = -EMSGSIZE;
		else
			memcpy(buf, rx_info->rxctl, rxlen);
		rx_info->rxlen = 0;
		spin_unlock_bh(&rx_info->rxctl_lock);
	}
	if (err)
		return err;
	err = rxlen > 0 ? (int)rxlen : -ETIMEDOUT;
	return err;
}

static struct wland_usbreq *wland_usbdev_qinit(struct list_head *q, int qsize)
{
	int i;
	struct wland_usbreq *req, *reqs;

	reqs = kcalloc(qsize, sizeof(struct wland_usbreq), GFP_KERNEL);
	if (!reqs)
		return NULL;

	req = reqs;

	for (i = 0; i < qsize; i++) {
		req->urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!req->urb)
			goto fail;

		INIT_LIST_HEAD(&req->list);
		list_add_tail(&req->list, q);
		req++;
	}
	return reqs;
fail:
	while (!list_empty(q)) {
		req = list_entry(q->next, struct wland_usbreq, list);

		if (req && req->urb)
			usb_free_urb(req->urb);
		list_del(q->next);
	}
	kfree(reqs);
	return NULL;
}

static void wland_usb_free_q(struct list_head *q, bool pending,
			     spinlock_t *qlock)
{
	struct wland_usbreq *req;
	unsigned long flags;

	while (1) {
		spin_lock_irqsave(qlock, flags);
		if (list_empty(q)) {
			spin_unlock_irqrestore(qlock, flags);
			break;
		}
		req = list_first_entry(q, struct wland_usbreq, list);
		list_del_init(&req->list);
		spin_unlock_irqrestore(qlock, flags);

		if (!req->urb)
			continue;

		if (pending)
			usb_kill_urb(req->urb);
		else
			usb_free_urb(req->urb);
	}
}

static void wland_usb_tx_complete(struct urb *urb)
{
	unsigned long flags;
	struct wland_usbreq *req = (struct wland_usbreq *)urb->context;
	struct wland_usbdev_info *devinfo = req->devinfo;
	struct sk_buff *skb = req->skb;
	struct wland_private *drvr = devinfo->bus_pub.bus->drvr;
	struct wland_if *ifp = drvr ? drvr->iflist[0] : NULL;

	wland_usb_finish_tx(devinfo->dev, skb, urb->status == 0);
	req->skb = NULL;

	wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
		      &devinfo->tx_freecount, &devinfo->tx_freeq_lock);

	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (ifp &&
	    devinfo->tx_freecount > devinfo->tx_high_watermark &&
	    ifp->tx_flowblock) {
		wland_txflowcontrol(devinfo->dev, false);
		ifp->tx_flowblock = false;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);
}

static void wland_usb_rx_unpost(struct wland_usbdev_info *devinfo,
				struct wland_usbreq *req)
{
	unsigned long flags;

	spin_lock_irqsave(&devinfo->rx_postq_lock, flags);
	list_del_init(&req->list);
	devinfo->rx_postcount--;
	spin_unlock_irqrestore(&devinfo->rx_postq_lock, flags);
}

static void wland_usb_rx_complete(struct urb *urb)
{
	struct wland_usbreq *req = (struct wland_usbreq *)urb->context;
	struct wland_usbdev_info *devinfo = req->devinfo;
	struct wland_rx_info *rx_info = devinfo->rx_info;
	struct sk_buff *skb = NULL;
	bool refill = true;
	uint prec = 0;
	unsigned long flags = 0;

	wland_usb_rx_unpost(devinfo, req);

	skb = req->skb;
	req->skb = NULL;
	if (urb->status == -ENODEV || urb->status == -ESHUTDOWN)
		wland_usb_mark_dead(devinfo, false);
	if (wland_usb_ctl_error(devinfo))
		goto free_buffer;

	if (urb->actual_length > urb->transfer_buffer_length) {
		dev_warn_ratelimited(devinfo->dev,
				     "RX URB actual_length %u > transfer_buffer_length %u\n",
				     urb->actual_length,
				     urb->transfer_buffer_length);
		goto free_buffer;
	}

	/* Unlinked URBs belong to shutdown, not a new refill attempt. */
	if (urb->status != 0 || !urb->actual_length) {
		if (urb->status != 0)
			dev_dbg_ratelimited(devinfo->dev,
					    "RX URB status: %d\n",
					    urb->status);
		if (urb->status == -ENOENT || urb->status == -ECONNRESET)
			refill = false;
		goto free_buffer;
	}

	if (devinfo->bus_pub.state == USB_STATE_UP) {
		skb_put(skb, urb->actual_length);

		wland_dhd_os_sdlock_rxq(rx_info, &flags);
		if (!wland_prec_enq(devinfo->dev, &rx_info->rxq, skb, prec)) {
			wland_dhd_os_sdunlock_rxq(rx_info, &flags);
			goto free_buffer;
		}
		wland_dhd_os_sdunlock_rxq(rx_info, &flags);
		atomic_inc(&rx_info->rx_dpc_tskcnt);
		WAKE_RX_WORK(rx_info);

		goto recycle;
	}
free_buffer:
	wland_pkt_buf_free_skb(skb);
recycle:
	wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			      &devinfo->rx_freeq_lock);
	if (refill)
		wland_usb_rx_schedule(devinfo);
}

static int wland_usb_rx_refill(struct wland_usbdev_info *devinfo,
			       struct wland_usbreq *req)
{
	struct sk_buff *skb;
	unsigned long flags;
	int ret;

	if (!req || !devinfo)
		return -EINVAL;

	ret = wland_usb_ctl_error(devinfo);
	if (ret)
		goto recycle;

	skb = __dev_alloc_skb(devinfo->bus_pub.bus_mtu, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto recycle;
	}

	req->skb = skb;

	usb_fill_bulk_urb(req->urb, devinfo->usbdev, devinfo->rx_pipe,
			  skb->data, skb_tailroom(skb), wland_usb_rx_complete,
			  req);

	req->devinfo = devinfo;

	/* Serialize the final state check/submission with disconnect and stop. */
	spin_lock_irqsave(&devinfo->q_lock, flags);
	ret = wland_usb_ctl_error(devinfo);
	if (ret) {
		spin_unlock_irqrestore(&devinfo->q_lock, flags);
		goto free_buffer;
	}
	wland_usb_enq(devinfo, &devinfo->rx_postq, req, &devinfo->rx_postcount,
		      &devinfo->rx_postq_lock);

	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	spin_unlock_irqrestore(&devinfo->q_lock, flags);
	if (ret) {
		if (ret == -ENODEV || ret == -ESHUTDOWN)
			wland_usb_mark_dead(devinfo, false);
		dev_err_ratelimited(devinfo->dev,
				    "failed to submit RX URB: %d\n", ret);
		wland_usb_rx_unpost(devinfo, req);
		goto free_buffer;
	}
	return 0;
free_buffer:
	wland_pkt_buf_free_skb(req->skb);
	req->skb = NULL;
recycle:
	wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			      &devinfo->rx_freeq_lock);
	return ret;
}

static int wland_usb_rx_fill_all(struct wland_usbdev_info *devinfo)
{
	struct wland_usbreq *req;
	unsigned int budget = devinfo->bus_pub.nrxq;
	int ret;

	/* Completions may replenish freeq while this worker is running. */
	while (budget--) {
		ret = wland_usb_ctl_error(devinfo);
		if (ret)
			return ret;
		req = wland_usb_deq(devinfo, &devinfo->rx_freeq, NULL,
				    &devinfo->rx_freeq_lock);
		if (!req)
			break;
		ret = wland_usb_rx_refill(devinfo, req);
		/* Failed requests rejoin freeq; defer retries to the next pass. */
		if (ret)
			return ret;
	}
	return wland_usb_ctl_error(devinfo);
}

static int wland_usb_state_change(struct wland_usbdev_info *devinfo, int state)
{
	struct wland_bus *bcmf_bus = devinfo->bus_pub.bus;
	unsigned long flags;

	spin_lock_irqsave(&devinfo->q_lock, flags);
	if (state == USB_STATE_UP &&
	    (devinfo->disconnecting || devinfo->rx_dead)) {
		spin_unlock_irqrestore(&devinfo->q_lock, flags);
		return -ENODEV;
	}

	WRITE_ONCE(devinfo->bus_pub.state, state);

	/*
	 * update state of upper layer
	 */
	if (state == USB_STATE_DOWN)
		WRITE_ONCE(bcmf_bus->state, WLAND_BUS_DOWN);
	else if (state == USB_STATE_UP)
		WRITE_ONCE(bcmf_bus->state, WLAND_BUS_DATA);
	spin_unlock_irqrestore(&devinfo->q_lock, flags);
	if (state != USB_STATE_UP) {
		wake_up_all(&devinfo->ioctl_resp_wait);
		wake_up_all(&devinfo->data_resp_wait);
	}
	return 0;
}

static int wland_usb_bus_txdata(struct device *dev, struct sk_buff *skb)
{
	u8 *buf;
	u16 buf_len = 0;
	struct wland_usbreq *req;
	int ret = 0;
	unsigned long flags;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_private *drvr = devinfo->bus_pub.bus->drvr;
	struct wland_if *ifp = drvr->iflist[0];

	if (devinfo->bus_pub.state != USB_STATE_UP) {
		wland_usb_finish_tx(dev, skb, false);
		return -EIO;
	}

	req = wland_usb_deq(devinfo, &devinfo->tx_freeq,
			    &devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	if (!req) {
		wland_usb_finish_tx(dev, skb, false);
		ret = -ENOMEM;
		goto flow_ctrl;
	}

	buf = skb->data;
	buf_len = skb->len & CDC_DCMD_LEN_MASK;

	if (buf_len <= 1536) {
		u16 adjust_len = buf_len % 512;
		u16 target_len = buf_len;

		if (adjust_len != 0) {
			if (adjust_len > 64)
				target_len += 512 - adjust_len + 4;
		} else {
			target_len += 4;
		}

		if (skb_tailroom(skb) >= (target_len - buf_len)) {
			memset(skb_tail_pointer(skb), 0, target_len - buf_len);
			buf_len = target_len;
		}
	}

	req->skb = skb;
	req->devinfo = devinfo;

	usb_fill_bulk_urb(req->urb, devinfo->usbdev, devinfo->tx_pipe,
			  buf, buf_len, wland_usb_tx_complete, req);
	req->urb->transfer_flags |= URB_ZERO_PACKET;

	wland_usb_enq(devinfo, &devinfo->tx_postq, req,
		      &devinfo->tx_postcount, &devinfo->tx_postq_lock);
	queue_work(devinfo->wland_txwq, &devinfo->tx_work);
	ret = 0;

flow_ctrl:
	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (devinfo->tx_freecount < devinfo->tx_low_watermark &&
	    !ifp->tx_flowblock) {
		wland_txflowcontrol(dev, true);
		ifp->tx_flowblock = true;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);

	return ret;
}

static void wland_usb_bus_down(struct device *dev);

static int wland_usb_bus_up(struct device *dev)
{
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	int ret;

	if (READ_ONCE(devinfo->bus_pub.state) == USB_STATE_UP)
		return wland_usb_ctl_error(devinfo);

	ret = wland_usb_state_change(devinfo, USB_STATE_UP);
	if (ret)
		return ret;

	ret = wland_usb_rx_fill_all(devinfo);
	if (ret)
		goto fail;

	wland_tx_pkt_reinit(devinfo->rx_info);
	return 0;
fail:
	wland_usb_bus_down(dev);
	return ret;
}

static void wland_usb_bus_down(struct device *dev)
{
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	int i;

	if (!devinfo)
		return;

	wland_usb_state_change(devinfo, USB_STATE_DOWN);
	/* Stop submitters before killing URBs; TX in-flight requests are no
	 * longer on tx_postq, so drain the allocated request arrays as well.
	 */
	cancel_work_sync(&devinfo->tx_work);
	cancel_work_sync(&devinfo->rx_refill_work);

	if (devinfo->bulk_urb)
		usb_kill_urb(devinfo->bulk_urb);

	if (devinfo->tx_reqs)
		for (i = 0; i < devinfo->bus_pub.ntxq; i++)
			usb_kill_urb(devinfo->tx_reqs[i].urb);
	if (devinfo->rx_reqs)
		for (i = 0; i < devinfo->bus_pub.nrxq; i++)
			usb_kill_urb(devinfo->rx_reqs[i].urb);
	/* Completion callbacks may have scheduled one last refill. */
	cancel_work_sync(&devinfo->rx_refill_work);
	if (devinfo->rx_info)
		wland_rx_quiesce(devinfo->rx_info);

	/* Unsent frames must be completed and their requests recycled; a plain
	 * list drain would leak both the request slot and the EAPOL accounting.
	 */
	wland_usb_tx_flush(devinfo);
	wland_usb_free_q(&devinfo->tx_postq, true, &devinfo->tx_postq_lock);
	wland_usb_free_q(&devinfo->rx_postq, true, &devinfo->rx_postq_lock);
}

static void wland_usb_detach(struct wland_usbdev_info *devinfo)
{
	int i;

	cancel_work_sync(&devinfo->tx_work);
	if (devinfo->wland_txwq)
		destroy_workqueue(devinfo->wland_txwq);

	cancel_work_sync(&devinfo->rx_refill_work);
	/* bus_down has drained all submitted URBs. Also free unsent TX
	 * requests, which can remain on tx_postq when shutdown stops tx_work.
	 */
	if (devinfo->rx_reqs)
		for (i = 0; i < devinfo->bus_pub.nrxq; i++) {
			usb_free_urb(devinfo->rx_reqs[i].urb);
			dev_kfree_skb_any(devinfo->rx_reqs[i].skb);
		}
	if (devinfo->tx_reqs)
		for (i = 0; i < devinfo->bus_pub.ntxq; i++) {
			usb_free_urb(devinfo->tx_reqs[i].urb);
			dev_kfree_skb_any(devinfo->tx_reqs[i].skb);
		}
	usb_free_urb(devinfo->bulk_urb);

	kfree(devinfo->tx_reqs);
	kfree(devinfo->rx_reqs);
}

static void wland_rx_refill_worker(struct work_struct *work)
{
	struct wland_usbdev_info *devinfo =
		container_of(work, struct wland_usbdev_info, rx_refill_work);

	wland_usb_rx_fill_all(devinfo);
}

static struct wland_usb_dev *wland_usb_attach(struct wland_usbdev_info *devinfo,
					      int nrxq, int ntxq)
{
	devinfo->bus_pub.nrxq = nrxq;
	devinfo->bus_pub.devinfo = devinfo;
	devinfo->bus_pub.ntxq = ntxq;
	devinfo->bus_pub.state = USB_STATE_DOWN;

	/* Flow control when too many tx urbs are posted. */
	devinfo->tx_low_watermark = ntxq / 4;
	devinfo->tx_high_watermark = devinfo->tx_low_watermark * 3;
	devinfo->bus_pub.bus_mtu = USB_MAX_PKT_SIZE;

	init_waitqueue_head(&devinfo->ioctl_resp_wait);
	init_waitqueue_head(&devinfo->data_resp_wait);

	spin_lock_init(&devinfo->tx_freeq_lock);
	spin_lock_init(&devinfo->tx_postq_lock);
	spin_lock_init(&devinfo->q_lock);
	spin_lock_init(&devinfo->rx_freeq_lock);
	spin_lock_init(&devinfo->rx_postq_lock);

	spin_lock_init(&devinfo->tx_flowblock_lock);

	INIT_LIST_HEAD(&devinfo->rx_freeq);
	INIT_LIST_HEAD(&devinfo->rx_postq);

	INIT_LIST_HEAD(&devinfo->tx_freeq);
	INIT_LIST_HEAD(&devinfo->tx_postq);

	/* Every allocation failure below enters detach. */
	INIT_WORK(&devinfo->rx_refill_work, wland_rx_refill_worker);
	INIT_WORK(&devinfo->tx_work, wland_usb_tx_worker);

	devinfo->rx_reqs = wland_usbdev_qinit(&devinfo->rx_freeq, nrxq);
	if (!devinfo->rx_reqs)
		goto error;

	devinfo->tx_reqs = wland_usbdev_qinit(&devinfo->tx_freeq, ntxq);
	if (!devinfo->tx_reqs)
		goto error;

	devinfo->tx_freecount = ntxq;
	devinfo->tx_postcount = 0;
	devinfo->rx_postcount = 0;

	devinfo->bulk_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!devinfo->bulk_urb)
		goto error;

	return &devinfo->bus_pub;

error:
	wland_usb_detach(devinfo);
	return NULL;
}

static const struct wland_bus_ops wland_usb_bus_ops = {
	.txdata = wland_usb_bus_txdata,
	.init = wland_usb_bus_up,
	.stop = wland_usb_bus_down,
	.txctl = wland_usb_bus_txctl,
	.rxctl = wland_usb_bus_rxctl,
};

static int wland_usb_probe(struct usb_interface *intf,
			   const struct usb_device_id *id)
{
	int ep, ret = 0, num_of_eps;
	u8 endpoint_num;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_device *usb = interface_to_usbdev(intf);
	struct wland_usbdev_info *devinfo;
	struct wland_bus *bus;
	struct wland_usb_dev *bus_pub = NULL;
	struct device *dev = NULL;
	struct wland_rx_info *rx_info = NULL;

	devinfo = kzalloc(sizeof(*devinfo), GFP_KERNEL);
	if (!devinfo)
		return -ENOMEM;

	devinfo->usbdev = usb;
	devinfo->intf = intf;
	devinfo->dev = &usb->dev;

	usb_set_intfdata(intf, devinfo);

	/* Only a single-configuration vendor-class device is supported. */
	if (usb->descriptor.bNumConfigurations != 1) {
		ret = -ENODEV;
		goto fail;
	}

	if (usb->descriptor.bDeviceClass != 0x00) {
		ret = -ENODEV;
		goto fail;
	}

	/*
	 * Expected layout: one vendor-specific interface with ep0 control,
	 * a bulk IN and a bulk OUT endpoint (in either order).
	 */
	if (CONFIGDESC(usb)->bNumInterfaces != 1) {
		ret = -ENODEV;
		goto fail;
	}

	if (IFDESC(usb, CONTROL_IF).bInterfaceClass != USB_CLASS_VENDOR_SPEC ||
	    IFDESC(usb, CONTROL_IF).bInterfaceSubClass != 0xff ||
	    IFDESC(usb, CONTROL_IF).bInterfaceProtocol != 0xff) {
		dev_err(&usb->dev,
			"invalid control interface: class %d, subclass %d, proto %d\n",
			IFDESC(usb, CONTROL_IF).bInterfaceClass,
			IFDESC(usb, CONTROL_IF).bInterfaceSubClass,
			IFDESC(usb, CONTROL_IF).bInterfaceProtocol);
		ret = -ENODEV;
		goto fail;
	}

	devinfo->rx_pipe = 0;
	devinfo->tx_pipe = 0;
	num_of_eps = IFDESC(usb, BULK_IF).bNumEndpoints - 1;

	for (ep = 0; ep <= num_of_eps; ep++) {
		endpoint = &IFEPDESC(usb, BULK_IF, ep);

		if ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) !=
			USB_ENDPOINT_XFER_BULK) {
			dev_err(&usb->dev, "invalid data endpoint %d\n", ep);
			ret = -ENODEV;
			goto fail;
		}

		endpoint_num =
			endpoint->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;

		if ((endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
			USB_DIR_IN) {
			if (!devinfo->rx_pipe)
				devinfo->rx_pipe =
					usb_rcvbulkpipe(usb, endpoint_num);
		} else {
			if (!devinfo->tx_pipe)
				devinfo->tx_pipe =
					usb_sndbulkpipe(usb, endpoint_num);
		}
	}

	if (usb->speed == USB_SPEED_HIGH)
		dev_info(&usb->dev,
			 "Rdamicro high speed USB wireless device detected\n");
	else
		dev_info(&usb->dev,
			 "Rdamicro full speed USB wireless device detected\n");

	dev = devinfo->dev;

	if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0)
		bus_pub = wland_usb_attach(devinfo, 50, 50);
	else
		bus_pub = wland_usb_attach(devinfo, WLAND_USB_NRXQ,
					   WLAND_USB_NTXQ);
	if (!bus_pub) {
		dev_err(&usb->dev, "failed to attach USB device\n");
		ret = -ENOMEM;
		goto fail;
	}

	bus = kzalloc(sizeof(*bus), GFP_KERNEL);
	if (!bus) {
		ret = -ENOMEM;
		goto fail2;
	}

	bus->dev = dev;
	bus_pub->bus = bus;
	bus->bus_priv.usb = bus_pub;
	atomic_set(&bus->software_reset, 0);

	dev_set_drvdata(dev, bus);

	bus->ops = &wland_usb_bus_ops;

	bus->chip_ready = 0;
	bus->up_data_mac = 0;
	bus->chip = WLAND_VER_91_H;

	bus_pub->devid = bus->chip;

	rx_info = wland_rx_init(devinfo);
	if (!rx_info) {
		dev_err(&usb->dev, "failed to initialize RX\n");
		ret = -ENOMEM;
		goto fail1;
	}

	devinfo->rx_info = rx_info;

	ret = wland_bus_attach(0, dev);
	if (ret < 0) {
		dev_err(&usb->dev, "failed to attach bus\n");
		goto fail1;
	}

	if (bus->drvr->maxctl) {
		rx_info->rxblen = roundup(bus->drvr->maxctl, ALIGNMENT) +
				  WLAND_RXCTL_ALIGN;
		rx_info->rxbuf = kzalloc(rx_info->rxblen, GFP_KERNEL);
		if (!rx_info->rxbuf) {
			ret = -ENOMEM;
			goto fail1;
		}
	}

	devinfo->wland_txwq = create_singlethread_workqueue("wland_txwq");
	if (!devinfo->wland_txwq) {
		dev_err(&usb->dev, "failed to create TX workqueue\n");
		ret = -ENOMEM;
		goto fail1;
	}

	ret = wland_bus_start(dev);
	if (ret < 0) {
		dev_err(&usb->dev, "chip is not responding\n");
		goto fail1;
	}
	return 0;
fail1:
	/* Stop transport/work before the common layer frees interfaces. */
	if (!bus->drvr)
		wland_usb_bus_down(dev);
	wland_bus_detach(dev);
	if (devinfo->rx_info) {
		wland_rx_uinit(devinfo->rx_info);
		devinfo->rx_info = NULL;
	}
	dev_set_drvdata(dev, NULL);
	kfree(bus);
fail2:
	wland_usb_detach(devinfo);
fail:
	dev_err(&usb->dev, "probe failed: %d\n", ret);
	kfree(devinfo);
	usb_set_intfdata(intf, NULL);
	return ret;
}

static void wland_usb_disconnect(struct usb_interface *intf)
{
	struct wland_usbdev_info *devinfo = usb_get_intfdata(intf);

	if (!devinfo)
		return;

	/* Wake control callers before teardown waits for ndo_open/RTNL or
	 * interface work. Those callers keep the protocol and RX storage alive
	 * until unregister/cancel_work_sync has drained them.
	 */
	wland_usb_mark_dead(devinfo, true);
	usb_set_intfdata(intf, NULL);
	wland_bus_detach(devinfo->dev);
	if (devinfo->rx_info)
		wland_rx_uinit(devinfo->rx_info);
	devinfo->rx_info = NULL;
	dev_set_drvdata(devinfo->dev, NULL);
	kfree(devinfo->bus_pub.bus);
	wland_usb_detach(devinfo);
	kfree(devinfo);
}

MODULE_DEVICE_TABLE(usb, wland_usb_devid_table);

static struct usb_driver wland_usbdrvr = {
	.name = KBUILD_MODNAME,
	.probe = wland_usb_probe,
	.disconnect = wland_usb_disconnect,
	.id_table = wland_usb_devid_table,
	/*
	 * Firmware suspend/resume is unsupported. Disable runtime PM and let
	 * USB core unbind/reprobe the interface across system sleep.
	 */
	.supports_autosuspend = 0,
	.disable_hub_initiated_lpm = 1,
};

void wland_usb_exit(void)
{
	usb_deregister(&wland_usbdrvr);
}

int wland_usb_register(void)
{
	return usb_register(&wland_usbdrvr);
}

