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
#ifndef _WLAND_USB_H_
#define _WLAND_USB_H_

#include "wland_dev.h"
#include <linux/usb.h>

#define WLAND_USB_CBCTL_WRITE		0
#define WLAND_USB_CBCTL_READ		1

#define WLAND_USB_NRXQ			10
#define WLAND_USB_NTXQ			10

#define CONFIGDESC(usb)			(&((usb)->actconfig)->desc)
#define IFPTR(usb, idx)			((usb)->actconfig->interface[(idx)])
#define IFALTS(usb, idx)		(IFPTR((usb), (idx))->altsetting[0])
#define IFDESC(usb, idx)		(IFALTS((usb), (idx)).desc)
#define IFEPDESC(usb, idx, ep) \
	((IFALTS((usb), (idx)).endpoint[(ep)]).desc)

#define CONTROL_IF			0
#define BULK_IF				0

#define USB_MAX_PKT_SIZE		2048

enum wland_usb_state {
	USB_STATE_DOWN,
	USB_STATE_UP,
};

struct wland_stats {
	u32 tx_ctlpkts;
	u32 tx_ctlerrs;
	u32 rx_ctlpkts;
	u32 rx_ctlerrs;
};

struct wland_usb_dev {
	struct wland_bus *bus;
	struct wland_usbdev_info *devinfo;
	enum wland_usb_state state;
	struct wland_stats stats;
	int ntxq, nrxq;
	u32 bus_mtu;
	int devid;
};

/* IO Request Block (IRB) */
struct wland_usbreq {
	struct list_head list;
	struct wland_usbdev_info *devinfo;
	struct urb *urb;
	struct sk_buff *skb;
};

struct wland_usbdev_info {
	struct wland_usb_dev bus_pub;	/* MUST BE FIRST */
	struct wland_rx_info *rx_info;

	spinlock_t rx_freeq_lock;
	spinlock_t rx_postq_lock;
	spinlock_t tx_freeq_lock;
	spinlock_t tx_postq_lock;
	spinlock_t q_lock; /* Transport state and RX submission/scheduling. */

	struct list_head rx_freeq;
	struct list_head rx_postq;
	struct list_head tx_freeq;
	struct list_head tx_postq;
	struct workqueue_struct *wland_txwq;
	struct work_struct tx_work;
	unsigned int rx_pipe, tx_pipe;

	int tx_low_watermark;
	int tx_high_watermark;
	int tx_freecount;
	int tx_postcount;
	int rx_postcount;
	spinlock_t tx_flowblock_lock;

	struct wland_usbreq *tx_reqs;
	struct wland_usbreq *rx_reqs;

	struct usb_device *usbdev;
	struct usb_interface *intf;
	unsigned long recovery_pending;
	bool disconnecting;
	bool rx_dead; /* Permanent transport failure; cleared only by reprobe. */
	struct device *dev;

	int ctl_urb_status;
	int ctl_completed;

	wait_queue_head_t ioctl_resp_wait;
	wait_queue_head_t data_resp_wait;

	unsigned long ctl_op;

	struct urb *bulk_urb;	/* WID commands and firmware download */

	struct work_struct rx_refill_work;
};

void wland_usb_exit(void);
int wland_usb_register(void);
void wland_usb_request_recovery(struct device *dev);
void wland_usb_data_resp_wake(struct wland_usbdev_info *devinfo);
void wland_tx_pkt_reinit(struct wland_rx_info *rx_info);

#endif /* _WLAND_USB_H_ */
