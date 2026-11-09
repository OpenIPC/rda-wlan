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
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_p2p.h"
#include "wland_cfg80211.h"
#include "wland_rf.h"

void wland_txflowcontrol(struct device *dev, bool state)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr = bus_if->drvr;
	struct wland_fws_info *fws = drvr->fws;
	int i;

	if (state)
		fws->stats.bus_flow_block++;

	for (i = 0; i < WLAND_MAX_IFS; i++) {
		if (drvr->iflist[i]) {
			if (state)
				netif_stop_queue(drvr->iflist[i]->ndev);
			else
				netif_wake_queue(drvr->iflist[i]->ndev);
		}
	}
}

int wland_bus_start(struct device *dev)
{
	int ret = -EINVAL;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr;
	struct wland_if *ifp = NULL;
	struct wland_if *p2p_ifp = NULL;
	u8 mac_addr[ETH_ALEN];

	if (!bus_if) {
		dev_err(dev, "missing bus interface\n");
		return -EINVAL;
	}
	drvr = bus_if->drvr;

	/*
	 * Without a module or board MAC address, use a random address until
	 * firmware starts and the eFuse address becomes readable.
	 */
	bus_if->up_data_mac = 0;
	if (n_WifiMac == ETH_ALEN && is_valid_ether_addr(WifiMac)) {
		memcpy(mac_addr, WifiMac, ETH_ALEN);
	} else if (wland_get_mac_address(mac_addr) != ETH_ALEN) {
		eth_random_addr(mac_addr);
		bus_if->up_data_mac = 1;
	}

	if (!bus_if->up_data_mac)
		dev_info(dev, "board MAC address %pM\n", mac_addr);

	ifp = wland_add_if(drvr, 0, 0, "wlan%d", mac_addr);
	if (IS_ERR(ifp)) {
		dev_err(dev, "failed to add interface: %ld\n", PTR_ERR(ifp));
		return PTR_ERR(ifp);
	}
	if (bus_if->up_data_mac)
		ifp->ndev->addr_assign_type = NET_ADDR_RANDOM;

	if (drvr->p2p_enable) {
		p2p_ifp = wland_add_if(drvr, 1, 0, "p2p%d", NULL);
		if (IS_ERR(p2p_ifp))
			p2p_ifp = NULL;
	}

	ret = wland_fws_init(drvr);
	if (ret < 0)
		goto out;

	wland_fws_add_interface(ifp);

	drvr->config = wland_cfg80211_attach(drvr, bus_if->dev);
	if (!drvr->config) {
		dev_err(dev, "failed to attach cfg80211\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = wland_netdev_attach(ifp);
	if (ret < 0) {
		dev_err(dev, "failed to attach netdev: %d\n", ret);
		goto out;
	}

	if (p2p_ifp) {
		ret = wland_netdev_p2p_attach(p2p_ifp);
		if (ret < 0) {
			dev_err(dev, "failed to attach P2P netdev: %d\n", ret);
			drvr->p2p_enable = false;
			/* Unregistering frees the netdev and ifp with it */
			wland_fws_del_interface(ifp);
			unregister_netdev(ifp->ndev);
			drvr->iflist[0] = NULL;
			ifp = NULL;
			goto out;
		}
	}

out:
	if (ret < 0) {
		bus_if->state = WLAND_BUS_DOWN;
		if (drvr->config) {
			wland_cfg80211_detach(drvr->config);
			drvr->config = NULL;
		}

		if (drvr->fws) {
			if (ifp)
				wland_fws_del_interface(ifp);
			wland_fws_deinit(drvr);
		}

		if (ifp) {
			free_netdev(ifp->ndev);
			drvr->iflist[0] = NULL;
		}
		if (p2p_ifp) {
			free_netdev(p2p_ifp->ndev);
			drvr->iflist[1] = NULL;
		}
	}

	return ret;
}

void wland_txcomplete(struct device *dev, struct sk_buff *txp, bool success)
{
	struct wland_bus *bus_if;
	struct wland_private *drvr;
	struct wland_if *ifp;
	struct ethhdr *eh;
	s32 ifidx = 0;
	u16 type;
	int res;

	if (!txp)
		return;

	if (!dev) {
		pr_err_ratelimited("missing device on TX complete\n");
		goto done;
	}
	bus_if = dev_get_drvdata(dev);
	if (!bus_if || !bus_if->drvr) {
		dev_err_ratelimited(dev, "invalid bus interface\n");
		goto done;
	}
	drvr = bus_if->drvr;

	if (!txp->dev) {
		dev_err_ratelimited(dev, "invalid TX packet\n");
		goto done;
	}

	res = wland_proto_hdrpull(drvr, &ifidx, txp);

	ifp = netdev_priv(txp->dev);
	if (!ifp) {
		dev_err_ratelimited(dev, "missing interface\n");
		goto done;
	}

	if (res == 0 && txp->len >= sizeof(*eh)) {
		eh = (struct ethhdr *)txp->data;
		type = ntohs(eh->h_proto);

		if (type == ETH_P_PAE) {
			atomic_dec(&ifp->pend_8021x_cnt);
			dev_dbg(dev, "TX EAPOL complete: bssidx %d, pend %d\n",
				ifp->bssidx,
				atomic_read(&ifp->pend_8021x_cnt));
			wake_up(&ifp->pend_8021x_wait);
		}
	}

done:
	dev_kfree_skb_any(txp);
}

int wland_bus_active(struct wland_bus *bus_if)
{
	int ret;

	ret = wland_bus_init(bus_if);
	if (ret < 0)
		dev_err(bus_if->dev, "failed to initialize bus: %d\n", ret);
	return ret;
}

int wland_bus_attach(unsigned int bus_hdrlen, struct device *dev)
{
	static const u8 rates[ALL_RATE_NUM] = {
		1, 2, 5, 11,			/* 11b */
		6, 9, 12, 18, 24, 36, 48, 54,	/* 11g */
		0, 1, 2, 3, 4, 5, 6, 7		/* 11n */
	};
	int ret = 0;
	struct wland_bus *bus_if;
	struct wland_private *drvr;

	if (!dev) {
		pr_err("missing device\n");
		return -EINVAL;
	}
	bus_if = dev_get_drvdata(dev);

	drvr = kzalloc(sizeof(*drvr), GFP_KERNEL);
	if (!drvr)
		return -ENOMEM;

	mutex_init(&drvr->proto_block);
	mutex_init(&drvr->rf_result_block);
	drvr->current_mode = WLAND_N_MODE;
	drvr->hdrlen = bus_hdrlen;
	drvr->bus_if = bus_if;
	drvr->country_code = WLAND_DEFAULT_COUNTRY_CODE;
	drvr->power_11f = 0x45;
	drvr->power_120 = 0x35;
	memcpy(drvr->rates, rates, ALL_RATE_NUM);
	drvr->p2p_enable = true;

	bus_if->drvr = drvr;
	/* The shared failure path detaches event work even if proto fails. */
	wland_fweh_attach(drvr);

	ret = wland_proto_attach(drvr);
	if (ret < 0) {
		dev_err(dev, "failed to attach proto: %d\n", ret);
		wland_bus_detach(dev);
		return ret;
	}

	return 0;
}

void wland_bus_detach(struct device *dev)
{
	s32 i;
	struct wland_bus *bus_if;
	struct wland_private *drvr;

	if (!dev) {
		pr_err("missing device\n");
		return;
	}
	bus_if = dev_get_drvdata(dev);
	drvr = bus_if->drvr;

	if (!drvr) {
		dev_err(dev, "missing private data\n");
		return;
	}

	/* RX/TX callbacks reference interfaces and drvr; stop them first. */
	for (i = 0; i < WLAND_MAX_IFS; i++)
		if (drvr->iflist[i] && drvr->iflist[i]->ndev)
			netif_tx_disable(drvr->iflist[i]->ndev);
	wland_bus_stop(bus_if);

	wland_fweh_detach(drvr);

	/* The primary interface is removed last. */
	for (i = WLAND_MAX_IFS - 1; i > -1; i--) {
		if (drvr->iflist[i]) {
			wland_fws_del_interface(drvr->iflist[i]);
			wland_del_if(drvr, i);
		}
	}

	if (drvr->prot)
		wland_proto_detach(drvr);

	wland_fws_deinit(drvr);
	bus_if->drvr = NULL;
	kfree(drvr);
}
