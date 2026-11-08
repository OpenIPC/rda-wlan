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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ppp_defs.h>
#include <linux/usb.h>
#include <asm/unaligned.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_p2p.h"
#include "wland_rx.h"
#include "wland_cfg80211.h"
#include "wland_rf.h"
#include "wland_usb.h"

#define MAX_WAIT_FOR_8021X_TX		50	/* msecs */

char *wland_ifname(struct wland_private *drvr, int ifidx)
{
	if (ifidx < 0 || ifidx >= WLAND_MAX_IFS) {
		dev_err(drvr->bus_if->dev, "interface index %d out of range\n", ifidx);
		return "<if_bad>";
	}

	if (!drvr->iflist[ifidx]) {
		dev_err(drvr->bus_if->dev, "missing interface for index %d\n", ifidx);
		return "<if_null>";
	}

	return ((drvr->iflist[ifidx]->ndev) ?
		drvr->iflist[ifidx]->ndev->name : "<if_none>");
}

static void _wland_set_multicast_list(struct work_struct *work)
{
	struct wland_if *ifp =
		container_of(work, struct wland_if, multicast_work);
	struct net_device *ndev = ifp->ndev;

	struct netdev_hw_addr *ha;
	u32 cmd_value, cnt, buflen;
	__le32 cnt_le;
	char *buf, *bufp;
	s32 err;

	cmd_value = (ndev->flags & IFF_ALLMULTI) ? true : false;

	netif_addr_lock_bh(ndev);
	cnt = netdev_mc_count(ndev);
	netif_addr_unlock_bh(ndev);

	buflen = sizeof(cnt) + (cnt * ETH_ALEN);
	buf = kmalloc(buflen, GFP_KERNEL);

	if (!buf)
		return;

	bufp = buf;
	cnt_le = cpu_to_le32(cnt);
	memcpy(bufp, &cnt_le, sizeof(cnt_le));
	bufp += sizeof(cnt_le);

	netif_addr_lock_bh(ndev);
	netdev_for_each_mc_addr(ha, ndev) {
		if (!cnt)
			break;
		memcpy(bufp, ha->addr, ETH_ALEN);
		bufp += ETH_ALEN;
		cnt--;
	}
	netif_addr_unlock_bh(ndev);

	err = wland_fil_iovar_data_set(ifp, "mcast_list", buf, buflen);
	if (err < 0) {
		netdev_err(ndev, "failed to set multicast list: %d\n", err);
		cmd_value = cnt ? true : cmd_value;
	}

	kfree(buf);

	/* Allmulti is also enabled if the firmware rejected the list */
	err = wland_fil_iovar_data_set(ifp, "allmulti", &cmd_value,
				       sizeof(cmd_value));
	if (err < 0)
		netdev_err(ndev, "failed to set allmulti: %d\n", err);

	cmd_value = (ndev->flags & IFF_PROMISC) ? true : false;
	err = wland_fil_iovar_data_set(ifp, "promisc", &cmd_value,
				       sizeof(cmd_value));
	if (err < 0)
		netdev_err(ndev, "failed to set promisc: %d\n", err);
}

static void _wland_set_mac_address(struct work_struct *work)
{
	s32 err;
	struct wland_if *ifp =
		container_of(work, struct wland_if, setmacaddr_work);

	err = wland_fil_iovar_data_set(ifp, "cur_etheraddr", ifp->mac_addr,
				       ETH_ALEN);
	if (err < 0) {
		netdev_err(ifp->ndev,
			   "failed to set MAC address: %d\n", err);
	} else {
		netdev_dbg(ifp->ndev, "MAC address updated to %pM\n",
			   ifp->mac_addr);
		memcpy(ifp->ndev->dev_addr, ifp->mac_addr, ETH_ALEN);
	}
}

static int wland_netdev_set_mac_address(struct net_device *ndev, void *addr)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct sockaddr *sa = (struct sockaddr *)addr;

	memcpy(ifp->mac_addr, sa->sa_data, ETH_ALEN);

	schedule_work(&ifp->setmacaddr_work);
	return 0;
}

static void wland_netdev_set_multicast_list(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	schedule_work(&ifp->multicast_work);
}

static int wland_check_arp(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;
	struct ethhdr arp_rsp_eth, *arp_eth;
	struct arphdr *arph, *rsp_arph;
	unsigned char *sha, *sip, *tip;
	unsigned char *rsp_ptr;
	struct sk_buff *skb = NULL;
	size_t arp_len = sizeof(struct arphdr) + 2 * ETH_ALEN + 8;

	if (pktbuf->protocol == htons(ETH_P_ARP)) {
		if (pktbuf->len < ETH_HLEN + arp_len)
			return -1;

		arp_eth = (struct ethhdr *)(pktbuf->data);
		arph = (struct arphdr *)(pktbuf->data + ETH_HLEN);
		sha = (unsigned char *)(arph + 1);
		sip = sha + ETH_ALEN;
		tip = sip + 4 + ETH_ALEN;

		if (ifp->vif->mode == WL_MODE_BSS &&
		    arph->ar_op == htons(ARPOP_REQUEST) &&
		    memcmp(tip, profile->dhcp_server_ip, 4) == 0) {
			skb = dev_alloc_skb(ETH_HLEN + arp_len +
					    NET_IP_ALIGN + 3);
			if (!skb)
				return -1;

			skb->dev = ifp->ndev;
			skb_reserve(skb, NET_IP_ALIGN);

			memcpy(arp_rsp_eth.h_dest, arp_eth->h_source, ETH_ALEN);
			memcpy(arp_rsp_eth.h_source, arp_eth->h_dest, ETH_ALEN);
			arp_rsp_eth.h_proto = arp_eth->h_proto;

			memcpy(skb->data, &arp_rsp_eth, ETH_HLEN);

			rsp_arph = (struct arphdr *)(skb->data + ETH_HLEN);
			rsp_arph->ar_hrd = arph->ar_hrd;
			rsp_arph->ar_pro = arph->ar_pro;
			rsp_arph->ar_hln = ETH_ALEN;
			rsp_arph->ar_pln = 4;
			rsp_arph->ar_op = htons(ARPOP_REPLY);

			rsp_ptr = (unsigned char *)(rsp_arph + 1);
			memcpy(rsp_ptr, profile->dhcp_server_bssid, ETH_ALEN);
			rsp_ptr += ETH_ALEN;
			memcpy(rsp_ptr, profile->dhcp_server_ip, 4);
			rsp_ptr += 4;
			memcpy(rsp_ptr, sha, ETH_ALEN);
			rsp_ptr += ETH_ALEN;
			memcpy(rsp_ptr, sip, 4);

			skb_put(skb, ETH_HLEN + arp_len);

			wland_process_8023_pkt(ifp->drvr->bus_if, skb);

			dev_kfree_skb(pktbuf);
			return 0;
		}
	}
	return -1;
}

static void wland_check_tid(struct wland_if *ifp, struct sk_buff *skb)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct iphdr ipbuf, *iph;
	struct udphdr udpbuf, *udph;
	unsigned int offset = ETH_HLEN;
	u8 pppbuf[2], *ppp, tid;

	if (ifp->drvr->bus_if->chip_version < 4 && ifp->bssidx == 1)
		return;
	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
		return;
	if (skb->protocol == htons(ETH_P_PPP_SES)) {
		ppp = skb_header_pointer(skb, ETH_HLEN + 6, 2, pppbuf);
		if (!ppp || ppp[0] != 0 || ppp[1] != PPP_IP)
			return;
		offset += 8;
	} else if (skb->protocol != htons(ETH_P_IP)) {
		return;
	}
	iph = skb_header_pointer(skb, offset, sizeof(ipbuf), &ipbuf);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return;
	if (iph->protocol == IPPROTO_UDP) {
		udph = skb_header_pointer(skb, offset + iph->ihl * 4,
					  sizeof(udpbuf), &udpbuf);
		if (!udph)
			return;
		if ((udph->source == htons(SERVER_PORT) &&
		     udph->dest == htons(CLIENT_PORT)) ||
		    (udph->source == htons(CLIENT_PORT) &&
		     udph->dest == htons(SERVER_PORT)))
			return;
	}
	tid = iph->tos >> 5;
	if (ifp->vif->mode == WL_MODE_BSS) {
		wland_queue_addba(ifp, tid, ifp->vif->profile.bssid);
	} else if (ifp->vif->mode == WL_MODE_AP &&
		   !is_multicast_ether_addr(skb->data)) {
		if (ifp->bssidx == 0)
			tid = WLAND_TID_NUM;
		wland_queue_addba(ifp, tid, skb->data);
	}
}

int wland_sendpkt(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	struct wland_private *drvr = ifp->drvr;
	struct ethhdr *eh = (struct ethhdr *)pktbuf->data;
	bool multicast = is_multicast_ether_addr(eh->h_dest);
	bool pae = eh->h_proto == htons(ETH_P_PAE);
	u8 *frame;
	int len, ifidx;

	drvr->tx_multicast += !!multicast;
	if (pae)
		atomic_inc(&ifp->pend_8021x_cnt);

	/* The 2-byte WID header carries the length and the packet type. */
	skb_push(pktbuf, WID_HEADER_LEN);
	frame = (u8 *)pktbuf->data;

	len = pktbuf->len;

	if (pktbuf->len > CDC_DCMD_LEN_MASK) {
		if (net_ratelimit())
			netdev_err(ifp->ndev,
				   "TX packet length overflow: %u\n",
				   pktbuf->len);
		skb_pull(pktbuf, WID_HEADER_LEN);
		dev_kfree_skb(pktbuf);
		return -EINVAL;
	}

	ifidx = ifp->bssidx;

	if (ifidx == 0)
		len |= (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT);
	else
		len |= (PKT_TYPE_DATA_MAC1 << CDC_DCMD_LEN_SHIFT);

	put_unaligned_le16(len, frame);

	return wland_bus_txdata(drvr->bus_if, pktbuf);
}

int wland_netdev_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int ret = NETDEV_TX_OK;
	unsigned int packet_len = skb->len;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;
	struct ethhdr *eh;

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		if (net_ratelimit())
			netdev_err(ndev, "transmit rejected: bus state %d\n",
				   drvr->bus_if->state);
		netif_stop_queue(ndev);
		dev_kfree_skb(skb);
		ret = -ENETDOWN;
		goto done;
	}

	if (netif_queue_stopped(ndev)) {
		dev_kfree_skb(skb);
		if (net_ratelimit())
			netdev_err(ndev, "TX queue already stopped\n");
		ret = -ENETDOWN;
		goto done;
	}

	if (!drvr->iflist[ifp->bssidx]) {
		if (net_ratelimit())
			netdev_err(ndev, "invalid interface index: %d\n",
				   ifp->bssidx);
		netif_stop_queue(ndev);
		dev_kfree_skb(skb);
		ret = -ENODEV;
		goto done;
	}

	if (skb_headroom(skb) < drvr->hdrlen) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, drvr->hdrlen);
		dev_kfree_skb(skb);
		skb = skb2;
		if (!skb) {
			ret = -ENOMEM;
			goto done;
		}
	}

	if (skb->len < sizeof(*eh)) {
		if (net_ratelimit())
			netdev_err(ndev,
				   "invalid ethernet packet length: %u\n",
				   skb->len);
		ret = -EINVAL;
		dev_kfree_skb(skb);
		goto done;
	}

	ret = wland_check_arp(ifp, skb);
	if (ret == 0)
		goto done;

	wland_check_tid(ifp, skb);

	ret = wland_sendpkt(ifp, skb);

done:
	if (ret < 0) {
		ifp->stats.tx_dropped++;
	} else {
		ifp->stats.tx_packets++;
		/* sendpkt/ARP handling may already have freed skb */
		ifp->stats.tx_bytes += packet_len;
	}

	/* The packet is always consumed */
	return NETDEV_TX_OK;
}

static struct net_device_stats *wland_netdev_get_stats(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	return &ifp->stats;
}

static void wland_ethtool_get_drvinfo(struct net_device *ndev,
				      struct ethtool_drvinfo *info)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;

	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	snprintf(info->version, sizeof(info->version), "%d", drvr->drv_version);
	strlcpy(info->bus_info, dev_name(drvr->bus_if->dev),
		sizeof(info->bus_info));
}

static const struct ethtool_ops wland_ethtool_ops = {
	.get_drvinfo = wland_ethtool_get_drvinfo,
};

static int wland_get_nickname(struct net_device *ndev, struct ifreq *ifr,
			      int cmd)
{
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct iwreq *wrq = (struct iwreq *)ifr;

	if (profile->ssid.SSID_len && wrq->u.data.pointer) {
		if (copy_to_user(wrq->u.data.pointer,
				 profile->ssid.SSID,
				 profile->ssid.SSID_len + 1))
			return -EFAULT;
		return 0;
	}

	return -EFAULT;
}

static int wland_netdev_ioctl_entry(struct net_device *ndev, struct ifreq *ifr,
				    int cmd)
{
	if (cmd == SIOCGIWNICKN)
		return wland_get_nickname(ndev, ifr, cmd);

	return -EOPNOTSUPP;
}

static int wland_netdev_stop(struct net_device *ndev)
{
	if (!netif_queue_stopped(ndev))
		netif_stop_queue(ndev);
	if (netif_carrier_ok(ndev))
		netif_carrier_off(ndev);

	wland_cfg80211_down(ndev);

	return 0;
}

static int wland_netdev_open(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;
	struct wland_bus *bus_if = drvr->bus_if;
	s32 ret;

	ret = wland_start_chip(ndev);
	if (ret < 0) {
		netdev_err(ndev, "failed to bring up chip: %d\n", ret);
		return ret;
	}

	if (bus_if->state != WLAND_BUS_DATA) {
		netdev_err(ndev, "bus is not ready\n");
		return -EAGAIN;
	}

	atomic_set(&ifp->pend_8021x_cnt, 0);

	if (wland_cfg80211_up(ndev) < 0) {
		netdev_err(ndev, "failed to bring up cfg80211\n");
		ret = -ENODEV;
	}

	if (!ret) {
		netif_carrier_on(ndev);
		netif_start_queue(ndev);
	}

	return ret;
}

static void wland_netdev_tx_timeout(struct net_device *dev)
{
	struct wland_if *ifp = netdev_priv(dev);

	netif_trans_update(dev);
	/* A wedged transport needs a fresh binding, not another queue wake. */
	wland_usb_request_recovery(ifp->drvr->bus_if->dev);
	dev->stats.tx_errors++;
}

static const struct net_device_ops wland_netdev_ops_pri = {
	.ndo_open = wland_netdev_open,
	.ndo_stop = wland_netdev_stop,
	.ndo_get_stats = wland_netdev_get_stats,
	.ndo_do_ioctl = wland_netdev_ioctl_entry,
	.ndo_start_xmit = wland_netdev_start_xmit,
	.ndo_tx_timeout = wland_netdev_tx_timeout,
	.ndo_set_mac_address = wland_netdev_set_mac_address,
	.ndo_set_rx_mode = wland_netdev_set_multicast_list,
};

int wland_netdev_attach(struct wland_if *ifp)
{
	struct wland_private *drvr = ifp->drvr;
	struct net_device *ndev = ifp->ndev;
	s32 err;

	ndev->netdev_ops = &wland_netdev_ops_pri;

	ndev->hard_header_len += drvr->hdrlen;
	ndev->flags |= IFF_BROADCAST | IFF_MULTICAST;

	ndev->ethtool_ops = &wland_ethtool_ops;

	memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);

	if (rtnl_is_locked())
		err = register_netdevice(ndev);
	else
		err = register_netdev(ndev);
	if (err != 0) {
		netdev_err(ndev, "failed to register netdev: %d\n", err);
		goto fail;
	}

	netdev_dbg(ndev, "rdawlan host driver (MAC %pM, MTU %d)\n",
		   ndev->dev_addr, ndev->mtu);

	INIT_WORK(&ifp->setmacaddr_work, _wland_set_mac_address);
	INIT_WORK(&ifp->multicast_work, _wland_set_multicast_list);

	ndev->needs_free_netdev = true;
	return 0;

fail:
	drvr->iflist[ifp->bssidx] = NULL;
	ndev->netdev_ops = NULL;
	free_netdev(ndev);
	return -EBADE;
}

static int wland_netdev_p2p_open(struct net_device *ndev)
{
	return wland_cfg80211_up(ndev);
}

static int wland_netdev_p2p_stop(struct net_device *ndev)
{
	if (!netif_queue_stopped(ndev))
		netif_stop_queue(ndev);
	if (netif_carrier_ok(ndev))
		netif_carrier_off(ndev);

	wland_cfg80211_down(ndev);
	return 0;
}

static int wland_netdev_p2p_do_ioctl(struct net_device *ndev, struct ifreq *ifr,
				     int cmd)
{
	return -EOPNOTSUPP;
}

static const struct net_device_ops wland_netdev_ops_p2p = {
	.ndo_open = wland_netdev_p2p_open,
	.ndo_stop = wland_netdev_p2p_stop,
	.ndo_do_ioctl = wland_netdev_p2p_do_ioctl,
	.ndo_start_xmit = wland_netdev_start_xmit,
};

static void wland_cfgp2p_ethtool_get_drvinfo(struct net_device *net,
					     struct ethtool_drvinfo *info)
{
	snprintf(info->driver, sizeof(info->driver), "p2p");
	snprintf(info->version, sizeof(info->version), "%lu", 0UL);
}

static const struct ethtool_ops wland_cfgp2p_ethtool_ops = {
	.get_drvinfo = wland_cfgp2p_ethtool_get_drvinfo
};

int wland_netdev_p2p_attach(struct wland_if *ifp)
{
	struct net_device *ndev = ifp->ndev;

	if (!ndev) {
		dev_err(ifp->drvr->bus_if->dev, "missing P2P netdev\n");
		return -EBADE;
	}
	ndev->netdev_ops = &wland_netdev_ops_p2p;
	ndev->ethtool_ops = &wland_cfgp2p_ethtool_ops;

	memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);

	if (register_netdev(ndev)) {
		netdev_err(ndev, "failed to register P2P netdev\n");
		goto fail;
	}

	return 0;
fail:
	ifp->drvr->iflist[ifp->bssidx] = NULL;
	ndev->netdev_ops = NULL;
	free_netdev(ndev);
	return -EBADE;
}

struct wland_if *wland_add_if(struct wland_private *drvr, s32 bssidx,
			      s32 ifidx, char *name, u8 *mac_addr)
{
	struct net_device *ndev;
	struct wland_if *ifp;
	struct device *dev;

	if (!drvr)
		return ERR_PTR(-EINVAL);

	dev = drvr->bus_if->dev;
	if (bssidx < 0 || bssidx >= WLAND_MAX_IFS) {
		dev_err(dev, "invalid bss index %d\n", bssidx);
		return ERR_PTR(-EINVAL);
	}

	ifp = drvr->iflist[bssidx];

	/*
	 * Delete the existing interface before overwriting it in case we
	 * missed the WLAND_E_IF_DEL event.
	 */
	if (ifp) {
		if (ifp->ndev)
			netdev_err(ifp->ndev,
				   "interface index %d already exists\n",
				   ifidx);
		else
			dev_err(dev, "interface index %d already exists\n",
				ifidx);

		if (ifidx) {
			if (ifp->ndev) {
				netif_stop_queue(ifp->ndev);
				unregister_netdev(ifp->ndev);
				free_netdev(ifp->ndev);
				drvr->iflist[bssidx] = NULL;
			}
		} else {
			if (ifp->ndev)
				netdev_err(ifp->ndev,
					   "ignoring interface event\n");
			else
				dev_err(dev, "ignoring interface event\n");
			return ERR_PTR(-EINVAL);
		}
	}

	if (!drvr->p2p_enable && bssidx == 1) {
		/* The P2P device interface has no netdev */
		ifp = kzalloc(sizeof(*ifp), GFP_KERNEL);
		if (!ifp)
			return ERR_PTR(-ENOMEM);
	} else {
		ndev = alloc_netdev(sizeof(struct wland_if), name,
				    NET_NAME_UNKNOWN, ether_setup);
		if (!ndev)
			return ERR_PTR(-ENOMEM);

		ndev->netdev_ops = NULL;

		ifp = netdev_priv(ndev);
		ifp->ndev = ndev;
	}

	ifp->drvr = drvr;
	ifp->ifidx = ifidx;
	ifp->bssidx = bssidx;
	ifp->tx_flowblock = false;
	drvr->iflist[bssidx] = ifp;

	init_waitqueue_head(&ifp->pend_8021x_wait);
	spin_lock_init(&ifp->netif_stop_lock);

	if (mac_addr)
		memcpy(ifp->mac_addr, mac_addr, ETH_ALEN);

	return ifp;
}

void wland_del_if(struct wland_private *drvr, s32 bssidx)
{
	struct wland_if *ifp = drvr->iflist[bssidx];

	if (!ifp) {
		dev_err(drvr->bus_if->dev, "missing interface for index %d\n", bssidx);
		return;
	}

	if (ifp->ndev) {
		if (bssidx == 0) {
			if (ifp->ndev->netdev_ops == &wland_netdev_ops_pri) {
				/*
				 * Bus teardown and firmware event work do not
				 * hold RTNL; ndo_open may still be running.
				 */
				rtnl_lock();
				wland_netdev_stop(ifp->ndev);
				rtnl_unlock();
			}
		} else {
			netif_stop_queue(ifp->ndev);
		}

		if (ifp->ndev->netdev_ops == &wland_netdev_ops_pri) {
			cancel_work_sync(&ifp->setmacaddr_work);
			cancel_work_sync(&ifp->multicast_work);
		}

		/* Unregistering also frees the netdev */
		unregister_netdev(ifp->ndev);
		if (bssidx == 0 && drvr->config && !IS_ERR(drvr->config)) {
			wland_cfg80211_detach(drvr->config);
			drvr->config = NULL;
		}
		drvr->iflist[bssidx] = NULL;

	} else {
		drvr->iflist[bssidx] = NULL;
		kfree(ifp);
	}
}

int wland_netdev_wait_pend8021x(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int err;

	err = wait_event_timeout(ifp->pend_8021x_wait,
				 !atomic_read(&ifp->pend_8021x_cnt),
				 msecs_to_jiffies(MAX_WAIT_FOR_8021X_TX));

	WARN_ON(!err);
	return !err;
}

static int __init wlanfmac_module_init(void)
{
	return wland_usb_register();
}

static void __exit wlanfmac_module_exit(void)
{
	wland_usb_exit();
}

module_init(wlanfmac_module_init);
module_exit(wlanfmac_module_exit);

char rdawlan_firmware_path[MOD_PARAM_PATHLEN] = "sta";
unsigned char WifiMac[6];
int n_WifiMac;

u8 wland_check_test_mode(void)
{
	return 0;
}

void wland_set_test_mode(u8 mode)
{
}

module_param_string(firmware_path, rdawlan_firmware_path,
		    MOD_PARAM_PATHLEN, 0660);
module_param_array(WifiMac, byte, &n_WifiMac, 0444);

MODULE_AUTHOR("RdaMicro");
MODULE_DESCRIPTION("RdaMicro 802.11 Wireless LAN FullMac Driver");
MODULE_LICENSE("GPL v2");
