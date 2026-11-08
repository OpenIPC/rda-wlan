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

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include "wland_defs.h"

#define WIFI_NVRAM_FILE_NAME	"/etc/WLANMAC"

static int wland_nvram_read(const char *filename, char *data, int size,
			    int offset)
{
	struct file *filp;
	char *buf;
	int ret;
	loff_t pos = offset;

	filp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(filp))
		return PTR_ERR(filp);
	buf = kzalloc(size + 1, GFP_KERNEL);
	if (!buf) {
		filp_close(filp, NULL);
		return -ENOMEM;
	}

	ret = kernel_read(filp, buf, size, &pos);

	buf[size] = '\0';
	if (data && ret > 0)
		memcpy(data, buf, min(ret, size));

	filp_close(filp, NULL);
	kfree(buf);
	return ret;
}

int wland_get_mac_address(char *mac)
{
	char buf[20] = {0};
	int ret;

	ret = wland_nvram_read(WIFI_NVRAM_FILE_NAME, buf, 17, 0);
	if (ret != 17)
		return ret;

	buf[17] = '\0';
	if (!mac_pton(buf, (u8 *)mac) || !is_valid_ether_addr((u8 *)mac)) {
		pr_err("invalid MAC address in %s: %s\n",
		       WIFI_NVRAM_FILE_NAME, buf);
		return -EINVAL;
	}
	return ETH_ALEN;
}
