/*
** helpers.h -- The header for WiFi helpers.
**
** Copyright (C) 2023 FMSoft (http://www.fmsoft.cn)
**
** Author: Vincent Wei (https://github.com/VincentWei)
**
** This file is part of HBDInetd.
**
** HBDInetd is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** HBDInetd is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU General Public License
** along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#ifndef _hbdinetd_port_linux_wifi_helpers_h
#define _hbdinetd_port_linux_wifi_helpers_h

#include "list.h"
#include <purc/purc-helpers.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wifi_hotspot;
struct netdev_context;

void wifi_reset_hotspots(struct list_head *hotspots);
const struct wifi_hotspot *
wifi_get_hotspot_by_ssid(struct netdev_context *ctxt, const char *ssid);

int wifi_load_saved_networks(struct netdev_context *ctxt);
int wifi_get_netid_from_ssid(struct netdev_context *ctxt, const char *ssid);

void wifi_reset_status(struct netdev_context *ctxt);
int wifi_update_status(struct netdev_context *ctxt);

int wifi_parse_scan_results(struct list_head *hotspots,
        const char *results, size_t max_len);
int wifi_parse_networks(struct kvlist *networks,
        const char *results, size_t max_len);

const char *
wifi_get_keymgmt_from_capabilities(const struct wifi_hotspot *hotspot);

int wifi_get_signal_level_by_bssid(struct netdev_context *ctxt,
        const char *bssid);

int wifi_add_network(struct netdev_context *ctxt, const char *ssid,
        const char *keymgmt, const char *passphrase);
int wifi_update_network(struct netdev_context *ctxt, int netid,
        const char *ssid, const char *keymgmt, const char *passphrase);

#ifdef __cplusplus
};  // extern "C"
#endif

#endif  // _hbdinetd_port_linux_wifi_helpers_h

