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

void wifi_reset_hotspots(struct list_head *hotspots);
int wifi_parse_scan_results(struct list_head *hotspots,
        const char *results, size_t max_len);
int wifi_parse_networks(struct kvlist *networks,
        const char *results, size_t max_len);

struct netdev_context;
int wifi_parse_status_for_netid(struct netdev_context *ctxt,
        const char *results, size_t max_len, char **ssid);

struct wifi_hotspot;
/* returns 0 for not changed, > 0 for changed, < 0 for failure */
int wifi_parse_bss_for_signal_level(struct wifi_hotspot *hotspot,
        const char *results, size_t max_len);

#ifdef __cplusplus
};  // extern "C"
#endif

#endif  // _hbdinetd_port_linux_wifi_helpers_h

