/*
** wpa-supplicant-conf.h -- The header for operations of wpa_supplicant.conf.
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

#ifndef _hbdinetd_port_linux_wifi_conf_h
#define _hbdinetd_port_linux_wifi_conf_h

#include "wifi.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t wpa_conf_network_load_saved_networks(struct netdev_context *ctxt);

int wpa_conf_is_ap_exist(struct netdev_context *ctxt, const char *ssid,
        const char *key_mgmt, char *net_id, int *len);

int wpa_conf_ssid2netid(struct netdev_context *ctxt,
        char *ssid, const char *key_mgmt, char *net_id, int *len);
int wpa_conf_get_max_priority(struct netdev_context *ctxt);
int wpa_conf_is_ap_connected(struct netdev_context *ctxt, char *ssid, int *len);
int wpa_conf_get_netid_connected(struct netdev_context *ctxt, char *net_id, int *len);
int wpa_conf_get_ap_connected(struct netdev_context *ctxt, char *netid, int *len);
int wpa_conf_enable_all_networks(struct netdev_context *ctxt);
int wpa_conf_remove_all_networks(struct netdev_context *ctxt);

#ifdef __cplusplus
};  // extern "C"
#endif

#endif /* _hbdinetd_port_linux_wifi_conf_h */

