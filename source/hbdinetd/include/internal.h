/*
** internal.h -- The internal header for HBDInetd.
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

#ifndef _hbdinetd_internal_h
#define _hbdinetd_internal_h

#include <purc/purc.h>
#include <hbdbus/hbdbus.h>

#include "hbdinetd.h"
#include "kvlist.h"

struct run_info {
    bool running;
    bool daemon;
    bool verbose;

    char app_name[PURC_LEN_APP_NAME + 1];
    char runner_name[PURC_LEN_RUNNER_NAME + 1];
    char self_endpoint[PURC_LEN_ENDPOINT_NAME + 1];

    purc_rwstream_t dump_stm;

    struct kvlist devices;
};

/* network device description */
struct hbd_ifaddr {
    char *addr;    /* Address of interface */
    char *netmask; /* Netmask of interface */
    union {
        char *broadaddr;
        /* Broadcast address of interface */
        char *dstaddr;
        /* Point-to-point destination address */
    } ifa_ifu;
#define hbdifa_broadaddr ifa_ifu.broadaddr
#define hbdifa_dstaddr   ifa_ifu.dstaddr
};

/* The details of this structure should be defined by the device engine. */
struct netdev_context;

struct wifi_hotspot {
    char *bssid;
    char *ssid;
    char *capabilities;
    char *frequency;
    char *signal_strength;
    bool is_connected;          // whether connected

    struct list_head ln;
};

struct wifi_device_ops {
    int (*connect)(struct netdev_context *, const char *ssid, const char *key);
    int (*disconnect)(struct netdev_context *);
    int (*start_scan)(struct netdev_context *);
    int (*stop_scan)(struct netdev_context *);
    struct list_head *(*get_hotspot_list_head)(struct netdev_context *);
    struct wifi_hotspot *(*get_connected_hotspot)(struct netdev_context *);
};

typedef struct network_device {
    /* fixed info */
    int                 type;       /* the type of network device */
    unsigned int        bitrate;    /* only for ether wireless */
    const char         *ifname;     /* interface name */
    char               *hwaddr;     /* only for ether interface */

    /* dynamic info */
    unsigned int        status;
    unsigned int        flags;      /* copied from kernel */
    struct hbd_ifaddr   ipv4;
    struct hbd_ifaddr   ipv6;

    /* basic operators for the device engine. */
    int (*on)(struct run_info *info, struct network_device* netdev);
    int (*off)(struct run_info *info, struct network_device* netdev);
    int (*check)(struct run_info *info, struct network_device* netdev);

    /* the following fields will be managed by the device engine */
    time_t              last_time_checked;
    unsigned int        check_interval;     /* interval to call check() */

    struct netdev_context *ctxt;    /* context for this device */
    union {                         /* operators for this device */
        struct wifi_device_ops *wifi_ops;
    };

} network_device;

#ifdef __cplusplus
extern "C" {
#endif

extern struct run_info run_info;

/* ports/<port>/network-device.c */
bool is_valid_interface_name(const char *ifname);
int enumerate_network_devices(struct run_info *run_info);
void cleanup_network_devices(struct run_info *run_info);

struct network_device *get_network_device_fixed_info(const char *ifname,
    struct network_device *netdev);
int update_network_device_dynamic_info(const char *ifname,
    struct network_device *netdev);

int update_network_device_info(struct run_info *info, const char *ifname);

/* ports/<port>/wifi-device.c */
int wifi_device_on(struct run_info *info, struct network_device *netdev);
int wifi_device_off(struct run_info *info, struct network_device *netdev);
int wifi_device_check(struct run_info *info, struct network_device *netdev);

/* utils.c */
const char *get_error_message(int errcode);
struct network_device *check_network_device(struct run_info *info,
        const char *method_param, int expect_type, int *errcode);

/* common-iface.c */
int register_common_interfaces(hbdbus_conn *conn);
void revoke_common_interfaces(hbdbus_conn *conn);

/* wifi-iface.c */
int register_wifi_interfaces(hbdbus_conn *conn);
void revoke_wifi_interfaces(hbdbus_conn *conn);

#ifdef __cplusplus
}
#endif

static inline struct network_device *
retrieve_network_device_from_ifname(struct run_info *info, const char *ifname)
{
    void *data;
    data = kvlist_get(&info->devices, ifname);
    return *(struct network_device **)data;
}

#endif /* not defined _hbdinetd_internal_h */
