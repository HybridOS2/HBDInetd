/*
** global.h -- The global header for HBDInetd.
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

#ifndef _hbdinetd_global_h
#define _hbdinetd_global_h

#include <purc/purc.h>
#include <hbdbus/hbdbus.h>

#include "hbdinetd.h"
#include "kvlist.h"

#define MAX_DEVICE_NUM                  10          // maximize of network devices is 10
#define DEFAULT_SCAN_TIME               30          // for WiFi scan  period

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

// network device description
struct sockaddr;
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

struct netdev_context;

typedef struct network_device {
    /* fixed info */
    int                 type;       /* the type of network device */
    unsigned int        bitrate;    /* only for ether wireless */
    const char         *ifname;     /* interface name */
    char               *hwaddr;     /* only for ether interface */

    /* dynamic info */
    int                 status;
    unsigned int        flags;      /* copied from kernel */
    struct hbd_ifaddr   ipv4;
    struct hbd_ifaddr   ipv6;

    time_t              time_checked;
    unsigned int        check_interval;     /* interval to call check() */

    /* context for device engine */
    struct netdev_context *ctxt;

    /* basic operators for the device engine. */
    int (*up)(struct run_info *info, struct network_device* netdev);
    int (*down)(struct run_info *info, struct network_device* netdev);
    int (*check)(struct run_info *info, struct network_device* netdev);
} network_device;

#if 0
// WiFi device description
typedef struct _WiFi_device                     // WiFi device description
{
    struct _hiWiFiDeviceOps * wifi_device_Ops;  // the operations for control layer
    struct _wifi_context * context;             // the context for WiFi control layer 
    char bssid[HOTSPOT_STRING_LENGTH];          // bssid of current connecting network
    int signal;                                 // signal strength for current connecting network
    int scan_time;                              // the global time for scan network
    pthread_mutex_t list_mutex;                 // for hotspots list
    struct _wifi_hotspot *first_hotspot;        // hotspots list
} WiFi_device;

// WiFi AP description
typedef struct _wifi_hotspot                    // the information for one AP
{
    char bssid[HOTSPOT_STRING_LENGTH];          // bssid
    unsigned char ssid[HOTSPOT_STRING_LENGTH];  // ssid
    char frenquency[HOTSPOT_STRING_LENGTH];     // frequency
    char capabilities[HOTSPOT_STRING_LENGTH];   // encrypt type
    int  signal_strength;                       // signal strength
    int isConnect;                              // whether connected
    struct _wifi_hotspot * next;                // the next node in list
} wifi_hotspot;

// wifi context of control layer
typedef struct _wifi_context                    // context get from control layer
{
    const aw_wifi_interface_t* p_wifi_interface;// context of tools layer. WiFi is a bit complicated。
    int event_label;                            // lable code for wifimanager
} wifi_context;

// interface of libwifi.so
typedef struct _hiWiFiDeviceOps
{
    int (* open) (const char * device_name, wifi_context ** context);           // open wifi device
    int (* close) (wifi_context * context);                                     // close wifi device
    int (* connect) (wifi_context * context, const char * ssid, const char *password);
    int (* disconnect) (wifi_context * context);
    int (* start_scan) (wifi_context * context);
    int (* stop_scan) (wifi_context * context);
    unsigned int (* get_hotspots) (wifi_context * context, wifi_hotspot ** hotspots);       
    int (*get_cur_net_info)(wifi_context * context, char * reply, int reply_length);
    int (*set_scan_interval)(wifi_context * context, int interval);
    void (* report_wifi_scan_info)(char * device_name, int type, void * hotspots, int number);
} hiWiFiDeviceOps;
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern struct run_info run_info;

/* network-device.c */
bool is_valid_interface_name(const char *ifname);
int enumerate_network_devices(struct run_info *run_info);
void cleanup_network_devices(struct run_info *run_info);

struct network_device *get_network_device_fixed_info(const char *ifname,
    struct network_device *netdev);
int update_network_device_dynamic_info(const char *ifname,
    struct network_device *netdev);

int update_network_device_info(struct run_info *info, const char *ifname);

/* utils.c */
const char *get_error_message(int errcode);

/* common-impl.c */
int register_common_interfaces(hbdbus_conn *conn);
void revoke_common_interfaces(hbdbus_conn *conn);

/* wifi-ops.c */
int wifi_op_up(struct run_info *info, struct network_device *netdev);
int wifi_op_down(struct run_info *info, struct network_device *netdev);
int wifi_op_check(struct run_info *info, struct network_device *netdev);

/* wifi-impl.c */
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

#endif /* not defined _hbdinetd_global_h */
