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

#include <time.h>

struct run_info {
    bool running;
    bool daemon;
    bool verbose;
    purc_log_facility_k log_facility;

    time_t shutdown_time;

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
    char *escaped_ssid; /* Use ssid if this is NULL */
    char *capabilities;
    unsigned int frequency;
    int signal_level;

    /* < 0 if not saved */
    int netid;

    struct list_head ln;
};

#define STATUS_KEY_BSSID            "bssid"
#define STATUS_KEY_SSID             "ssid"
#define STATUS_KEY_ID               "id"
#define STATUS_KEY_PAIRWISE_CIPHER  "pairwise_cipher"
#define STATUS_KEY_GROUP_CIPHER     "group_cipher"
#define STATUS_KEY_KEY_MGMT         "key_mgmt"
#define STATUS_KEY_WPA_STATE        "wpa_state"
#define STATUS_KEY_IP_ADDRESS       "ip_address"
#define STATUS_KEY_SUPP_PAE_STATE   "Supplicant PAE state"
#define STATUS_KEY_SUPP_PORT_STATUS "suppPortStatus"
#define STATUS_KEY_EAP_STATE        "EAP state"

enum wpa_state {
    WPA_STATE_floor = 0,

    WPA_STATE_UNKNOWN = WPA_STATE_floor,
#define WPA_STATE_NAME_UNKNOWN              "UNKNOWN"
    WPA_STATE_DISCONNECTED,
#define WPA_STATE_NAME_DISCONNECTED         "DISCONNECTED"
    WPA_STATE_INACTIVE,
#define WPA_STATE_NAME_INACTIVE             "INACTIVE"
    WPA_STATE_INTERFACE_DISABLED,
#define WPA_STATE_NAME_INTERFACE_DISABLED   "INTERFACE_DISABLED"
    WPA_STATE_SCANNING,
#define WPA_STATE_NAME_SCANNING             "SCANNING"
    WPA_STATE_AUTHENTICATING,
#define WPA_STATE_NAME_AUTHENTICATING       "AUTHENTICATING"
    WPA_STATE_ASSOCIATING,
#define WPA_STATE_NAME_ASSOCIATING          "ASSOCIATING"
    WPA_STATE_ASSOCIATED,
#define WPA_STATE_NAME_ASSOCIATED           "ASSOCIATED"
    WPA_STATE_4WAY_HANDSHAKE,
#define WPA_STATE_NAME_4WAY_HANDSHAKE       "4WAY_HANDSHAKE"
    WPA_STATE_GROUP_HANDSHAKE,
#define WPA_STATE_NAME_GROUP_HANDSHAKE      "GROUP_HANDSHAKE"
    WPA_STATE_COMPLETED,
#define WPA_STATE_NAME_COMPLETED            "COMPLETED"

    WPA_STATE_ceil,
};

#define WPA_STATE_nr (WPA_STATE_ceil - WPA_STATE_floor)

enum supp_pae_state {
    SUPP_PAE_STATE_floor = 0,

    SUPP_PAE_STATE_UNKNOWN = SUPP_PAE_STATE_floor,
#define SUPP_PAE_STATE_NAME_UNKNOWN         "Unknown"
    SUPP_PAE_STATE_INITIALIZE,
#define SUPP_PAE_STATE_NAME_INITIALIZE      "INITIALIZE"
    SUPP_PAE_STATE_DISCONNECTED,
#define SUPP_PAE_STATE_NAME_DISCONNECTED    "DISCONNECTED"
    SUPP_PAE_STATE_CONNECTING,
#define SUPP_PAE_STATE_NAME_CONNECTING      "CONNECTING"
    SUPP_PAE_STATE_AUTHENTICATING,
#define SUPP_PAE_STATE_NAME_AUTHENTICATING  "AUTHENTICATING"
    SUPP_PAE_STATE_AUTHENTICATED,
#define SUPP_PAE_STATE_NAME_AUTHENTICATED   "AUTHENTICATED"
    SUPP_PAE_STATE_ABORTING,
#define SUPP_PAE_STATE_NAME_ABORTING        "ABORTING"
    SUPP_PAE_STATE_HELD,
#define SUPP_PAE_STATE_NAME_HELD            "HELD"
    SUPP_PAE_STATE_FORCE_AUTH,
#define SUPP_PAE_STATE_NAME_FORCE_AUTH      "FORCE_AUTH"
    SUPP_PAE_STATE_FORCE_UNAUTH,
#define SUPP_PAE_STATE_NAME_FORCE_UNAUTH    "FORCE_UNAUTH"
    SUPP_PAE_STATE_RESTART,
#define SUPP_PAE_STATE_NAME_RESTART         "RESTART"

    SUPP_PAE_STATE_ceil,
};

#define SUPP_PAE_STATE_nr   (SUPP_PAE_STATE_ceil - SUPP_PAE_STATE_floor)

enum supp_port_status {
    SUPP_PORT_STATUS_floor = 0,

    SUPP_PORT_STATUS_UNKNOWN = SUPP_PORT_STATUS_floor,
#define SUPP_PORT_STATUS_NAME_UNKNOWN       "Unknown"
    SUPP_PORT_STATUS_AUTHORIZED,
#define SUPP_PORT_STATUS_NAME_AUTHORIZED    "Authorized"
    SUPP_PORT_STATUS_UNAUTHORIZED,
#define SUPP_PORT_STATUS_NAME_UNAUTHORIZED  "Unauthorized"

    SUPP_PORT_STATUS_ceil,
};

#define SUPP_PORT_STATUS_nr   (SUPP_PORT_STATUS_ceil - SUPP_PORT_STATUS_floor)

enum eap_state {
    EAP_STATE_floor = 0,

    EAP_STATE_UNKNOWN = EAP_STATE_floor,
#define EPA_STATE_NAME_UNKNOWN          "UNKNOWN"
    EAP_STATE_INITIALIZE,
#define EAP_STATE_NAME_INITIALIZE       "INITIALIZE"
    EAP_STATE_DISABLED,
#define EAP_STATE_NAME_DISABLED         "DISABLED"
    EAP_STATE_IDLE,
#define EAP_STATE_NAME_IDLE             "IDLE"
    EAP_STATE_RECEIVED,
#define EAP_STATE_NAME_RECEIVED         "RECEIVED"
    EAP_STATE_GET_METHOD,
#define EAP_STATE_NAME_GET_METHOD       "GET_METHOD"
    EAP_STATE_METHOD,
#define EAP_STATE_NAME_METHOD           "METHOD"
    EAP_STATE_SEND_RESPONSE,
#define EAP_STATE_NAME_SEND_RESPONSE    "SEND_RESPONSE"
    EAP_STATE_DISCARD,
#define EAP_STATE_NAME_DISCARD          "DISCARD"
    EAP_STATE_IDENTITY,
#define EAP_STATE_NAME_IDENTITY         "IDENTITY"
    EAP_STATE_NOTIFICATION,
#define EAP_STATE_NAME_NOTIFICATION     "NOTIFICATION"
    EAP_STATE_RETRANSMIT,
#define EAP_STATE_NAME_RETRANSMIT       "RETRANSMIT"
    EAP_STATE_SUCCESS,
#define EAP_STATE_NAME_SUCCESS          "SUCCESS"
    EAP_STATE_FAILURE,
#define EAP_STATE_NAME_FAILURE          "FAILURE"

    EAP_STATE_ceil,
};

#define EAP_STATE_nr   (EAP_STATE_ceil - EAP_STATE_floor)

struct wifi_status {
    char *fields[0];        /* aliase for the following fields */
#define WIFI_STATUS_STRING_FIELDS       6

    char *bssid;            /* NULL if not connected */
    char *ssid;             /* Not NULL if bssid is not NULL */
    char *escaped_ssid;     /* Use ssid if this is NULL */
    char *pairwise_cipher;  /* CCMP */
    char *group_cipher;     /* CCMP */
    char *key_mgmt;         /* WPA-PSK */
    char *ip_address;       /* 192.168.2.77 */

    const struct wifi_hotspot *hotspot;

    int  netid;             /* -1 if not connected */
    int  signal_level;

    enum wpa_state          wpa_state;
    enum supp_pae_state     supp_pae_state;
    enum supp_port_status   supp_port_status;
    enum eap_state          eap_state;
};

struct wifi_device_ops {
    int (*connect)(struct netdev_context *,
            const char *ssid, const char *bssid,
            const char *keymgmt, const char *passphrase);
    int (*disconnect)(struct netdev_context *);
    int (*start_scan)(struct netdev_context *);
    int (*stop_scan)(struct netdev_context *);
    const struct list_head *(*get_hotspot_list)(struct netdev_context *, int *);
    const struct wifi_status *(*get_status)(struct netdev_context *);
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
    int (*on)(hbdbus_conn *conn, struct network_device* netdev);
    int (*off)(hbdbus_conn *conn, struct network_device* netdev);
    int (*check)(hbdbus_conn *conn, struct network_device* netdev);
    void (*terminate)(struct network_device* netdev);

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
int wifi_device_on(hbdbus_conn *conn, struct network_device *netdev);
int wifi_device_off(hbdbus_conn *conn, struct network_device *netdev);
int wifi_device_check(hbdbus_conn *conn, struct network_device *netdev);
void wifi_device_terminate(struct network_device *netdev);

/* utils.c */
const char *get_error_message(int errcode);
struct network_device *check_network_device_ex(struct run_info *info,
        const char *method_param, int expect_type,
        const char *extra_key, purc_variant_t *extra_value, int *errcode);

size_t convert_to_hex_string(const char *src, char *hex);
size_t escape_string_to_literal_text(const char *src, char *escaped);
ssize_t unescape_literal_text(const char *escaped, size_t len, char *dst);
char *escape_string_to_literal_text_alloc(const char *src);

int print_frequency(unsigned int frequency, char *buf, size_t buf_sz);
int print_one_hotspot(const struct wifi_hotspot *hotspot, int curr_netid,
        struct pcutils_printbuf *pb);
int print_hotspot_list(const struct list_head *hotspots, int curr_netid,
        struct pcutils_printbuf *pb);

/* pathname will be the first argument. */
int start_daemon(const char *pathname, const char *arg, ...);
int stop_daemon(const char *pidfile);

/* common-iface.c */
int register_common_interfaces(hbdbus_conn *conn);
void revoke_common_interfaces(hbdbus_conn *conn);

/* wifi-iface.c */
int register_wifi_interfaces(hbdbus_conn *conn);
void revoke_wifi_interfaces(hbdbus_conn *conn);

/* dhclient.c */
#define DHCLI_OP_SHUTDOWN   "shutdown"
purc_atom_t dhcli_start(const struct run_info *mainrun);
void dhcli_sync_exit(void);

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

static inline struct network_device *
check_network_device(struct run_info *info,
        const char *method_param, int expect_type, int *errcode)
{
    return check_network_device_ex(info,
        method_param, expect_type, NULL, NULL, errcode);
}

#define strncmp2ltr(str, literal, len) \
    ((len > (sizeof(literal "") - 1)) ? 1 :  \
        (len < (sizeof(literal "") - 1) ? -1 : strncmp(str, literal, len)))

#define strncasecmp2ltr(str, literal, len) \
    ((len > (sizeof(literal "") - 1)) ? 1 :  \
        (len < (sizeof(literal "") - 1) ? -1 : strncasecmp(str, literal, len)))

/* Evaluate EXPRESSION, and repeat as long as it returns -1 with `errno'
    set to EINTR.  */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
   (__extension__                                                              \
     ({ long int __result;                                                     \
        do __result = (long int) (expression);                                 \
        while (__result == -1L && errno == EINTR);                             \
        __result; }))
#endif

#endif /* not defined _hbdinetd_internal_h */

