/*
** wifi-iface.c -- The implementation of WiFi interfaces.
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

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"
#include "list.h"

#include <unistd.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>

static char *wifiStartScanHotspots(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_START_SCAN) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    pcutils_printbuf_strappend(pb, "{\"data\":[");

    purc_variant_t extra_value;
    struct network_device *netdev;
    netdev = check_network_device_ex(info, method_param,
            DEVICE_TYPE_ETHER_WIRELESS, "waitSeconds", &extra_value, &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN ||
            netdev->status == DEVICE_STATUS_UNCERTAIN ||
            netdev->ctxt == NULL) {
        errcode = ENETDOWN;
        goto done;
    }

    double wait_seconds = 0;
    if (extra_value) {
        purc_variant_cast_to_number(extra_value, &wait_seconds, false);
        purc_variant_unref(extra_value);
    }

    if (wait_seconds >= 0.1) {
        errcode = netdev->wifi_ops->start_scan(netdev->ctxt);
        if (errcode) {
            goto done;
        }

        if (wait_seconds > 5.0) {
            wait_seconds = 5.0;
        }

        unsigned nr_100ms = (unsigned)(wait_seconds * 10);
        do {
            TEMP_FAILURE_RETRY(usleep(100000)); // 0.1s
        } while (--nr_100ms);
    }

    const struct list_head *hotspots;
    hotspots = netdev->wifi_ops->get_hotspot_list_head(netdev->ctxt);
    if (hotspots == NULL) {
        goto done;
    }

    print_hotspots(hotspots, pb);

    if (wait_seconds < 0.1) {
        netdev->wifi_ops->start_scan(netdev->ctxt);
    }

done:
    pcutils_printbuf_format(pb,
            "],\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *bus_ec = 0;
    return pb->buf;
}

static char *wifiGetHotspotList(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_GET_HOTSPOTS) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    pcutils_printbuf_strappend(pb, "{\"data\":[");

    struct network_device *netdev;
    netdev = check_network_device(info, method_param,
            DEVICE_TYPE_ETHER_WIRELESS, &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN ||
            netdev->status == DEVICE_STATUS_UNCERTAIN ||
            netdev->ctxt == NULL) {
        errcode = ENETDOWN;
        goto done;
    }

    const struct list_head *hotspots;
    hotspots = netdev->wifi_ops->get_hotspot_list_head(netdev->ctxt);
    if (hotspots == NULL) {
        goto done;
    }

    print_hotspots(hotspots, pb);

done:
    pcutils_printbuf_format(pb, "],\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    return pb->buf;
}

static char *wifiStopScanHotspots(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_START_SCAN) == 0);

    struct network_device *netdev;
    netdev = check_network_device(info, method_param,
            DEVICE_TYPE_ETHER_WIRELESS, &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN ||
            netdev->status == DEVICE_STATUS_UNCERTAIN ||
            netdev->ctxt == NULL) {
        errcode = ENETDOWN;
        goto done;
    }

    errcode = netdev->wifi_ops->stop_scan(netdev->ctxt);
    if (errcode) {
        goto done;
    }

done:
    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *bus_ec = 0;
    return pb->buf;
}

static char *wifiConnect(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_CONNECT_AP) == 0);

    purc_variant_t jo = NULL;
    purc_variant_t jo_tmp = NULL;

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        errcode = ERR_WRONG_JSON;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "device")) == NULL) {
        HLOG_ERR("No `device` key\n");
        errcode = ENOKEY;
        goto done;
    }

    const char *ifname = purc_variant_get_string_const(jo_tmp);
    if (ifname == NULL || !is_valid_interface_name(ifname)) {
        HLOG_ERR("Bad interface name: %s\n", ifname);
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "ssid")) == NULL) {
        HLOG_ERR("No `ssid` key\n");
        errcode = ENOKEY;
        goto done;
    }

    const char *ssid = purc_variant_get_string_const(jo_tmp);
    if (ssid == NULL) {
        HLOG_ERR("SSID not specified\n");
        errcode = EINVAL;
        goto done;
    }

    const char *keymgmt = NULL;
    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "keymgmt"))) {
        keymgmt = purc_variant_get_string_const(jo_tmp);
        HLOG_INFO("Specified key management: %s\n", keymgmt);
    }

    struct network_device *netdev;
    netdev = retrieve_network_device_from_ifname(info, ifname);
    if (netdev == NULL) {
        HLOG_ERR("Not existed interface name: %s\n", ifname);
        errcode = ENOENT;
        goto done;
    }

    if (netdev->type != DEVICE_TYPE_ETHER_WIRELESS) {
        errcode = EINVAL;
        goto done;
    }

    if (update_network_device_dynamic_info(ifname, netdev)) {
        HLOG_ERR("Failed to update interface information: %s\n", ifname);
        errcode = errno;
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN ||
            netdev->status == DEVICE_STATUS_UNCERTAIN ||
            netdev->ctxt == NULL) {
        errcode = ENETDOWN;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "password")) == NULL) {
        errcode = ENOKEY;
        goto done;
    }

    const char *password = purc_variant_get_string_const(jo_tmp);
    if (password == NULL) {
        HLOG_ERR("Password not specified\n");
        errcode = EINVAL;
        goto done;
    }

    errcode = netdev->wifi_ops->connect(netdev->ctxt, ssid, keymgmt, password);

done:
    if (jo)
        purc_variant_unref(jo);

    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *bus_ec = 0;
    return pb->buf;
}

static char *wifiDisconnect(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_DISCONNECT_AP) == 0);

    struct network_device *netdev;
    netdev = check_network_device(info, method_param,
            DEVICE_TYPE_ETHER_WIRELESS, &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_RUNNING) {
        errcode = ENONET;
        goto done;
    }

    errcode = netdev->wifi_ops->disconnect(netdev->ctxt);
    if (errcode) {
        goto done;
    }

done:
    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *bus_ec = 0;
    return pb->buf;
}

static char *wifiGetNetworkInfo(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_GET_NETWORK_INFO) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    struct network_device *netdev;
    netdev = check_network_device(info, method_param,
            DEVICE_TYPE_ETHER_WIRELESS, &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN ||
            netdev->status == DEVICE_STATUS_UNCERTAIN ||
            netdev->ctxt == NULL) {
        errcode = ENETDOWN;
        goto done;
    }

    pcutils_printbuf_strappend(pb, "{\"data\":{");

    // device name
    pcutils_printbuf_format(pb,
            "\"device\":\"%s\",", netdev->ifname);

    switch (netdev->status) {
        case DEVICE_STATUS_DOWN:
            pcutils_printbuf_strappend(pb, "\"status\":\"down\",");
            break;

        case DEVICE_STATUS_UP:
            pcutils_printbuf_strappend(pb, "\"status\":\"up\",");
            break;

        case DEVICE_STATUS_RUNNING:
            pcutils_printbuf_strappend(pb, "\"status\":\"running\",");
            break;

        default:
            pcutils_printbuf_strappend(pb, "\"status\":\"uncertain\",");
            break;
    }

    const struct wifi_status *status;
    status = netdev->wifi_ops->get_status(netdev->ctxt);
    if (status == NULL || status->hotspot == NULL) {
        errcode = ENONET;
        goto done;
    }

    const struct wifi_hotspot *hotspot = status->hotspot;

    char frequency[64];
    print_frequency(hotspot->frequency, frequency, sizeof(frequency));
    pcutils_printbuf_format(pb,
            "\"bssid\":\"%s\","
            "\"ssid\":\"%s\","
            "\"frequency\":\"%s\","
            "\"keyMgmt\":\"%s\","
            "\"signalLevel\":%d,",
            hotspot->bssid,
            hotspot->ssid,
            frequency,
            status->key_mgmt,
            hotspot->signal_level);

    pcutils_printbuf_format(pb,
            "\"hardwareAddr\":\"%s\","
            "\"inet\":{\"address\":\"%s\","
                "\"netmask\":\"%s\","
                "\"broadcastAddr\":\"%s\","
                "\"destinationAddr\":\"%s\""
            "},"
            "\"inet6\":{\"address\":\"%s\","
                "\"netmask\":\"%s\","
                "\"broadcastAddr\":\"%s\","
                "\"destinationAddr\":\"%s\""
            "},",
            netdev->hwaddr ? netdev->hwaddr : "",
            netdev->ipv4.addr ? netdev->ipv4.addr : "",
            netdev->ipv4.netmask ? netdev->ipv4.netmask : "",
            (netdev->flags & IFF_POINTOPOINT) ? "" : netdev->ipv4.hbdifa_broadaddr,
            (netdev->flags & IFF_POINTOPOINT) ? netdev->ipv4.hbdifa_dstaddr : "",
            netdev->ipv6.addr ? netdev->ipv6.addr : "",
            netdev->ipv6.netmask ? netdev->ipv6.netmask : "",
            (netdev->flags & IFF_POINTOPOINT) ? "" : netdev->ipv6.hbdifa_broadaddr,
            (netdev->flags & IFF_POINTOPOINT) ? netdev->ipv6.hbdifa_dstaddr : "");

done:
    pcutils_printbuf_format(pb,
            "},\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *bus_ec = 0;
    return pb->buf;
}

static const struct procedure {
    const char           *name;
    hbdbus_method_handler handler;
} procedures[] = {
    { METHOD_WIFI_START_SCAN, wifiStartScanHotspots },
    { METHOD_WIFI_GET_HOTSPOTS, wifiGetHotspotList },
    { METHOD_WIFI_STOP_SCAN, wifiStopScanHotspots },
    { METHOD_WIFI_CONNECT_AP, wifiConnect },
    { METHOD_WIFI_DISCONNECT_AP, wifiDisconnect },
    { METHOD_WIFI_GET_NETWORK_INFO, wifiGetNetworkInfo },
};

static const char *events[] = {
    BUBBLE_WIFISCANFINISHED,
    BUBBLE_WIFICONNECTED,
    BUBBLE_WIFICONFIGURED,
    BUBBLE_WIFIDISCONNECTED,
    BUBBLE_WIFISCANFINISHED,
    BUBBLE_WIFISIGNALSTRENGTHCHANGED,
};

int register_wifi_interfaces(hbdbus_conn *conn)
{
    int errcode = 0;

    for (size_t i = 0; i < PCA_TABLESIZE(procedures); i++) {
        errcode = hbdbus_register_procedure(conn, procedures[i].name,
                HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
                procedures[i].handler);
        if (errcode) {
            HLOG_ERR("Error when registering procedure %s: %s.\n",
                    procedures[i].name, hbdbus_get_err_message(errcode));
            goto done;
        }
    }

    for (size_t i = 0; i < PCA_TABLESIZE(events); i++) {
        errcode = hbdbus_register_event(conn, events[i],
                HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS);
        if (errcode) {
            HLOG_ERR("Error for register event %s: %s.\n",
                    events[i], hbdbus_get_err_message(errcode));
            goto done;
        }
    }

done:
    return errcode;
}

void revoke_wifi_interfaces(hbdbus_conn *conn)
{
    for (size_t i = 0; i < PCA_TABLESIZE(events); i++) {
        hbdbus_revoke_event(conn, events[i]);
    }

    for (size_t i = 0; i < PCA_TABLESIZE(procedures); i++) {
        hbdbus_revoke_procedure(conn, procedures[i].name);
    }
}

