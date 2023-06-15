/*
** common-iface.c -- The implementation of common interfaces.
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

#undef NDEBUG

#include "internal.h"
#include "log.h"

#include <net/if.h>
#include <glib.h>
#include <assert.h>
#include <errno.h>

static char* terminate(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;
    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);

    assert(info);
    assert(strcasecmp(to_method, METHOD_GLOBAL_TERMINATE) == 0);

    purc_variant_t jo, jo_tmp;
    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        errcode = EINVAL;
        goto done;
    }

    uint32_t seconds;
    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "afterSeconds")) &&
        (purc_variant_cast_to_uint32(jo_tmp, &seconds, false))) {
        info->shutdown_time = time(NULL) + seconds;
        HLOG_INFO("HBDInetd will terminate in %u seconds\n", seconds);
    }
    else {
        errcode = EINVAL;
        goto done;
    }

    purc_variant_unref(jo);
    jo = NULL;

done:
    if (jo)
        purc_variant_unref(jo);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);
    pcutils_printbuf_format(pb, "{\"errCode\":%d, \"errMsg\":\"%s\"}", errcode,
            get_error_message(errcode));

    if (pb->buf == NULL) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    *bus_ec = 0;
    return pb->buf;
}

static char* openDevice(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;
    int errcode = ERR_OK;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    struct run_info *info = hbdbus_conn_get_user_data(conn);

    assert(info);
    assert(strcasecmp(to_method, METHOD_NET_OPEN_DEVICE) == 0);

    struct network_device *netdev;
    netdev = check_network_device(info, method_param, DEVICE_TYPE_UNKNOWN,
            &errcode);
    if (netdev == NULL) {
        errcode = ENOENT;
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_UNCERTAIN) {
        HLOG_INFO("The device %s is in uncertain state\n", netdev->ifname);
        errcode = 0;
        goto done;
    }

    if (netdev->on == NULL) {
        errcode = ENOTSUP;
        goto done;
    }
    else {
        errcode = netdev->on(conn, netdev);
    }

done:
    pcutils_printbuf_init(pb);
    pcutils_printbuf_format(pb, "{\"errCode\":%d, \"errMsg\":\"%s\"}", errcode,
            get_error_message(errcode));

    if (pb->buf == NULL) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }
    *bus_ec = 0;
    return pb->buf;
}

static char *closeDevice(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;
    int errcode = ERR_OK;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    struct run_info *info = hbdbus_conn_get_user_data(conn);

    assert(info);
    assert(strcasecmp(to_method, METHOD_NET_CLOSE_DEVICE) == 0);

    struct network_device *netdev;
    netdev = check_network_device(info, method_param, DEVICE_TYPE_UNKNOWN,
            &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_DOWN) {
        errcode = 0;
        goto done;
    }

    if (netdev->off == NULL) {
        errcode = ENOTSUP;
        goto done;
    }
    else {
        errcode = netdev->off(conn, netdev);
    }

done:
    pcutils_printbuf_init(pb);
    pcutils_printbuf_format(pb, "{\"errCode\":%d, \"errMsg\":\"%s\"}", errcode,
            get_error_message(errcode));

    if (pb->buf == NULL) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    *bus_ec = 0;
    return pb->buf;
}

static char *getDeviceStatus(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *bus_ec)
{
    (void)from_endpoint;
    (void)to_method;

    purc_variant_t jo = NULL;
    purc_variant_t jo_tmp = NULL;
    const char *ifname = NULL;
    int errcode = ERR_OK;

    // get device array
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_NET_GET_DEVICE_STATUS) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);
    pcutils_printbuf_strappend(pb, "{\"data\":[");

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        HLOG_ERR("Bad parameters: %s\n", method_param);
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "device")) == NULL) {
        HLOG_ERR("No device defined: %s\n", method_param);
        errcode = ENOKEY;
        goto done;
    }

    ifname = purc_variant_get_string_const(jo_tmp);
    if (ifname == NULL) {
        HLOG_ERR("Bad interface name\n");
        errcode = EINVAL;
        goto done;
    }

    GPatternSpec* spec = g_pattern_spec_new(ifname);
    if (spec == NULL) {
        if (pb->buf)
            free(pb->buf);
        purc_variant_unref(jo);
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }
    purc_variant_unref(jo);
    jo = NULL;

    int nr_devices = 0;
    const char* name;
    void *data;
    kvlist_for_each(&info->devices, name, data) {
        struct network_device *netdev;
        netdev = *(struct network_device **)data;

#if GLIB_CHECK_VERSION(2, 70, 0)
        if (g_pattern_spec_match_string(spec, name)) {
#else
        if (g_pattern_match_string(spec, name)) {
#endif
            const char *type;
            const char *status;

            switch (netdev->type) {
                case DEVICE_TYPE_LOOPBACK:
                    type = DEVICE_TYPE_NAME_LOOPBACK;
                    break;
                case DEVICE_TYPE_MOBILE:
                    type = DEVICE_TYPE_NAME_MOBILE;
                    break;
                case DEVICE_TYPE_ETHER_WIRED:
                    type = DEVICE_TYPE_NAME_ETHER_WIRED;
                    break;
                case DEVICE_TYPE_ETHER_WIRELESS:
                    type = DEVICE_TYPE_NAME_ETHER_WIRELESS;
                    break;
                default:
                    type = DEVICE_TYPE_NAME_UNKNOWN;
                    break;
            }

            switch (netdev->status) {
                case DEVICE_STATUS_DOWN:
                    status = DEVICE_STATUS_NAME_DOWN;
                    break;

                case DEVICE_STATUS_UP:
                    status = DEVICE_STATUS_NAME_UP;
                    break;

                case DEVICE_STATUS_RUNNING:
                    status = DEVICE_STATUS_NAME_RUNNING;
                    break;

                default:
                    status = DEVICE_STATUS_NAME_UNCERTAIN;
                    break;
            }

            pcutils_printbuf_format(pb,
                "{"
                    "\"device\":\"%s\","
                    "\"type\":\"%s\","
                    "\"status\":\"%s\","
                    "\"hardwareAddr\":\"%s\","
                    "\"dns1\":\"%s\","
                    "\"dns2\":\"%s\","
                    "\"configMethod\":\"%s\","
                    "\"search\":\"%s\","
                    "\"inet4\":{\"address\":\"%s\","
                        "\"netmask\":\"%s\","
                        "\"broadcastAddr\":\"%s\","
                        "\"destinationAddr\":\"%s\","
                        "\"gateway\":\"%s\""
                    "},"
                    "\"inet6\":{\"address\":\"%s\","
                        "\"netmask\":\"%s\","
                        "\"broadcastAddr\":\"%s\","
                        "\"destinationAddr\":\"%s\","
                        "\"gateway\":\"%s\""
                    "}"
                "},",
                name,
                type,
                status,
                netdev->hwaddr ? netdev->hwaddr : "",
                netdev->dns1 ? netdev->dns1 : "",
                netdev->dns2 ? netdev->dns2 : "",
                netdev->search ? netdev->search : "",
                netdev->method ? netdev->method : "Unknown",
                netdev->ipv4.addr ? netdev->ipv4.addr : "",
                netdev->ipv4.netmask ? netdev->ipv4.netmask : "",
                (netdev->flags & IFF_POINTOPOINT) ? "" :
                    (netdev->ipv4.hbdifa_broadaddr ? netdev->ipv4.hbdifa_broadaddr : ""),
                (netdev->flags & IFF_POINTOPOINT) ?
                    (netdev->ipv4.hbdifa_dstaddr ? netdev->ipv4.hbdifa_dstaddr : "") : "",
                netdev->ipv4.gateway ? netdev->ipv4.gateway : "",
                netdev->ipv6.addr ? netdev->ipv6.addr : "",
                netdev->ipv6.netmask ? netdev->ipv6.netmask : "",
                (netdev->flags & IFF_POINTOPOINT) ? "" :
                    (netdev->ipv6.hbdifa_broadaddr ? netdev->ipv6.hbdifa_broadaddr : ""),
                (netdev->flags & IFF_POINTOPOINT) ?
                    (netdev->ipv6.hbdifa_dstaddr ? netdev->ipv6.hbdifa_dstaddr : "") : "",
                netdev->ipv6.gateway ? netdev->ipv6.gateway : "");
            nr_devices++;
        }
    }

    if (nr_devices > 0)
        pcutils_printbuf_shrink(pb, 1);

    g_pattern_spec_free(spec);

done:
    if (jo)
        purc_variant_unref(jo);

    pcutils_printbuf_format(pb, "],\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));

    if (pb->buf == NULL) {
        *bus_ec = HBDBUS_EC_NOMEM;
        return NULL;
    }

    *bus_ec = 0;
    return pb->buf;
}

int register_common_interfaces(hbdbus_conn * conn)
{
    int errcode = 0;

    errcode = hbdbus_register_procedure(conn, METHOD_GLOBAL_TERMINATE,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS, terminate);
    if (errcode) {
        HLOG_ERR("Error for register procedure %s: %s.\n",
                METHOD_GLOBAL_TERMINATE, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_NET_OPEN_DEVICE,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS, openDevice);
    if (errcode) {
        HLOG_ERR("Error for register procedure %s: %s.\n",
                METHOD_NET_OPEN_DEVICE, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_NET_CLOSE_DEVICE,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS, closeDevice);
    if (errcode) {
        HLOG_ERR("Error for register procedure %s: %s.\n",
                METHOD_NET_CLOSE_DEVICE, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_NET_GET_DEVICE_STATUS,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS, getDeviceStatus);
    if (errcode) {
        HLOG_ERR("Error for register procedure %s: %s.\n",
                METHOD_NET_GET_DEVICE_STATUS, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_event(conn, BUBBLE_DEVICECHANGED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS);
    if (errcode) {
        HLOG_ERR("Error for register event %s: %s.\n",
                BUBBLE_DEVICECHANGED, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_event(conn, BUBBLE_DEVICECONFIGURED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS);
    if (errcode) {
        HLOG_ERR("Error for register event %s: %s.\n",
                BUBBLE_DEVICECONFIGURED, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_event(conn, BUBBLE_DEVICECONFIGFAILED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS);
    if (errcode) {
        HLOG_ERR("Error for register event %s: %s.\n",
                BUBBLE_DEVICECONFIGFAILED, hbdbus_get_err_message(errcode));
        goto failed;
    }

    return 0;

failed:
    return errcode;
}

void revoke_common_interfaces(hbdbus_conn *conn)
{
    hbdbus_revoke_event(conn, BUBBLE_DEVICECHANGED);
    hbdbus_revoke_event(conn, BUBBLE_DEVICECONFIGURED);
    hbdbus_revoke_event(conn, BUBBLE_DEVICECONFIGFAILED);
    hbdbus_revoke_procedure(conn, METHOD_NET_OPEN_DEVICE);
    hbdbus_revoke_procedure(conn, METHOD_NET_CLOSE_DEVICE);
    hbdbus_revoke_procedure(conn, METHOD_NET_GET_DEVICE_STATUS);
}

