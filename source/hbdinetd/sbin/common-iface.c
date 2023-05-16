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

#include "global.h"
#include "log.h"

#include <net/if.h>
#include <glib.h>
#include <assert.h>
#include <errno.h>

static char* openDevice(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *ret_code)
{
    (void)from_endpoint;
    (void)to_method;
    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);

    assert(info);
    assert(strcasecmp(to_method, METHOD_NET_OPEN_DEVICE) == 0);

    struct network_device *netdev;
    netdev = check_network_device(info, method_param, DEVICE_TYPE_UNKNOWN,
            &errcode);
    if (netdev == NULL) {
        goto done;
    }

    if (netdev->status == DEVICE_STATUS_RUNNING) {
        errcode = 0;
        goto done;
    }

    if (netdev->on == NULL) {
        errcode = ENOTSUP;
        goto done;
    }
    else {
        errcode = netdev->on(info, netdev);
    }

done:
    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb, "{\"errCode\":%d, \"errMsg\":\"%s\"}", errcode,
            get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *closeDevice(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *ret_code)
{
    (void)from_endpoint;
    (void)to_method;
    int errcode = ERR_OK;
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
        errcode = netdev->off(info, netdev);
    }

done:
    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb, "{\"errCode\":%d, \"errMsg\":\"%s\"}", errcode,
            get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *getDeviceStatus(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *ret_code)
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

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "device")) == NULL) {
        errcode = ENOKEY;
        goto done;
    }

    ifname = purc_variant_get_string_const(jo_tmp);
    if (ifname == NULL || !is_valid_interface_name(ifname)) {
        LOG_ERROR("Bad interface name: %s\n", ifname);
        errcode = EINVAL;
        goto done;
    }

    GPatternSpec* spec = g_pattern_spec_new(ifname);
    if (spec == NULL) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_strappend(pb, "{\"data\":[");

    int nr_devices = 0;
    const char* name;
    void *data;
    kvlist_for_each(&info->devices, name, data) {
        struct network_device *netdev;
        netdev = *(struct network_device **)data;

        if (g_pattern_spec_match_string(spec, name)) {
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
                        "\"inet\":{\"address\":\"%s\","
                            "\"netmask\":\"%s\","
                            "\"broadcastAddr\":\"%s\","
                            "\"destinationAddr\":\"%s\""
                        "},"
                        "\"inet6\":{\"address\":\"%s\","
                            "\"netmask\":\"%s\","
                            "\"broadcastAddr\":\"%s\","
                            "\"destinationAddr\":\"%s\""
                        "}"
                    "},",
                    name,
                    type,
                    status,
                    netdev->hwaddr ? netdev->hwaddr : "",
                    netdev->ipv4.addr ? netdev->ipv4.addr : "",
                    netdev->ipv4.netmask ? netdev->ipv4.netmask : "",
                    (netdev->flags & IFF_POINTOPOINT) ? "" : netdev->ipv4.hbdifa_broadaddr,
                    (netdev->flags & IFF_POINTOPOINT) ? netdev->ipv4.hbdifa_dstaddr : "",
                    netdev->ipv6.addr ? netdev->ipv6.addr : "",
                    netdev->ipv6.netmask ? netdev->ipv6.netmask : "",
                    (netdev->flags & IFF_POINTOPOINT) ? "" : netdev->ipv6.hbdifa_broadaddr,
                    (netdev->flags & IFF_POINTOPOINT) ? netdev->ipv6.hbdifa_dstaddr : "");
            nr_devices++;
        }
    }

    if (nr_devices > 0)
        pcutils_printbuf_shrink(pb, 1);

done:
    pcutils_printbuf_format(pb, "],\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

int register_common_interfaces(hbdbus_conn * conn)
{
    int errcode = 0;

    errcode = hbdbus_register_procedure(conn, METHOD_NET_OPEN_DEVICE,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS, openDevice);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_NET_OPEN_DEVICE, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_NET_CLOSE_DEVICE,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS, closeDevice);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_NET_CLOSE_DEVICE, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_NET_GET_DEVICE_STATUS,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS, getDeviceStatus);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_NET_GET_DEVICES_STATUS, hbdbus_get_err_message(errcode));
        goto failed;
    }

    errcode = hbdbus_register_event(conn, NETWORKDEVICECHANGED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_ANY_APPS);
    if (errcode) {
        LOG_ERROR("Error for register event %s: %s.\n",
                NETWORKDEVICECHANGED, hbdbus_get_err_message(errcode));
        goto failed;
    }

    return 0;

failed:
    return errcode;
}

void revoke_common_interfaces(hbdbus_conn *conn)
{
    hbdbus_revoke_event(conn, NETWORKDEVICECHANGED);
    hbdbus_revoke_procedure(conn, METHOD_NET_OPEN_DEVICE);
    hbdbus_revoke_procedure(conn, METHOD_NET_CLOSE_DEVICE);
    hbdbus_revoke_procedure(conn, METHOD_NET_GET_DEVICE_STATUS);
}
