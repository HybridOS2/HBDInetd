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

#include <net/if.h>
#include <assert.h>
#include <errno.h>

static char *wifiStartScanHotspots(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *ret_code)
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

    errcode = netdev->wifi_ops->start_scan(netdev->ctxt);
    if (errcode) {
        goto done;
    }

done:
    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *wifiGetHotspotList(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *ret_code)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_GET_HOTSPOTS) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
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

    struct list_head *hotspots;
    hotspots = netdev->wifi_ops->get_hotspot_list_head(netdev->ctxt);
    if (hotspots == NULL) {
        goto done;
    }

    size_t nr_hotspots = 0;
    struct list_head *p;
    list_for_each(p, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        pcutils_printbuf_format(pb,
                "{"
                "\"bssid\":\"%s\","
                "\"ssid\":\"%s\","
                "\"frequency\":\"%s\","
                "\"capabilities\":\"%s\","
                "\"signalStrength\":\"%s\","
                "\"isConnected\":%s"
                "},",
                hotspot->bssid,
                hotspot->ssid,
                hotspot->frequency,
                hotspot->capabilities,
                hotspot->signal_strength,
                hotspot->is_connected ? "true": "false");

        nr_hotspots++;
    }

    if (nr_hotspots > 0)
        pcutils_printbuf_shrink(pb, 1);

done:
    pcutils_printbuf_format(pb, "],\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    return pb->buf;
}

static char *wifiStopScanHotspots(hbdbus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *ret_code)
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
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *wifiConnect(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *ret_code)
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
        errcode = ENOKEY;
        goto done;
    }

    const char *ifname = purc_variant_get_string_const(jo_tmp);
    if (ifname == NULL || !is_valid_interface_name(ifname)) {
        LOG_ERROR("Bad interface name: %s\n", ifname);
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "ssid")) == NULL) {
        errcode = ENOKEY;
        goto done;
    }

    const char *ssid = purc_variant_get_string_const(jo_tmp);
    if (ssid == NULL) {
        LOG_ERROR("SSID not specified\n");
        errcode = EINVAL;
        goto done;
    }

    struct network_device *netdev;
    netdev = retrieve_network_device_from_ifname(info, ifname);
    if (netdev == NULL) {
        LOG_ERROR("Not existed interface name: %s\n", ifname);
        errcode = ENOENT;
        goto done;
    }

    if (netdev->type != DEVICE_TYPE_ETHER_WIRELESS) {
        errcode = EINVAL;
        goto done;
    }

    if (update_network_device_dynamic_info(ifname, netdev)) {
        LOG_ERROR("Failed to update interface information: %s\n", ifname);
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
        LOG_ERROR("Password not specified\n");
        errcode = EINVAL;
        goto done;
    }

    errcode = netdev->wifi_ops->connect(netdev->ctxt, ssid, password);
    if (errcode == 0) {
#if 0
        char reply[512];
        int reply_length = 512;
        int i = 0;

        memset(wifi_device->bssid, 0, HOTSPOT_STRING_LENGTH);

        errcode = ERR_LIBRARY_OPERATION;
        while(errcode)
        {
            usleep(100000);

            i ++;
            if(i > 200)
                goto failed;

            memset(reply, 0, 512);
            errcode = wifi_device->wifi_device_Ops->get_cur_net_info(wifi_device->context, reply, reply_length);
        }

        if(errcode == 0)
        {
            char * tempstart = NULL;
            char * tempend = NULL;
            char content[64];

            memset(content, 0, 64);
            tempstart = strstr(reply, "wpa_state=");
            if(tempstart)
            {
                tempstart += strlen("wpa_state=");
                tempend = strstr(tempstart, "\n");
                if(tempend)
                {
                    memcpy(content, tempstart, tempend - tempstart);
                    if(strncasecmp(content, "COMPLETED", strlen("COMPLETED")) == 0)
                    {
                        device[index].status = DEVICE_STATUS_RUNNING;

                        // bssid
                        tempstart = strstr(reply, "bssid=");
                        if(tempstart)
                        {
                            tempstart += strlen("bssid=");
                            tempend = strstr(tempstart, "\n");
                            if(tempend)
                                memcpy(wifi_device->bssid, tempstart, tempend - tempstart);
                        }
                    }
                }
            }

            wifi_hotspot * node = wifi_device->first_hotspot;

            pthread_mutex_lock(&(wifi_device->list_mutex));
            while(node)
            {
                if(strcmp((char *)wifi_device->bssid, (char *)node->bssid) == 0)
                {
                    wifi_device->signal = node->signal_strength;
                    break;
                }
                node = node->next;
            }
            pthread_mutex_unlock(&(wifi_device->list_mutex));
        }
#endif
    }

done:
    if (jo)
        purc_variant_unref(jo);

    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *wifiDisconnect(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *ret_code)
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
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_format(pb,
            "{\"errCode\":%d, \"errMsg\":\"%s\"}",
            errcode, get_error_message(errcode));
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *wifiGetNetworkInfo(hbdbus_conn* conn, const char* from_endpoint,
        const char* to_method, const char* method_param, int *ret_code)
{
    (void)from_endpoint;
    (void)to_method;

    int errcode = ERR_OK;
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);
    assert(strcasecmp(to_method, METHOD_WIFI_GET_NETWORK_INFO) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
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

    struct wifi_hotspot *hotspot;
    hotspot = netdev->wifi_ops->get_connected_hotspot(netdev->ctxt);
    if (hotspot == NULL) {
        errcode = ENONET;
        goto done;
    }

    pcutils_printbuf_format(pb,
            "\"bssid\":\"%s\","
            "\"ssid\":\"%s\","
            "\"frequency\":\"%s\","
            "\"capabilities\":\"%s\","
            "\"signalStrength\":\"%s\",",
            hotspot->bssid,
            hotspot->ssid,
            hotspot->frequency,
            hotspot->capabilities,
            hotspot->signal_strength);

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
    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

#if 0
void report_wifi_scan_info(char * device_name, int type, void * results, int number)
{
    wifi_hotspot * node = NULL;
    wifi_hotspot * tempnode = NULL;

    network_device * device_array = NULL; 
    int index = 0;
    WiFi_device * wifi_device = NULL;

    if(conn == NULL)
        return;
    device_array = hbdbus_conn_get_user_data(conn);
    if(device_array == NULL)
        return;

    index = get_device_index(device_array, device_name);
    if(index == -1)
        return;

    if(device_array[index].type != DEVICE_TYPE_WIFI)
        return;

    if(device_array[index].lib_handle == NULL)
        return;

    wifi_device = (WiFi_device *)(device_array[index].device);
    if(wifi_device == NULL)
        return;

    if(type == 0)
    {
        wifi_hotspot * hotspots = results;
        wifi_hotspot nodecopy;
        wifi_hotspot * nodecopynext = NULL;

        if(hotspots == NULL)
            return;

        // according to signal strength, order the list
        if(number > 1)
        {
            int i = 1;
            int j = i + 1;
            node = hotspots;

            for(i = 1; i < number - 1; i++)
            {
                node = node->next;
                tempnode = node->next;
                for(j = i + 1; j < number; j++)
                {
                    if(node->signal_strength < tempnode->signal_strength)
                    {
                        nodecopynext = node->next;
                        node->next = tempnode->next;
                        tempnode->next = nodecopynext;

                        memcpy(&nodecopy, node, sizeof(wifi_hotspot));
                        memcpy(node, tempnode, sizeof(wifi_hotspot));
                        memcpy(tempnode, &nodecopy, sizeof(wifi_hotspot));
                    }
                    tempnode = tempnode->next;
                }
            }
        }

        // the connected ssid is the first
        if(strlen(wifi_device->bssid))
        {
            node = hotspots;
            while(node)
            {
                if(strcmp((char *)wifi_device->bssid, (char *)node->bssid) == 0)
                {
                    if(node != hotspots)
                    {
                        nodecopynext = node->next;
                        node->next = hotspots->next;
                        hotspots->next = nodecopynext;

                        memcpy(&nodecopy, node, sizeof(wifi_hotspot));
                        memcpy(node, hotspots, sizeof(wifi_hotspot));
                        memcpy(hotspots, &nodecopy, sizeof(wifi_hotspot));
                        break;
                    }
                }
                node = node->next;
            }
        }

        // send the message
        char * signal = malloc(4096);
        char * remove = malloc(4096);
        char * added = malloc(8192);
        char * message = malloc(8192);
        bool bsignal = false;
        bool bremove = false;
        bool bnew = false;
        bool changedssid = false;
        bool changedsignal = false;
        bool changedcapabilities = false;
        int i = 0;
        wifi_hotspot * host = wifi_device->first_hotspot;

        // send WIFISIGNALSTRENGTHCHANGED message
        if(hotspots && wifi_device->bssid[0] && strcmp((char *)wifi_device->bssid, (char *)hotspots->bssid) == 0)
        {
            wifi_device->signal = hotspots->signal_strength;
            memset(signal, 0, 4096);
            sprintf(signal, "{\"bssid\":\"%s\", \"ssid\":\"%s\", \"signalStrength\":%d}", hotspots->bssid, hotspots->ssid, hotspots->signal_strength);
            hbdbus_fire_event(conn, WIFISIGNALSTRENGTHCHANGED, signal);
        }

        // if scan ap, send WIFIHOTSPOTSCHANGED message
        memset(signal, 0, 4096);
        sprintf(signal, "\"changed\":[");

        memset(remove, 0, 4096);
        sprintf(remove, "\"missed\":[");

        memset(added, 0, 8192);
        sprintf(added, "\"found\":[");

        if(host == NULL)            // all is new ap
        {
            node = hotspots;
            for(i = 0; i < number; i++)
            {
                if(node != hotspots)
                    sprintf(added + strlen(added), ",");

                sprintf(added + strlen(added), 
                        "{"
                        "\"bssid\":\"%s\","
                        "\"ssid\":\"%s\","
                        "\"capabilities\":\"%s\","
                        "\"signalStrength\":%d"
                        "}",
                        node->bssid, node->ssid, node->capabilities, node->signal_strength);
                node = node->next;
            }
        }
        else
        {
            while(host)
            {
                node = hotspots;
                i = 0;
                while(node)
                {
                    if(strcmp((char *)host->bssid, (char *)node->bssid) == 0)
                    {
                        changedssid = false;
                        changedsignal = false;
                        changedcapabilities = false;

                        // signal
                        if(host->signal_strength != node->signal_strength)
                            changedsignal = true;
                        if(strcmp((char *)host->ssid, (char *)node->ssid))
                            changedssid = true;
                        if(strcmp((char *)host->capabilities, (char *)node->capabilities))
                            changedcapabilities = true;

                        if(changedssid || changedsignal || changedcapabilities)
                        {
                            if(bsignal)
                                sprintf(signal + strlen(signal), ",");
                            bsignal = true;

                            sprintf(signal + strlen(signal), 
                                    "{"
                                        "\"bssid\":\"%s\"",
                                    node->bssid);

                            if(changedsignal)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"signalStrength\":%d",
                                        node->signal_strength);

                            if(changedssid)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"ssid\":\"%s\"",
                                        node->ssid);

                            if(changedcapabilities)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"capabilities\":\"%s\"",
                                        node->capabilities);
                            sprintf(signal + strlen(signal), "}");
                        }

                        i = 1;                      // old ap is found in new ap list
                        node->isConnect = true;     // flag to indicate: it is not new hotspot 
                        break;
                    }
                    node = node->next;
                }

                if(i == 0)          // do not find in orignal list, it is removed
                {
                    if(bremove)
                        sprintf(remove + strlen(remove), ",");
                    bremove = true;
                    sprintf(remove + strlen(remove), 
                            "{"
                            "\"bssid\":\"%s\""
                            "}",
                            host->bssid);
                }
                host = host->next;
            }

            node = hotspots;
            host = wifi_device->first_hotspot;

            while(node)
            {
                if(!(node->isConnect))         // have been checked
                {
                    if(bnew)
                        sprintf(added + strlen(added), ",");
                    bnew = true;
                    sprintf(added + strlen(added), 
                            "{"
                            "\"bssid\":\"%s\","
                            "\"ssid\":\"%s\","
                            "\"capabilities\":\"%s\","
                            "\"signalStrength\":%d"
                            "}",
                            node->bssid, node->ssid, node->capabilities, node->signal_strength);
                }
                node->isConnect = false;
                node = node->next;
            }
        }

        memset(message, 0, 8192);
        sprintf(message, "{%s], %s], %s]}", added, remove, signal);
        hbdbus_fire_event(conn, WIFIHOTSPOTSCHANGED, message);

        free(signal);
        free(remove);
        free(added);
        free(message);

        if(hotspots && wifi_device->bssid[0] && strcmp((char *)wifi_device->bssid, (char *)hotspots->bssid) == 0)
            hotspots->isConnect = true;;

        // set hotspots list
        pthread_mutex_lock(&(wifi_device->list_mutex));
        node = wifi_device->first_hotspot;
        while(node)
        {
            tempnode = node->next;
            free(node);
            node = tempnode;
        }
        wifi_device->first_hotspot = hotspots;
        pthread_mutex_unlock(&(wifi_device->list_mutex));
    }
}
#endif

int register_wifi_interfaces(hbdbus_conn * conn)
{
    int errcode = 0;

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_START_SCAN,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiStartScanHotspots);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_START_SCAN, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_GET_HOTSPOTS,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiGetHotspotList);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_START_SCAN, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_STOP_SCAN,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiStopScanHotspots);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_STOP_SCAN, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_CONNECT_AP,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiConnect);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_CONNECT_AP, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_DISCONNECT_AP,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiDisconnect);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_DISCONNECT_AP, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_procedure(conn, METHOD_WIFI_GET_NETWORK_INFO,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS,
            wifiGetNetworkInfo);
    if (errcode) {
        LOG_ERROR("Error for register procedure %s: %s.\n",
                METHOD_WIFI_GET_NETWORK_INFO, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_event(conn, WIFIHOTSPOTSCHANGED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS);
    if (errcode) {
        LOG_ERROR("Error for register event %s: %s.\n",
                WIFIHOTSPOTSCHANGED, hbdbus_get_err_message(errcode));
        goto done;
    }

    errcode = hbdbus_register_event(conn, WIFISIGNALSTRENGTHCHANGED,
            HBDINETD_ALLOWED_HOSTS, HBDINETD_PRIVILEGED_APPS);
    if (errcode) {
        LOG_ERROR("Error for register event %s: %s.\n",
                WIFISIGNALSTRENGTHCHANGED, hbdbus_get_err_message(errcode));
        goto done;
    }

done:
    return errcode;
}

void revoke_wifi_interfaces(hbdbus_conn *conn)
{
    hbdbus_revoke_event(conn, WIFISIGNALSTRENGTHCHANGED);
    hbdbus_revoke_event(conn, WIFIHOTSPOTSCHANGED);

    hbdbus_revoke_procedure(conn, METHOD_WIFI_START_SCAN);
    hbdbus_revoke_procedure(conn, METHOD_WIFI_GET_HOTSPOTS);
    hbdbus_revoke_procedure(conn, METHOD_WIFI_STOP_SCAN);
    hbdbus_revoke_procedure(conn, METHOD_WIFI_CONNECT_AP);
    hbdbus_revoke_procedure(conn, METHOD_WIFI_DISCONNECT_AP);
    hbdbus_revoke_procedure(conn, METHOD_WIFI_GET_NETWORK_INFO);
}

