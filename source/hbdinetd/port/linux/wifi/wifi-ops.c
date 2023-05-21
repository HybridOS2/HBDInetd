/*
** wifi-ops.c -- The basic operators for wifi devices.
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

#include "network-device.h"
#include "wpa-supplicant-conf.h"
#include "wifi.h"
#include "event.h"
#include "helpers.h"

#include <unistd.h>
#include <errno.h>

#define US_100MS    100000

#if 0
    char *start = NULL;
    char *end = NULL;
    start = strstr(reply, "wpa_state=");
    if (start) {
        start += strlen("wpa_state=");
        end = strstr(start, "\n");
        if (end) {
            if (strncasecmp(start, "COMPLETED", strlen("COMPLETED"))) {
                errcode = ENONET;
                goto done;
            }
        }
        else {
            errcode = ENONET;
            goto done;
        }
    }
    else {
        errcode = ENONET;
        goto done;
    }

    // bssid
    start = strstr(end, "bssid=");
    if (start) {
        start += strlen("bssid=");
        end = strstr(start, "\n");
        if (end) {
            size_t len = end - start;
            pcutils_printbuf_strappend(pb, "\"bssid\":\"");
            pcutils_printbuf_memappend_fast(pb, start, len);
            pcutils_printbuf_strappend(pb, "\",");
        }
    }

    if (start == NULL || end == NULL) {
        pcutils_printbuf_strappend(pb, "\"bssid\":null,");
        goto done;
    }

    // frenquency
    start = strstr(end, "freq=");
    if (start) {
        start += strlen("freq=");
        end = strstr(start, "\n");
        if (end) {
            size_t len = end - start;
            pcutils_printbuf_strappend(pb, "\"frenquency\":\"");
            pcutils_printbuf_memappend_fast(pb, start, len);
            pcutils_printbuf_strappend(pb, " MHz\",");
        }
    }

    if (start == NULL || end == NULL) {
        pcutils_printbuf_strappend(pb, "\"frenquency\":null,");
        goto done;
    }

    // ssid
    start = strstr(end, "ssid=");
    if (start) {
        start += strlen("ssid=");
        end = strstr(start, "\n");
        if (end) {
            size_t len = end - start;
            pcutils_printbuf_strappend(pb, "\"ssid\":\"");
            pcutils_printbuf_memappend_fast(pb, start, len);
            pcutils_printbuf_strappend(pb, "\",");
        }
    }

    if (start == NULL || end == NULL) {
        pcutils_printbuf_strappend(pb, "\"ssid\":null,");
        goto done;
    }

    // encryptionType
    start = strstr(end, "key_mgmt=");
    if (start) {
        start += strlen("key_mgmt=");
        end = strstr(start, "\n");
        if (end) {
            size_t len = end - start;
            pcutils_printbuf_strappend(pb, "\"encryptionType\":\"");
            pcutils_printbuf_memappend_fast(pb, start, len);
            pcutils_printbuf_strappend(pb, "\",");
        }
    }

    if (start == NULL || end == NULL) {
        pcutils_printbuf_strappend(pb, "\"encryptionType\":null,");
        goto done;
    }
#endif

static int connect(struct netdev_context *ctxt,
        const char *ssid, const char *keymgmt, const char *password)
{
    (void)ctxt;
    (void)ssid;
    (void)keymgmt;
    (void)password;
    return 0;
}

static int disconnect(struct netdev_context *ctxt)
{
    (void)ctxt;
    return 0;
}

static int start_scan(struct netdev_context *ctxt)
{
    size_t len = WIFI_MSG_BUF_SIZE;
    int ret = wifi_command(ctxt, "SCAN", ctxt->buf, &len);
    if (ret) {
        HLOG_ERR("Failed to issue SCAN command to wpa_supplicant\n");
        return ERR_DEVICE_CONTROLLER;
    }

    return 0;
}

static int stop_scan(struct netdev_context *ctxt)
{
    (void)ctxt;
    return 0;
}

static const struct list_head *
get_hotspot_list_head(struct netdev_context *ctxt)
{
    return &ctxt->hotspots;
}

static const struct wifi_status *
get_status(struct netdev_context *ctxt)
{
    return ctxt->status;
}

static struct wifi_device_ops wifi_ops = {
    connect,
    disconnect,
    start_scan,
    stop_scan,
    get_hotspot_list_head,
    get_status,
};

static int get_id_len(struct kvlist *kv, const void *data)
{
    (void)kv;
    (void)data;
    return sizeof(int);
}

static struct netdev_context *netdev_context_new(void)
{
    struct netdev_context *ctxt = NULL;

    ctxt = calloc(1, sizeof(*ctxt));
    if (ctxt) {
        ctxt->buf = malloc(WIFI_MSG_BUF_SIZE);
        if (ctxt->buf == NULL) {
            free(ctxt);
            ctxt = NULL;
        }
    }

    if (ctxt) {
        init_list_head(&ctxt->hotspots);
        if (wifi_event_init(ctxt)) {
            free(ctxt->buf);
            free(ctxt);
            ctxt = NULL;
        }

        kvlist_init(&ctxt->saved_networks, get_id_len);
    }

    return ctxt;
}

static void netdev_context_delete(struct netdev_context *ctxt)
{
    kvlist_free(&ctxt->saved_networks);

    wifi_event_free(ctxt);

    wifi_reset_hotspots(&ctxt->hotspots);

    if (ctxt->ctrl_conn) {
        wifi_close_supplicant_connection(ctxt);
        wifi_stop_supplicant(ctxt);
    }

    free(ctxt->buf);
    free(ctxt);
}

int wifi_device_on(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;

    if (netdev->ctxt)
        return 0;

    netdev->ctxt = netdev_context_new();
    if (netdev->ctxt == NULL) {
        HLOG_ERR("Failed to allocate memory for WiFi device context!\n");
        return ENOMEM;
    }

    netdev->wifi_ops = &wifi_ops;
    int ret;
    if (netdev->status < DEVICE_STATUS_UP) {
        ret = netdev_config_iface_up(netdev->ifname, netdev);
        if (ret) {
            HLOG_ERR("Failed to make WiFi device up; you may consult `rfkill`!\n");
            return errno;
        }
    }

    netdev->ctxt->netdev = netdev;
    ret = wifi_connect_to_supplicant(netdev->ctxt);
    if (ret) {
        wifi_start_supplicant(netdev->ctxt, 0);

        unsigned nr_tries = 0;
        do {
            TEMP_FAILURE_RETRY(usleep(US_100MS * 2));
            ret = wifi_connect_to_supplicant(netdev->ctxt);
            if (ret == 0) {
                HLOG_INFO("Connected to wpa_supplicant!\n");
                break;
            }
            nr_tries++;
        } while (ret && nr_tries < 10);

        if (ret) {
            HLOG_ERR("Give up after 10 retries to connect to wpa_supplicant!\n");
        }
    }

    if (wpa_conf_load_saved_networks(netdev->ctxt)) {
        goto failed;
    }

    return 0;

failed:
    netdev_context_delete(netdev->ctxt);
    netdev->ctxt = NULL;
    return ERR_DEVICE_CONTROLLER;
}

int wifi_device_off(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;

    if (netdev->ctxt == NULL || netdev->ctxt->ctrl_conn == NULL)
        return EPERM;

    int ret;

    netdev_context_delete(netdev->ctxt);
    netdev->ctxt = NULL;

    ret = netdev_config_iface_down(netdev->ifname, netdev);
    if (ret) {
        HLOG_ERR("Failed to make WiFi device down!\n");
        return errno;
    }

    return 0;
}

int wifi_device_check(hbdbus_conn *conn, struct network_device *netdev)
{
    if (netdev->ctxt == NULL)
        return EPERM;

    do {
       int ret = wpa_ctrl_pending(netdev->ctxt->monitor_conn);
       if (ret == 0) {
           break;
       }
       else if (ret < 0) {
           return ECONNRESET;
       }
       else if (ret > 0) {
           int bytes = wifi_wait_for_event(netdev->ctxt, netdev->ctxt->buf,
                       WIFI_MSG_BUF_SIZE);
           if (bytes == 0)
               break;
           else if (bytes < 0)
               return ECONNRESET;

           wifi_event_handle_message(conn, netdev->ctxt, netdev->ctxt->buf,
                   bytes);
       }
    } while (true);

    return 0;
}

