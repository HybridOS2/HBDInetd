/*
** event.c -- The event handlers for wpa_supplicant.
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
#include "wifi.h"
#include "event.h"
#include "helpers.h"

#include <unistd.h>
#include <errno.h>

typedef int (*event_handler)(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len);

static int on_connected(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)data;
    (void)len;

    int ret;
    ret = wifi_update_status(ctxt);
    if (ret) {
        HLOG_ERR("Failed when updating status\n");
        goto fatal;
    }

    /* Save config */
    if (ctxt->new_netid >= 0) {
        size_t len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, "SAVE_CONFIG", ctxt->buf, &len)) {
            HLOG_WARN("Failed to save config\n");
        }
        ctxt->new_netid = -1;
    }

    /* TODO: Issue DHCP request */

    if (ctxt->status && ctxt->status->bssid) {
        struct pcutils_printbuf my_buff, *pb = &my_buff;
        if (pcutils_printbuf_init(pb)) {
            HLOG_ERR("Failed when initializing print buffer\n");
            goto fatal;
        }

        pcutils_printbuf_format(pb,
                "{\"bssid\":\"%s\","
                "\"ssid\":\"%s\","
                "\"signalLevel\":%d}",
                  ctxt->status->bssid,
                  ctxt->status->escaped_ssid ? ctxt->status->escaped_ssid :
                    ctxt->status->ssid,
                  ctxt->status->signal_level);

        ret = hbdbus_fire_event(conn, BUBBLE_WIFICONNECTED, pb->buf);
        free(pb->buf);
        if (ret)
            goto fatal;
    }
    else {
        ret = hbdbus_fire_event(conn, BUBBLE_WIFICONNECTED,
                "{\"bssid\":null,\"ssid\":null,\"signalLevel\":null}");
        if (ret)
            goto fatal;
    }

    // TODO: start dhclient to fetch addresses.
    return 0;

fatal:
    if (ret) {
        HLOG_ERR("Failed when firing event: %s\n", BUBBLE_WIFICONNECTED);
    }

    return ret;
}

static int on_disconnected(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)data;
    (void)len;

    int ret;
    if (ctxt->status && ctxt->status->bssid) {
        struct pcutils_printbuf my_buff, *pb = &my_buff;
        if (pcutils_printbuf_init(pb)) {
            HLOG_ERR("Failed when initializing print buffer\n");
            goto fatal;
        }

        pcutils_printbuf_format(pb,
                "{\"bssid\":\"%s\",\"ssid\":\"%s\"}",
                  ctxt->status->bssid,
                  ctxt->status->escaped_ssid ? ctxt->status->escaped_ssid :
                    ctxt->status->ssid);
        ret = hbdbus_fire_event(conn, BUBBLE_WIFIDISCONNECTED, pb->buf);
        free(pb->buf);
        if (ret)
            goto fatal;
    }
    else {
        ret = hbdbus_fire_event(conn, BUBBLE_WIFIDISCONNECTED,
                "{\"bssid\":null,\"ssid\":null}");
        if (ret)
            goto fatal;
    }

    wifi_reset_status(ctxt);
    return 0;

fatal:
    if (ret) {
        HLOG_ERR("Failed when firing event: %s\n", BUBBLE_WIFIDISCONNECTED);
    }

    return ret;
}

static int on_scan_results(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)data;
    (void)len;

    size_t reply_len = WIFI_MSG_BUF_SIZE;
    int ret = wifi_command(ctxt, "SCAN_RESULTS", ctxt->buf, &reply_len);
    if (ret) {
        HLOG_ERR("Failed when getting scan results: %d\n", ret);
        goto failed;
    }

    if (wifi_parse_scan_results(&ctxt->hotspots, ctxt->buf, reply_len)) {
        HLOG_ERR("Failed when parsing scan results\n");
        goto failed;
    }

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        HLOG_ERR("Failed when initializing print buffer\n");
        goto fatal;
    }

    pcutils_printbuf_strappend(pb, "{\"success\":true,\"hotspots\":[");
    print_hotspot_list(&ctxt->hotspots, ctxt->status->netid, pb);
    pcutils_printbuf_strappend(pb, "]");

    ret = hbdbus_fire_event(conn, BUBBLE_WIFISCANFINISHED, pb->buf);
    free(pb->buf);
    if (ret) {
        goto fatal;
    }
    return 0;

failed:
    ret = hbdbus_fire_event(conn, BUBBLE_WIFISCANFINISHED,
            "{\"success\":false,\"hotspots\":null}");

fatal:
    if (ret) {
        HLOG_ERR("Failed when firing event: %s\n", BUBBLE_WIFISCANFINISHED);
    }

    return ret;
}

/* event data format:
   <bss-entry-id> <bssid>
   34 00:11:22:33:44:55 */
static int on_bss_added(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)len;

    const char *bssid;
    bssid = strrchr(data, ' ');
    if (bssid == NULL)
        goto bad_data;

    struct wifi_hotspot *hotspot, *newone = NULL;
    hotspot = wifi_get_hotspot_by_bssid(ctxt, bssid);
    if (hotspot == NULL) {
        hotspot = newone = calloc(1, sizeof(*newone));
        if (hotspot == NULL) {
            HLOG_ERR("Failed to allocate memory for new hotspot\n");
            goto failed;
        }
    }

    if (wifi_update_hotspot_by_bssid(ctxt, hotspot, bssid)) {
        goto failed;
    }

    if (newone) {
        list_add_tail(&newone->ln, &ctxt->hotspots);
        newone = NULL;

        struct pcutils_printbuf my_buff, *pb = &my_buff;
        if (pcutils_printbuf_init(pb)) {
            HLOG_ERR("Failed when initializing print buffer\n");
            goto failed;
        }

        print_one_hotspot(newone, ctxt->status->netid, pb);

        hbdbus_fire_event(conn, BUBBLE_WIFIHOTSPOTFOUND, pb->buf);
        free(pb->buf);
    }

    return 0;

bad_data:
    HLOG_WARN("Bad event data: %s\n", data);
failed:
    if (newone)
        wifi_release_one_hotspot(newone);
    return -1;
};

static int on_bss_removed(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)len;

    const char *bssid;
    bssid = strrchr(data, ' ');
    if (bssid == NULL)
        goto bad_data;

    struct wifi_hotspot *hotspot;
    hotspot = wifi_get_hotspot_by_bssid(ctxt, bssid);
    if (hotspot) {
        if (hotspot->netid >= 0 && ctxt->status->netid) {
            wifi_update_status(ctxt);
        }

        list_del(&hotspot->ln);
        wifi_release_one_hotspot(hotspot);
    }
    else {
        HLOG_WARN("BSS (%s) is not recorded\n", bssid);
    }

    /* It's safe to reuse the buffer in context */
    sprintf(ctxt->buf, "{\"bssid\": \"%s\"}", bssid);
    hbdbus_fire_event(conn, BUBBLE_WIFIHOTSPOTLOST, ctxt->buf);
    return 0;

bad_data:
    HLOG_WARN("Bad event data: %s\n", data);
    return -1;
};

/* event data format:
    id=%d ssid="%s" auth_failures=%u duration=%d reason=%s */
static int on_ssid_temp_disabled(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)len;
    int netid;
    int ret;

    const char *p = strchr(data, '=');
    if (p == NULL) {
        goto bad_data;
    }

    netid = atoi(p);
    if (netid < 0) {
        goto bad_data;
    }

    const char *start_ssid = strchr(data, '"');
    const char *end_ssid = strrchr(data, '"');
    if (start_ssid == NULL || end_ssid == NULL || end_ssid == start_ssid) {
        goto bad_data;
    }

    start_ssid += 1;
    char *escaped_ssid = strndup(start_ssid, end_ssid - start_ssid);
    size_t my_len = strlen(escaped_ssid);
    char *ssid = ctxt->buf;
    if (unescape_literal_text(escaped_ssid, my_len, ssid) < 0) {
        goto bad_data;
    }
    free(escaped_ssid);
    escaped_ssid = pcutils_escape_string_for_json(ssid);

    const char *reason = strrchr(data, '=');
    if (reason == NULL) {
        goto bad_data;
    }
    reason++;

    /* 1) Fire WiFiFaileConnAttempt event. */
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    if (pcutils_printbuf_init(pb)) {
        HLOG_ERR("Failed when initializing print buffer\n");
        goto failed;
    }

    pcutils_printbuf_format(pb,
            "{\"ssid\":\"%s\","
            "\"reason\":\"%s\"}",
            escaped_ssid, reason);

    ret = hbdbus_fire_event(conn, BUBBLE_WIFIFAILEDCONNATTEMPT, pb->buf);
    free(pb->buf);

    if (escaped_ssid)
        free(escaped_ssid);

    /* 2) If the network is newly added, remove it. */
    if (ctxt->new_netid >= 0) {
        wifi_remove_network(ctxt, ctxt->new_netid);
        ctxt->new_netid = -1;
    }

    return ret;

bad_data:
    HLOG_WARN("Bad event data: %s\n", data);
failed:
    if (escaped_ssid)
        free(escaped_ssid);
    return -1;
}

static int on_terminating(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)conn;
    (void)ctxt;
    (void)data;
    (void)len;

    HLOG_WARN("WAP terminated, turn off the device: %s\n", ctxt->netdev->ifname);
    wifi_device_off(conn, ctxt->netdev);
    return 0;
}

static int on_eap_failure(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)conn;
    (void)ctxt;
    (void)data;
    (void)len;

    /* TODO */
    HLOG_WARN("called, but not implemented\n");
    return 0;
}

static int on_assoc_reject(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *data, int len)
{
    (void)conn;
    (void)ctxt;
    (void)data;
    (void)len;

    /* TODO */
    HLOG_WARN("called, but not implemented\n");
    return 0;
}

static const struct event_handler {
    const char *name;
    event_handler handler;
} event_handlers[] = {
    { "CONNECTED", on_connected },
    { "DISCONNECTED", on_disconnected },
    { "SCAN-RESULTS", on_scan_results },
    { "BSS-ADDED", on_bss_added },
    { "BSS-REMOVED", on_bss_removed },
    { "SSID-TEMP-DISABLED", on_ssid_temp_disabled },
    { "TERMINATING", on_terminating },
    { "EAP-FAILURE", on_eap_failure },
    { "ASSOC-REJECT", on_assoc_reject },
};

int wifi_event_init(struct netdev_context *ctxt)
{
    kvlist_init(&ctxt->event_handlers, NULL);

    for (size_t i = 0; i < PCA_TABLESIZE(event_handlers); i++) {
        if (!kvlist_set(&ctxt->event_handlers, event_handlers[i].name,
                &event_handlers[i].handler)) {
            goto failed;
        }
    }

    return 0;

failed:
    kvlist_free(&ctxt->event_handlers);
    return -1;
}

void wifi_event_free(struct netdev_context *ctxt)
{
    kvlist_free(&ctxt->event_handlers);
}

int wifi_event_handle_message(hbdbus_conn *conn,
        struct netdev_context *ctxt, const char *msg, int len)
{
    if (msg[0] == '\0')
        return 0;

    if (strncmp(msg, "WPA:", 4) == 0) {
        if (strstr(msg, "pre-shared key may be incorrect")) {
            HLOG_WARN("pre-shared key\n");

#if 0
            ctxt->auth_failure_count++;
            if (ctxt->auth_failure_count >= MAX_RETRIES_ON_AUTH_FAILURE) {

                size_t len = WIFI_MSG_BUF_SIZE;
                wifi_command(ctxt, "DISCONNECT", ctxt->buf, &len);
                // TODO:

                ctxt->auth_failure_count = 0;
            }
#endif
        }
    }
    else if (strncmp(msg, "CTRL-EVENT-", 11) == 0) {
        const char *event_start = msg + 11;
        const char *event_end = strchr(event_start, ' ');
        int left = len - 11;

        if (event_end) {
            size_t event_len = event_end - event_start;
            char *event_name = strndup(event_start, event_len);

            left -= event_len;
            void *data = kvlist_get(&ctxt->event_handlers, event_name);

            event_handler handler = NULL;
            if (data == NULL) {
                HLOG_WARN("Unknown event name: %s\n", event_name);
            }
            else {
                handler = *(event_handler *)data;
                if (handler) {
                    left--;
                }
                else {
                    HLOG_WARN("Ignore event: %s\n", event_name);
                }
            }

            free(event_name);
            if (handler)
                return handler(conn, ctxt, event_end + 1, left);
        }
        else {
            HLOG_WARN("Bad event message: %s\n", msg);
        }
    }

    return 0;
}

