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

#include <unistd.h>
#include <errno.h>

enum {
    SCAN_STATE_STOPPED = 0,
    SCAN_STATE_SCANNING,
};

enum {
    CONN_STATE_DISCONNECTED = 0,
    CONN_STATE_TRYING,
    CONN_STATE_CONNECTED,
};

struct wifi_hotspot_candidate {
    const char *bssid;
    const char *ssid;
    const char *capabilities;
    unsigned int frequency;
    int signal_level;

    unsigned    found:1;
    unsigned    saved:1;
};

struct netdev_context {
    struct network_device *netdev;

    enum wpa_state wpa_state;

    /* the next netid */
    int next_netid;

    /* the new network id if >= 0. */
    int new_netid;

    /* the trying netid */
    const struct wifi_hotspot_candidate *trying;

    time_t last_update_time;
    time_t scan_start_time;

    struct list_head hotspots;
    struct kvlist saved_networks;
    struct wifi_status *status;
};

void wifi_release_one_hotspot(struct wifi_hotspot *one)
{
    if (one->bssid)
        free(one->bssid);
    if (one->ssid)
        free(one->ssid);
    if (one->capabilities)
        free(one->capabilities);
    if (one->escaped_ssid)
        free(one->escaped_ssid);
    free(one);
}

void wifi_reset_hotspots(struct list_head *hotspots)
{
    struct list_head *p, *n;
    list_for_each_safe(p, n, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);
        list_del(&hotspot->ln);
        wifi_release_one_hotspot(hotspot);
    }
}

struct wifi_hotspot *
wifi_get_hotspot_by_bssid(struct netdev_context *ctxt, const char *bssid)
{
    struct list_head *p;
    list_for_each(p, &ctxt->hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        if (strcmp(bssid, hotspot->bssid) == 0) {
            return hotspot;
        }
    }

    return NULL;
}

struct wifi_hotspot *
wifi_get_hotspot_by_ssid(struct netdev_context *ctxt, const char *ssid)
{
    struct list_head *p;
    list_for_each(p, &ctxt->hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        if (strcmp(ssid, hotspot->ssid) == 0) {
            return hotspot;
        }
    }

    return NULL;
}

int wifi_get_netid_from_ssid(struct netdev_context *ctxt, const char *ssid)
{
    void *data = kvlist_get(&ctxt->saved_networks, ssid);
    if (data) {
        return *(int *)data;
    }

    return -1;
}

void wifi_reset_status(struct netdev_context *ctxt)
{
    if (ctxt->status) {
        for (size_t i = 0; i < WIFI_STATUS_STRING_FIELDS; i++) {
            if (ctxt->status->fields[i]) {
                free(ctxt->status->fields[i]);
            }
        }

        memset(ctxt->status, 0, sizeof(*ctxt->status));
        ctxt->status->netid = -1;
    }
}

const char *
wifi_get_keymgmt_from_capabilities(const struct wifi_hotspot *hotspot)
{
    if (strstr(hotspot->capabilities, "WPA2-PSK"))
        return "WPA-PSK";
    else if (strstr(hotspot->capabilities, "WPA-PSK"))
        return "WPA-PSK";
    else if (strstr(hotspot->capabilities, "WPA2"))
        return "WPA-PSK";
    else if (strstr(hotspot->capabilities, "WPA"))
        return "WPA-PSK";
    else if (strstr(hotspot->capabilities, "WEP"))
        return "WEP";
    else if (strstr(hotspot->capabilities, "NONE"))
        return "NONE";

    return NULL;
}

int wifi_update_status(struct netdev_context *ctxt)
{
    if (ctxt->status == NULL) {
        ctxt->status = calloc(1, sizeof(*ctxt->status));
        if (ctxt->status == NULL) {
            HLOG_ERR("Failed allocating WiFi status structure\n");
            return -1;
        }
    }
    else
        wifi_reset_status(ctxt);

    if (ctxt->wpa_state > WPA_STATE_SCANNING) {
        ctxt->status->bssid = strdup(ctxt->trying->bssid);
        ctxt->status->ssid = strdup(ctxt->trying->ssid);
        ctxt->status->escaped_ssid =
            pcutils_escape_string_for_json(ctxt->status->ssid);
        ctxt->status->wpa_state = ctxt->wpa_state;

        if (ctxt->wpa_state == WPA_STATE_COMPLETED) {
            ctxt->status->netid = wifi_get_netid_from_ssid(ctxt,
                    ctxt->status->ssid);
        }

        ctxt->status->hotspot =
            wifi_get_hotspot_by_bssid(ctxt, ctxt->status->bssid);
        if (ctxt->status->hotspot == NULL) {
            HLOG_ERR("BSS %s is not in the hotspot list\n", ctxt->status->bssid);
        }
        else {
            ctxt->status->key_mgmt = strdup(
                    wifi_get_keymgmt_from_capabilities(ctxt->status->hotspot));
        }
    }

    return 0;
}

static int connect(struct netdev_context *ctxt,
        const char *ssid, const char *bssid,
        const char *keymgmt, const char *passphrase)
{
    int ret;

    if (ctxt->new_netid >= 0) {
        return ERR_UNRESOLVED_ATTEMPT;
    }

    if (keymgmt != NULL &&
            (ret = check_wpa_passphrase(keymgmt, passphrase))) {
        return ret;
    }

    if (ctxt->status) {
        if (bssid) {
            if (ctxt->status->bssid &&
                    strcmp(ctxt->status->bssid, bssid) == 0) {
                /* already connected */
                return 0;
            }
        }
        else if (ctxt->status->ssid &&
                strcmp(ctxt->status->ssid, ssid) == 0) {
            /* already connected */
            return 0;
        }
    }

    return ERR_UNCERTAIN_RESULT;
}

static int disconnect(struct netdev_context *ctxt)
{
    if (ctxt->status == NULL || ctxt->status->bssid == NULL) {
        /* not connected */
        return 0;
    }
    return 0;
}

static struct wifi_hotspot_candidate candidates[] = {
    { "00:09:5b:95:e0:40", "HybridOS",                  "[WPA-PSK-CCMP]",  2412, 0, 0, 0 },
    { "00:09:5b:95:e0:41", "HybridOS 1",                "[WPA2-PSK-CCMP]", 2412, 0, 0, 0 },
    { "00:09:5b:95:e0:42", "HybridOS 2",                "[WPA-PSK-CCMP]",  2412, 0, 0, 0 },
    { "02:55:24:33:77:a0", "testing 0",                 "[WPA2-PSK-TKIP]", 5766, 0, 0, 0 },
    { "02:55:24:33:77:a1", "testing 1",                 "[WPA-PSK-TKIP]",  2462, 0, 0, 0 },
    { "02:55:24:33:77:a2", "testing 2",                 "[WPA2-PSK-TKIP]", 2462, 0, 0, 0 },
    { "02:55:24:33:77:a3", "testing 3",                 "[WEP]",  2462, 0, 0, 0 },
    { "02:55:24:33:77:a4", "testing 5",                 "[WPA2-PSK-TKIP]", 5830, 0, 0, 0 },
    { "00:09:5b:95:e0:40", "合璧操作系统",              "[WPA-PSK-TKIP]",  2412, 0, 0, 0 },
    { "00:09:5b:95:e0:41", "测 试 UTF-8",               "[WPA2-PSK-TKIP]", 2412, 0, 0, 0 },
    { "00:09:5b:95:e0:42", "testing 2",                 "[WPA-PSK-TKIP]",  2412, 0, 0, 0 },
    { "00:09:5b:95:e0:43", "My Private",                "[WPA2-PSK-TKIP]", 2412, 0, 0, 0 },
    { "00:09:5b:95:e0:44", "Guest",                     "[NONE]",  2412, 0, 0, 0 },
    { "00:09:5b:95:e0:45", "\"Tom\" and \"Jerry\"",     "[WPA2-PSK-TKIP]", 5348, 0, 0, 0 },
};

static int start_scan(struct netdev_context *ctxt)
{
    /* generate a random hotspot list */
    unsigned found = 0;
    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if ((random() % 2) == 0) {
            struct wifi_hotspot *one = NULL;

            one = calloc(1, sizeof(*one));
            one->bssid = strdup(candidates[i].bssid);
            one->frequency = candidates[i].frequency;
            one->signal_level = -(random() % 100);
            one->capabilities = strdup(candidates[i].capabilities);

            one->ssid = strdup(candidates[i].ssid);
            one->escaped_ssid = pcutils_escape_string_for_json(one->ssid);
            one->netid = wifi_get_netid_from_ssid(ctxt, one->ssid);
            list_add_tail(&one->ln, &ctxt->hotspots);

            candidates[i].found = 1;
            found++;
        }
    }

    HLOG_INFO("Found %u hotspots\n", found);
    return 0;
}

static int stop_scan(struct netdev_context *ctxt)
{
    (void)ctxt;
    return 0;
}

static const struct list_head *
get_hotspot_list(struct netdev_context *ctxt, int *curr_netid)
{
    if (curr_netid)
        *curr_netid = ctxt->status->netid;

    return &ctxt->hotspots;
}

static const struct wifi_status *
get_status(struct netdev_context *ctxt)
{
    // TODO: wifi_update_status(ctxt);
    return ctxt->status;
}

static struct wifi_device_ops wifi_ops = {
    connect,
    disconnect,
    start_scan,
    stop_scan,
    get_hotspot_list,
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
        init_list_head(&ctxt->hotspots);
        kvlist_init(&ctxt->saved_networks, get_id_len);
    }

    ctxt->new_netid = -1;

    return ctxt;
}

static void netdev_context_delete(struct netdev_context *ctxt)
{
    wifi_reset_status(ctxt);
    if (ctxt->status)
        free(ctxt->status);

    kvlist_free(&ctxt->saved_networks);
    wifi_reset_hotspots(&ctxt->hotspots);
    free(ctxt);
}

int wifi_device_on(hbdbus_conn *conn, struct network_device *netdev)
{
    if (netdev->ctxt) {
        HLOG_WARN("The WiFi device %s is already on!\n", netdev->ifname);
        return 0;
    }

    netdev->ctxt = netdev_context_new();
    if (netdev->ctxt == NULL) {
        HLOG_ERR("Failed to allocate memory for WiFi device context!\n");
        return ENOMEM;
    }
    netdev->ctxt->netdev = netdev;

    netdev->wifi_ops = &wifi_ops;
    int ret;
    if (netdev->status < DEVICE_STATUS_UP) {
        ret = netdev_config_iface_up(netdev->ifname, netdev);
        if (ret) {
            HLOG_ERR("Failed to make WiFi device up; you may consult `rfkill`!\n");
            ret = errno;
            goto failed;
        }
    }

    srandom(time(NULL));

    netdev->ctxt->next_netid = 0;
    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {

        if ((random() % 10) == 0) {
            candidates[i].saved = 1;
            kvlist_set(&netdev->ctxt->saved_networks, candidates[i].ssid,
                    &netdev->ctxt->next_netid);
            netdev->ctxt->next_netid++;
        }
    }

    HLOG_INFO("Loaded saved networks; next netid: %d!\n", netdev->ctxt->next_netid);
    if (register_wifi_interfaces(conn)) {
        ret = ERR_DATA_BUS;
        goto failed;
    }

    HLOG_INFO("Switch %s on successfully!\n", netdev->ifname);
    return 0;

failed:
    netdev_context_delete(netdev->ctxt);
    netdev->ctxt = NULL;
    return ret;
}

int wifi_device_off(hbdbus_conn *conn, struct network_device *netdev)
{
    if (netdev->ctxt == NULL)
        return ENOENT;

    revoke_wifi_interfaces(conn);

    netdev_context_delete(netdev->ctxt);
    netdev->ctxt = NULL;

    int ret = netdev_config_iface_down(netdev->ifname, netdev);
    if (ret) {
        HLOG_ERR("Failed to make WiFi device down!\n");
        return errno;
    }

    HLOG_INFO("Switch %s off successfully!\n", netdev->ifname);
    return 0;
}

int wifi_device_check(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;
    if (netdev->ctxt == NULL)
        return EPERM;

    return 0;
}

void wifi_device_terminate(struct network_device *netdev)
{
    if (netdev->ctxt == NULL)
        return;

    wifi_reset_status(netdev->ctxt);
    if (netdev->ctxt->status)
        free(netdev->ctxt->status);

    kvlist_free(&netdev->ctxt->saved_networks);

    wifi_reset_hotspots(&netdev->ctxt->hotspots);

    free(netdev->ctxt);
    netdev->ctxt = NULL;
}

