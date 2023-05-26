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
#include <assert.h>

struct wifi_hotspot_candidate {
    const char *bssid;
    const char *ssid;
    const char *capabilities;
    unsigned int frequency;
    int signal_level;

    int  netid;

    bool found;
};

enum scan_state {
    SCAN_STATE_IDLE = 0,
    SCAN_STATE_SCANNING,
};

struct netdev_context {
    hbdbus_conn *conn;
    struct network_device *netdev;

    enum scan_state scan_state;
    enum wpa_state wpa_state;

    /* the next netid */
    int next_netid;

    /* the new network id if >= 0. */
    int new_netid;

    /* the hotspot trying to connect */
    const struct wifi_hotspot_candidate *trying;
    char *passphrase;

    unsigned evt_connected:1;
    unsigned evt_disconnected:1;

    time_t last_update_time;
    time_t scan_start_time;

    struct list_head hotspots;
    struct kvlist saved_networks;
    struct wifi_status *status;
};

/* PSK or key for all hotspots is: `HybridOS 2.0` */
#define MY_PASSPHRASE "HybridOS 2.0"

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

static int my_check_network(const struct wifi_hotspot_candidate *candidate,
        const char *keymgmt, const char *passphrase)
{
    (void)passphrase;
    if (keymgmt == NULL)
        return -1;

    const char *my_keymgmt = NULL;
    if (strstr(candidate->capabilities, "WPA2-PSK"))
        my_keymgmt = "WPA-PSK";
    else if (strstr(candidate->capabilities, "WPA-PSK"))
        my_keymgmt = "WPA-PSK";
    else if (strstr(candidate->capabilities, "WPA2"))
        my_keymgmt = "WPA-PSK";
    else if (strstr(candidate->capabilities, "WPA"))
        my_keymgmt = "WPA-PSK";
    else if (strstr(candidate->capabilities, "WEP"))
        my_keymgmt = "WEP";
    else if (strstr(candidate->capabilities, "NONE"))
        my_keymgmt = "NONE";

    if (my_keymgmt && strcmp(my_keymgmt, keymgmt) == 0)
        return 0;

    return -1;
}

int wifi_check_network(struct netdev_context *ctxt, int netid,
        const char *ssid, const char *keymgmt, const char *passphrase)
{
    (void)ctxt;

    if (netid < 0)
        return -1;

    struct wifi_hotspot_candidate *candidate = NULL;
    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if (candidates[i].netid == netid) {
            candidate = candidates + i;
            break;
        }
    }

    if (candidate == NULL) {
        return -1;
    }

    assert(strcmp(candidate->ssid, ssid) == 0);
    return my_check_network(candidate, keymgmt, passphrase);
}

int wifi_add_network(struct netdev_context *ctxt, const char *ssid,
        const char *keymgmt, const char *passphrase)
{
    struct wifi_hotspot_candidate *candidate = NULL;

    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if (strcmp(ssid, candidates[i].ssid) == 0) {
            candidate = candidates + i;
            break;
        }
    }

    if (candidate == NULL) {
        return -1;
    }

    assert(candidate->netid == -1);

    if (my_check_network(candidate, keymgmt, passphrase))
        return -1;

    candidate->netid = ctxt->next_netid;
    ctxt->next_netid++;
    kvlist_set(&ctxt->saved_networks, ssid, &candidate->netid);
    return 0;
}

int wifi_select_network(struct netdev_context *ctxt, int netid)
{
    assert(netid >= 0);

    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if (candidates[i].netid == netid) {
            ctxt->trying = candidates + i;
            return 0;
        }
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

static int disconnect(struct netdev_context *ctxt);

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

    int netid = wifi_get_netid_from_ssid(ctxt, ssid);
    if (keymgmt == NULL) {
        if (netid >= 0) {   /* if it is a saved network */
            goto select;
        }

        const struct wifi_hotspot *hotspot;
        hotspot = wifi_get_hotspot_by_ssid(ctxt, ssid);
        if (hotspot == NULL) {
            HLOG_ERR("No key_mgmt specified and `%s` not found.\n", ssid);
            return ENOENT;
        }
        keymgmt = wifi_get_keymgmt_from_capabilities(hotspot);

        if (keymgmt == NULL) {
            HLOG_ERR("Can not get key_mgmt from capabilities: %s.\n",
                    hotspot->capabilities);
            return ENOTSUP;
        }

        netid = wifi_add_network(ctxt, ssid, keymgmt, passphrase);
        if (netid < 0) {
            HLOG_ERR("Failed to add new network: %s (key_mgmt: %s)\n",
                    ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }
    }
    else if (netid >= 0) {
        if (wifi_check_network(ctxt, netid, ssid, keymgmt, passphrase)) {
            HLOG_ERR("Failed to update network: %d) %s (key_mgmt: %s)\n",
                    netid, ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }
    }
    else {
        netid = wifi_add_network(ctxt, ssid, keymgmt, passphrase);
        if (netid < 0) {
            HLOG_ERR("Failed to add new network: %s (key_mgmt: %s)\n",
                    ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }

        ctxt->new_netid = netid;
    }

    if (ctxt->status && ctxt->status->bssid) {
        disconnect(ctxt);
    }

select:
    ctxt->wpa_state = WPA_STATE_SCANNING;
    wifi_select_network(ctxt, netid);

    unsigned count = 30;    /* total 3s */
    do {
        TEMP_FAILURE_RETRY(usleep(100000)); // 0.1s

        if (random() % 30 == count) {
            if (strcmp(keymgmt, "NONE")) {
                ctxt->wpa_state = WPA_STATE_AUTHENTICATING;
                break;
            }
            else {
                ctxt->wpa_state = WPA_STATE_COMPLETED;
                break;
            }
        }

    } while (--count);

    wifi_update_status(ctxt);

    if (ctxt->wpa_state == WPA_STATE_COMPLETED) {
        ctxt->evt_connected = 1;
        return 0;
    }
    else if (ctxt->wpa_state == WPA_STATE_AUTHENTICATING) {
        if (strcmp(passphrase, MY_PASSPHRASE))
            return ERR_WPA_WRONG_PASSPHRASE;
    }
    else if (ctxt->wpa_state == WPA_STATE_SCANNING) {
        ctxt->passphrase = strdup(passphrase);
    }

    return ERR_UNCERTAIN_RESULT;
}

static int disconnect(struct netdev_context *ctxt)
{
    if (ctxt->status == NULL || ctxt->status->bssid == NULL) {
        /* not connected */
        return 0;
    }

    ctxt->wpa_state = WPA_STATE_DISCONNECTED;
    ctxt->evt_disconnected = 1;
    wifi_reset_status(ctxt);
    return 0;
}

static int start_scan(struct netdev_context *ctxt)
{
    if (ctxt->scan_state == SCAN_STATE_SCANNING)
        return 0;

    ctxt->scan_state = SCAN_STATE_SCANNING;

    wifi_reset_hotspots(&ctxt->hotspots);
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

            candidates[i].found = true;
            found++;
        }
    }

    HLOG_INFO("Found %u hotspots\n", found);
    return 0;
}

static int stop_scan(struct netdev_context *ctxt)
{
    if (ctxt->scan_state == SCAN_STATE_IDLE)
        return 0;

    ctxt->scan_state = SCAN_STATE_IDLE;
    wifi_reset_hotspots(&ctxt->hotspots);
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
    netdev->ctxt->conn = conn;
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
            candidates[i].netid = netdev->ctxt->next_netid;
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

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);

    struct netdev_context *ctxt = netdev->ctxt;

    const char *evt = NULL;
    if (ctxt->wpa_state == WPA_STATE_SCANNING) {
        ctxt->wpa_state = WPA_STATE_AUTHENTICATING;
    }
    else if (ctxt->wpa_state == WPA_STATE_AUTHENTICATING) {
        if (strcmp(ctxt->passphrase, MY_PASSPHRASE)) {
            evt = BUBBLE_WIFIFAILEDCONNATTEMPT;

            char *escaped_ssid;
            escaped_ssid = pcutils_escape_string_for_json(ctxt->trying->ssid);
            pcutils_printbuf_format(pb,
                    "{\"ssid\":\"%s\","
                    "\"reason\":\"%s\"}",
                    escaped_ssid, "BAD-KEY");
            free(escaped_ssid);

            if (ctxt->new_netid >= 0) {
                kvlist_remove(&ctxt->saved_networks, ctxt->trying->ssid);
                ctxt->new_netid = -1;
            }
        }
        else {
            ctxt->wpa_state = WPA_STATE_COMPLETED;
            ctxt->evt_connected = 1;
        }

        free(ctxt->passphrase);
    }
    else if (ctxt->evt_disconnected &&
            ctxt->wpa_state == WPA_STATE_DISCONNECTED) {
        ctxt->evt_disconnected = 0;
        evt = BUBBLE_WIFIDISCONNECTED;
        pcutils_printbuf_format(pb,
                "{\"bssid\":\"%s\",\"ssid\":\"%s\"}",
                ctxt->status->bssid,
                ctxt->status->escaped_ssid ? ctxt->status->escaped_ssid :
                ctxt->status->ssid);

    }
    else if (ctxt->evt_connected && ctxt->wpa_state == WPA_STATE_COMPLETED) {
        ctxt->evt_connected = 0;
        evt = BUBBLE_WIFICONNECTED;
        pcutils_printbuf_format(pb,
                "{\"bssid\":\"%s\","
                "\"ssid\":\"%s\","
                "\"signalLevel\":%d}",
                  ctxt->status->bssid,
                  ctxt->status->escaped_ssid ? ctxt->status->escaped_ssid :
                    ctxt->status->ssid,
                  ctxt->status->signal_level);
    }

    if (evt) {
        if (pb->buf) {
            int ret = hbdbus_fire_event(ctxt->conn, evt, pb->buf);
            free(pb->buf);
            if (ret) {
                HLOG_ERR("Failed when firing event: %s\n", evt);
                return ERR_DATA_BUS;
            }
        }
        else {
            HLOG_ERR("OOM when using printbuf\n");
            return ENOMEM;
        }
    }

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

