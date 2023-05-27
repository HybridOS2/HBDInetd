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
    int netid;
    bool found;
};

struct netdev_context {
    hbdbus_conn *conn;
    struct network_device *netdev;

    time_t scan_start_time;
    time_t start_trying_time;
    time_t last_update_time;

    /* wap state */
    enum wpa_state wpa_state;

    /* the next netid */
    int next_netid;

    /* the new network id if >= 0. */
    int new_netid;

    /* the hotspot trying to connect */
    struct wifi_hotspot_candidate *trying;
    char *trying_ssid;
    char *trying_bssid;
    char *trying_key;

    struct wifi_hotspot *connected;

    struct list_head hotspots;
    struct kvlist saved_networks;
    struct wifi_status *status;
};

/* PSK or key for all hotspots is: `HybridOS 2.0` */
#define MY_PASSPHRASE "HybridOS 2.0"

static struct wifi_hotspot_candidate candidates[] = {
    { "00:09:5b:95:e0:77", "Always Saved", "[WPA-PSK-CCMP]",  2412, 0, 0 },
    { "00:09:5b:95:e0:40", "HybridOS", "[WPA-PSK-CCMP]",  2412, -1, 0 },
    { "00:09:5b:95:e0:41", "HybridOS 1", "[WPA2-PSK-CCMP]", 2412, -1, 0 },
    { "00:09:5b:95:e0:42", "HybridOS 2", "[WPA-PSK-CCMP]",  2412, -1, 0 },
    { "02:55:24:33:77:a0", "testing 0", "[WPA2-PSK-TKIP]", 5766, -1, 0 },
    { "02:55:24:33:77:a1", "testing 1", "[WPA-PSK-TKIP]",  2462, -1, 0 },
    { "02:55:24:33:77:a2", "testing 2", "[WPA2-PSK-TKIP]", 2462, -1, 0 },
    { "02:55:24:33:77:a3", "testing 3", "[WEP]",  2462, -1, 0 },
    { "02:55:24:33:77:a4", "testing 5", "[WPA2-PSK-TKIP]", 5830, -1, 0 },
    { "00:09:5b:95:e0:40", "合璧操作系统", "[WPA-PSK-TKIP]",  2412, -1, 0 },
    { "00:09:5b:95:e0:41", "测 试 UTF-8", "[WPA2-PSK-TKIP]", 2412, -1, 0 },
    { "00:09:5b:95:e0:42", "testing 2", "[WPA-PSK-TKIP]",  2412, -1, 0 },
    { "00:09:5b:95:e0:43", "My Private", "[WPA2-PSK-TKIP]", 2412, -1, 0 },
    { "00:09:5b:95:e0:44", "Guest", "[NONE]",  2412, -1, 0 },
    { "00:09:5b:95:e0:45", "\"Tom\" and \"Jerry\"", "[WEP]", 5348, -1, 0 },
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
    list_for_each_safe(p,
            n, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);
        list_del(&hotspot->ln);
        wifi_release_one_hotspot(hotspot);
    }
}

struct wifi_hotspot *
wifi_get_hotspot_by_netid(struct netdev_context *ctxt, int netid)
{
    if (netid < 0)
        return NULL;

    struct list_head *p;
    list_for_each(p, &ctxt->hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        const struct wifi_hotspot_candidate *candidate = hotspot->extra;
        assert(candidate);
        if (netid == candidate->netid) {
            return hotspot;
        }
    }

    return NULL;
}

struct wifi_hotspot *
wifi_get_hotspot_by_candidate(struct netdev_context *ctxt,
        const struct wifi_hotspot_candidate *candidate)
{
    struct list_head *p;
    list_for_each(p, &ctxt->hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        if (hotspot->extra == candidate) {
            return hotspot;
        }
    }

    return NULL;
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

struct wifi_hotspot_candidate *
wifi_find_candidate(const char *ssid, const char *bssid)
{
    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if (bssid && strcmp(bssid, candidates[i].bssid) == 0) {
            return candidates + i;
        }

        if (strcmp(ssid, candidates[i].ssid) == 0) {
            return candidates + i;
        }
    }

    return NULL;
}

const char *
wifi_get_keymgmt_from_capabilities(const char *capabilities)
{
    if (strstr(capabilities, "WPA2-PSK"))
        return "WPA-PSK";
    else if (strstr(capabilities, "WPA-PSK"))
        return "WPA-PSK";
    else if (strstr(capabilities, "WPA2"))
        return "WPA-PSK";
    else if (strstr(capabilities, "WPA"))
        return "WPA-PSK";
    else if (strstr(capabilities, "WEP"))
        return "WEP";
    else if (strstr(capabilities, "NONE"))
        return "NONE";

    return NULL;
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

    const char *my_keymgmt;
    my_keymgmt = wifi_get_keymgmt_from_capabilities(candidate->capabilities);
    if (my_keymgmt == NULL || strcmp(my_keymgmt, keymgmt))
        return -1;

    return check_wpa_passphrase(keymgmt, passphrase);
}

int wifi_add_network(struct netdev_context *ctxt, const char *ssid,
        const char *keymgmt, const char *passphrase)
{
    (void)passphrase;

    struct wifi_hotspot *found;
    found = wifi_get_hotspot_by_ssid(ctxt, ssid);

    if (found) {
        const char *_keymgmt;
        _keymgmt = wifi_get_keymgmt_from_capabilities(found->capabilities);
        if (_keymgmt == NULL || strcmp(_keymgmt, keymgmt))
            return -1;

        found->netid = ctxt->next_netid;
    }

    kvlist_set(&ctxt->saved_networks, ssid, &ctxt->next_netid);
    ctxt->next_netid++;

    return 0;
}

int wifi_select_network_in_scan_result(struct netdev_context *ctxt, int netid)
{
    assert(netid >= 0);

    ctxt->trying = NULL;
    struct wifi_hotspot *hotspot;
    hotspot = wifi_get_hotspot_by_netid(ctxt, netid);
    if (hotspot) {
        ctxt->trying = hotspot->extra;
    }

    return 0;
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

    if (ctxt->wpa_state == WPA_STATE_COMPLETED) {
        assert(ctxt->connected);

        ctxt->status->bssid = strdup(ctxt->connected->bssid);
        ctxt->status->ssid = strdup(ctxt->connected->ssid);
        ctxt->status->escaped_ssid =
            pcutils_escape_string_for_json(ctxt->status->ssid);
        ctxt->status->wpa_state = ctxt->wpa_state;

        const struct wifi_hotspot_candidate *candidate = ctxt->connected->extra;
        assert(candidate && candidate->netid >= 0);
        ctxt->status->netid = candidate->netid;

        ctxt->status->hotspot = ctxt->connected;
        ctxt->status->key_mgmt = strdup(
                wifi_get_keymgmt_from_capabilities(
                    ctxt->connected->capabilities));
    }
    else if (ctxt->wpa_state > WPA_STATE_SCANNING && ctxt->trying != NULL) {
        ctxt->status->bssid = strdup(ctxt->trying->bssid);
        ctxt->status->ssid = strdup(ctxt->trying->ssid);
        ctxt->status->escaped_ssid =
            pcutils_escape_string_for_json(ctxt->status->ssid);
        ctxt->status->wpa_state = ctxt->wpa_state;

        if (ctxt->wpa_state == WPA_STATE_COMPLETED) {
            ctxt->status->netid = ctxt->trying->netid;
        }

        ctxt->status->hotspot =
            wifi_get_hotspot_by_bssid(ctxt, ctxt->status->bssid);
        assert(ctxt->status->hotspot);

        ctxt->status->key_mgmt = strdup(
                wifi_get_keymgmt_from_capabilities(
                    ctxt->status->hotspot->capabilities));
    }

    return 0;
}

static int disconnect(struct netdev_context *ctxt);

static void on_wpa_completed(struct netdev_context *ctxt)
{
    assert(ctxt->trying);

    ctxt->connected = wifi_get_hotspot_by_bssid(ctxt,
            ctxt->trying->bssid);
    assert(ctxt->connected);

    if (ctxt->trying->netid < 0) {
        assert(ctxt->new_netid >= 0);
        ctxt->trying->netid = ctxt->new_netid;  /* mark as saved */
    }
    ctxt->new_netid = -1;

    ctxt->connected->netid = ctxt->trying->netid;
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
        keymgmt = wifi_get_keymgmt_from_capabilities(hotspot->capabilities);

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
            HLOG_ERR("Invalid key_mgmt or passphrase (%d): (%s/%s)\n",
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

    disconnect(ctxt);

select:
    wifi_select_network_in_scan_result(ctxt, netid);
    if (ctxt->trying) { /* the network is in scan result */

        unsigned count = 20;    /* maybe get result in 2s */
        do {
            TEMP_FAILURE_RETRY(usleep(100000)); // 0.1s

            if (random() % 20 == count) {
                ctxt->wpa_state = WPA_STATE_AUTHENTICATING;
                break;
            }
        } while (--count);
    }
    else {
        ctxt->wpa_state = WPA_STATE_SCANNING;
        ctxt->trying = wifi_find_candidate(ssid, bssid);
        ctxt->start_trying_time = purc_monotonic_time_after(0);
    }

    if (ctxt->wpa_state == WPA_STATE_AUTHENTICATING) {
        if (strcmp(keymgmt, "NONE") == 0) {
            ctxt->wpa_state = WPA_STATE_COMPLETED;
            on_wpa_completed(ctxt);
            return 0;
        }
        else if (strcmp(passphrase, MY_PASSPHRASE) == 0) {
            ctxt->wpa_state = WPA_STATE_COMPLETED;
            on_wpa_completed(ctxt);
            return 0;
        }

        return ERR_WPA_WRONG_PASSPHRASE;
    }
    else if (ctxt->wpa_state == WPA_STATE_SCANNING) {
        ctxt->trying_ssid = strdup(ssid);
        ctxt->trying_bssid = bssid ? strdup(bssid) : NULL;
        ctxt->trying_key = passphrase ? strdup(passphrase) : NULL;
    }

    return ERR_UNCERTAIN_RESULT;
}

static int disconnect(struct netdev_context *ctxt)
{
    if (ctxt->connected == NULL) {
        /* not connected */
        return 0;
    }

    ctxt->wpa_state = WPA_STATE_DISCONNECTED;
    wifi_reset_status(ctxt);
    return 0;
}

static struct wifi_hotspot *
clone_hotspot_from_candidate(struct wifi_hotspot_candidate *candidate)
{
    struct wifi_hotspot *one;
    one = calloc(1, sizeof(*one));
    one->bssid = strdup(candidate->bssid);
    one->frequency = candidate->frequency;
    one->signal_level = -(random() % 100);
    one->capabilities = strdup(candidate->capabilities);

    one->ssid = strdup(candidate->ssid);
    one->escaped_ssid = pcutils_escape_string_for_json(one->ssid);
    one->extra = candidate;
    one->netid = candidate->netid;

    return one;
}

static int start_scan(struct netdev_context *ctxt)
{
    if (ctxt->scan_start_time > 0)
        return 0;

    ctxt->scan_start_time = purc_monotonic_time_after(0);

    wifi_reset_hotspots(&ctxt->hotspots);
    /* generate a random hotspot list */
    unsigned found = 0;
    for (size_t i = 0; i < PCA_TABLESIZE(candidates); i++) {
        if ((random() % 2) == 0) {
            struct wifi_hotspot *one;
            one = clone_hotspot_from_candidate(candidates + i);
            candidates[i].found = true;
            list_add_tail(&one->ln, &ctxt->hotspots);
            found++;
        }
    }

    HLOG_INFO("Found %u hotspots\n", found);
    return 0;
}

static int stop_scan(struct netdev_context *ctxt)
{
    if (ctxt->scan_start_time == 0)
        return 0;

    ctxt->scan_start_time = 0;
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
    wifi_update_status(ctxt);
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
    if (ctxt->trying_ssid) {
        free(ctxt->trying_ssid);
        if (ctxt->trying_bssid) free(ctxt->trying_bssid);
        if (ctxt->trying_key) free(ctxt->trying_key);
    }

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

static void release_trying_info(struct netdev_context *ctxt)
{
    if (ctxt->wpa_state == WPA_STATE_UNKNOWN && ctxt->new_netid >= 0) {
        kvlist_remove(&ctxt->saved_networks, ctxt->trying_ssid);
        ctxt->new_netid = -1;
    }

    if (ctxt->trying_ssid) {
        free(ctxt->trying_ssid);
        if (ctxt->trying_bssid) free(ctxt->trying_bssid);
        if (ctxt->trying_key) free(ctxt->trying_key);
        ctxt->trying_ssid = NULL;
    }
}

int wifi_device_check(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;
    if (netdev->ctxt == NULL)
        return EPERM;

    struct netdev_context *ctxt = netdev->ctxt;
    size_t curr_time = purc_monotonic_time_after(0);
    if (curr_time - ctxt->last_update_time < 1) {
        return 0;
    }
    ctxt->last_update_time = curr_time;

    const char *evt = NULL;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);

    /* handle change of WPA state first */
    if (ctxt->wpa_state == WPA_STATE_SCANNING) {
        assert(ctxt->trying_ssid);
        if (ctxt->trying) {
            if (wifi_get_hotspot_by_candidate(ctxt, ctxt->trying) == NULL) {
                struct wifi_hotspot *one;
                one = clone_hotspot_from_candidate(ctxt->trying);
                ctxt->trying->found = true;
                list_add_tail(&one->ln, &ctxt->hotspots);

                evt = BUBBLE_WIFIHOTSPOTFOUND;
                print_one_hotspot(one, ctxt->status->netid, pb);
            }
            ctxt->wpa_state = WPA_STATE_AUTHENTICATING;
        }
        else {
            if (curr_time - ctxt->start_trying_time >= 3) {
                evt = BUBBLE_WIFIFAILEDCONNATTEMPT;

                char *escaped_ssid;
                escaped_ssid = pcutils_escape_string_for_json(ctxt->trying_ssid);
                pcutils_printbuf_format(pb,
                        "{\"ssid\":\"%s\","
                        "\"reason\":\"%s\"}",
                        escaped_ssid, "NOT-FOUND");
                free(escaped_ssid);

                ctxt->wpa_state = WPA_STATE_UNKNOWN;
                release_trying_info(ctxt);
            }
        }
    }
    else if (ctxt->wpa_state == WPA_STATE_AUTHENTICATING) {
        if (strcmp(ctxt->trying_key, MY_PASSPHRASE)) {
            evt = BUBBLE_WIFIFAILEDCONNATTEMPT;

            char *escaped_ssid;
            escaped_ssid = pcutils_escape_string_for_json(ctxt->trying_ssid);
            pcutils_printbuf_format(pb,
                    "{\"ssid\":\"%s\","
                    "\"reason\":\"%s\"}",
                    escaped_ssid, "BAD-KEY");
            free(escaped_ssid);

            ctxt->wpa_state = WPA_STATE_UNKNOWN;
        }
        else {
            ctxt->wpa_state = WPA_STATE_COMPLETED;
            on_wpa_completed(ctxt);
        }

        release_trying_info(ctxt);
    }
    else if (ctxt->wpa_state == WPA_STATE_DISCONNECTED) {
        assert(ctxt->connected);

        evt = BUBBLE_WIFIDISCONNECTED;
        pcutils_printbuf_format(pb,
                "{\"bssid\":\"%s\",\"ssid\":\"%s\"}",
                ctxt->connected->bssid,
                ctxt->connected->escaped_ssid ? ctxt->connected->escaped_ssid :
                ctxt->connected->ssid);
        ctxt->wpa_state = WPA_STATE_UNKNOWN;
        ctxt->connected = NULL;
    }
    else if (ctxt->wpa_state == WPA_STATE_COMPLETED) {
        if (ctxt->trying) {
            wifi_update_status(ctxt);

            evt = BUBBLE_WIFICONNECTED;
            pcutils_printbuf_format(pb,
                    "{\"bssid\":\"%s\","
                    "\"ssid\":\"%s\","
                    "\"signalLevel\":%d}",
                      ctxt->status->bssid,
                      ctxt->status->escaped_ssid ? ctxt->status->escaped_ssid :
                        ctxt->status->ssid,
                      ctxt->status->signal_level);
            ctxt->trying = NULL;
        }
        else {
            /* simulate WiFiSignalLevelChanged event */
            int level = -(random() % 100);
            if (ctxt->status->signal_level != level) {
                ctxt->connected->signal_level = level;
                ctxt->status->signal_level = level;

                evt = BUBBLE_WIFISIGNALLEVELCHANGED;

                pcutils_printbuf_format(pb,
                        "{\"bssid\":\"%s\","
                         "\"ssid\":\"%s\","
                         "\"signalLevel\":%d}",
                         ctxt->status->bssid,
                         ctxt->status->escaped_ssid ?
                            ctxt->status->escaped_ssid :
                            ctxt->status->ssid,
                         ctxt->status->signal_level);
            }
        }

    }
    else if (ctxt->scan_start_time) {
        if (curr_time - ctxt->scan_start_time >= 5) {
            /* simulate WiFiScanFinished event */
        }
        else if (random() % 5 == 0) {    // about 0.5s
            int index = random() % (int)PCA_TABLESIZE(candidates);
            if (candidates[index].found) {
                /* simulate WiFiHotspotLost event */
                struct wifi_hotspot *one;
                one = wifi_get_hotspot_by_candidate(ctxt, candidates + index);
                assert(one);
                if (one == ctxt->connected) {
                    disconnect(ctxt);
                }
                list_del(&one->ln);

                candidates[index].found = false;

                evt = BUBBLE_WIFIHOTSPOTLOST;
                pcutils_printbuf_format(pb, "{\"bssid\": \"%s\"}", one->bssid);
                wifi_release_one_hotspot(one);
            }
            else {
                /* simulate WiFiHotspotFound event */
                struct wifi_hotspot *one;
                one = clone_hotspot_from_candidate(candidates + index);
                candidates[index].found = true;
                list_add_tail(&one->ln, &ctxt->hotspots);

                evt = BUBBLE_WIFIHOTSPOTFOUND;
                print_one_hotspot(one, ctxt->status->netid, pb);
            }
        }
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

