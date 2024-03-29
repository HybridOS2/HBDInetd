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

#include "wifi.h"
#include "event.h"
#include "helpers.h"

#include <unistd.h>
#include <errno.h>

#define US_100MS    100000

static int connect(struct netdev_context *ctxt,
        const char *ssid, const char *bssid,
        const char *keymgmt, const char *passphrase)
{
    int ret;
    char cmd[32];

    if (ctxt->new_netid >= 0) {
        return ERR_UNRESOLVED_ATTEMPT;
    }

    if (keymgmt != NULL &&
            (ret = check_wpa_passphrase(keymgmt, passphrase))) {
        return ret;
    }

    if (ctxt->status) {
        if (keymgmt == NULL) {
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

        netid = wifi_add_network(ctxt, bssid, ssid, keymgmt, passphrase);
        if (netid < 0) {
            HLOG_ERR("Failed to add a new network: %s (key_mgmt: %s)\n",
                    ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }

        ctxt->new_netid = netid;
    }
    else if (netid >= 0) {
        if (wifi_update_network(ctxt, netid, bssid, NULL, keymgmt, passphrase)) {
            HLOG_ERR("Failed to update network: %d) %s (key_mgmt: %s)\n",
                    netid, ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }
    }
    else {
        netid = wifi_add_network(ctxt, bssid, ssid, keymgmt, passphrase);
        if (netid < 0) {
            HLOG_ERR("Failed to add a new network: %s (key_mgmt: %s)\n",
                    ssid, keymgmt);
            return ERR_DEVICE_CONTROLLER;
        }

        ctxt->new_netid = netid;
    }

    wifi_update_status(ctxt);
    if (ctxt->status && ctxt->status->bssid) {
        /* disconnect first if connected */
        size_t len = WIFI_MSG_BUF_SIZE;
        ret = wifi_command(ctxt, "DISCONNECT", ctxt->buf, &len);
        if (ret) {
            HLOG_ERR("Failed to issue DISCONNECT command\n");
            return ERR_DEVICE_CONTROLLER;
        }

        wifi_reset_status(ctxt);
    }

select:
    ctxt->trying_netid = netid;
    sprintf(cmd, "SELECT_NETWORK %d", netid);

    size_t len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, cmd, ctxt->buf, &len);
    if (ret) {
        HLOG_ERR("Failed to issue `SELECT_NETWORK %d` command\n",
                netid);
        return ERR_DEVICE_CONTROLLER;
    }

#if 0
    ret = wifi_command(ctxt, "RECONNECT", ctxt->buf, &len);
    if (ret) {
        HLOG_ERR("Failed to issue RECONNECT command\n");
        return ERR_DEVICE_CONTROLLER;
    }
#endif

    unsigned count = 10;    /* total 3s */
    do {
        TEMP_FAILURE_RETRY(usleep(200000)); // 0.2s

        wifi_update_status(ctxt);
        switch (ctxt->status->wpa_state) {
        case WPA_STATE_UNKNOWN:
        case WPA_STATE_INACTIVE:
        case WPA_STATE_INTERFACE_DISABLED:
            return ERR_DEVICE_CONTROLLER;

        case WPA_STATE_COMPLETED:
            return 0;

        default:
            break;
        }

    } while (--count);

#if 0   /* always use WiFiFailedConnAttempt event */
    if (ctxt->status->wpa_state >= WPA_STATE_SCANNING &&
            ctxt->status->wpa_state < WPA_STATE_COMPLETED) {

        if (ctxt->new_netid >= 0) {
            wifi_remove_network(ctxt, ctxt->new_netid);
            ctxt->new_netid = -1;
            kvlist_remove(&ctxt->saved_networks, ssid);
        }
        return ERR_WPA_WRONG_PASSPHRASE;
    }
#endif

    return ERR_UNCERTAIN_RESULT;
}

static int disconnect(struct netdev_context *ctxt)
{
    wifi_update_status(ctxt);
    if (ctxt->status == NULL || ctxt->status->bssid == NULL) {
        /* not connected */
        return 0;
    }

    size_t len = WIFI_MSG_BUF_SIZE;
    int ret = wifi_command(ctxt, "DISCONNECT", ctxt->buf, &len);
    if (ret) {
        HLOG_ERR("Failed to issue DISCONNECT command\n");
        return ERR_DEVICE_CONTROLLER;
    }

    wifi_reset_status(ctxt);
    return 0;
}

static int start_scan(struct netdev_context *ctxt)
{
    wifi_update_status(ctxt);
    if (ctxt->status->wpa_state == WPA_STATE_SCANNING)
        return 0;

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
get_hotspot_list(struct netdev_context *ctxt, int *curr_netid)
{
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    int ret = wifi_command(ctxt, "SCAN_RESULTS", ctxt->buf, &reply_len);
    if (ret) {
        HLOG_ERR("Failed when getting scan results: %d\n", ret);
        goto failed;
    }

    if (wifi_parse_scan_results(ctxt, ctxt->buf, reply_len)) {
        HLOG_ERR("Failed when parsing scan results\n");
        goto failed;
    }

    if (curr_netid) {
        *curr_netid = ctxt->status->netid;
    }

    return &ctxt->hotspots;

failed:
    return NULL;
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
        ctxt->buf = malloc(WIFI_MSG_BUF_SIZE);
        if (ctxt->buf == NULL) {
            free(ctxt->status);
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

    ctxt->new_netid = -1;

    return ctxt;
}

static void netdev_context_delete(struct netdev_context *ctxt)
{
    wifi_reset_status(ctxt);
    if (ctxt->status)
        free(ctxt->status);

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
    if (netdev->ctxt) {
        HLOG_WARN("The WiFi device %s is already on!\n", netdev->ifname);
        return 0;
    }

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
            ret = errno;
            goto failed;
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
                break;
            }
            nr_tries++;
        } while (ret && nr_tries < 10);

        if (ret) {
            HLOG_ERR("Give up after 10 retries to connect to wpa_supplicant!\n");
            ret = ERR_DEVICE_CONTROLLER;
            goto failed;
        }
    }

    HLOG_INFO("Connected to wpa_supplicant!\n");

    if (wifi_load_saved_networks(netdev->ctxt)) {
        ret = ERR_DEVICE_CONTROLLER;
        goto failed;
    }

    HLOG_INFO("Loaded saved networks!\n");
    if (register_wifi_interfaces(conn)) {
        ret = ERR_DATA_BUS;
        goto failed;
    }

    if (wifi_update_status(netdev->ctxt)) {
        ret = ERR_DEVICE_CONTROLLER;
        goto failed;
    }

    HLOG_INFO("Switch %s on successfully!\n", netdev->ifname);
    return 0;

failed:
    netdev_context_delete(netdev->ctxt);
    netdev->ctxt = NULL;
    return ret;
}

int wifi_device_config(hbdbus_conn *conn, struct network_device *netdev,
        const char *param)
{
    if (netdev->ctxt == NULL)
        return ENOENT;

    wifi_update_status(netdev->ctxt);
    if (netdev->ctxt->status->wpa_state != WPA_STATE_COMPLETED) {
        return ERR_DEVICE_NOT_READY;
    }

    int errcode = ERR_OK;
    purc_variant_t jo = NULL;
    purc_variant_t jo_tmp = NULL;

    jo = purc_variant_make_from_json_string(param, strlen(param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "method")) == NULL) {
        HLOG_ERR("No `method` key\n");
        errcode = ENOKEY;
        goto done;
    }

    const char *method = purc_variant_get_string_const(jo_tmp);
    if (method == NULL) {
        HLOG_ERR("No configuring method specified.\n");
        errcode = EINVAL;
    }
    else if (strcasecmp(method, "dhcp") == 0) {
        issue_dhcp_request(conn, netdev->ifname);
    }
    else if (strcasecmp(method, "static") == 0) {
        /* TODO */
        HLOG_ERR("Not supported configuring method: %s\n", method);
        errcode = ENOTSUP;
    }
    else {
        HLOG_ERR("Bad configuring method: %s\n", method);
        errcode = EINVAL;
    }

done:
    if (jo)
        purc_variant_unref(jo);
    return errcode;
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

    /* check if signal level changed */
    if (netdev->ctxt->status && netdev->ctxt->status->bssid &&
            netdev->ctxt->status->wpa_state == WPA_STATE_COMPLETED) {

        time_t t = purc_monotonic_time_after(0);
        if (t >= netdev->ctxt->last_update_time + DEF_UPDATE_INTERVAL) {

            int level = wifi_get_signal_level_by_bssid(netdev->ctxt,
                    netdev->ctxt->status->bssid);
            if (netdev->ctxt->status->signal_level != level) {

                netdev->ctxt->status->signal_level = level;
                struct pcutils_printbuf my_buff, *pb = &my_buff;
                pcutils_printbuf_init(pb);
                pcutils_printbuf_format(pb,
                        "{\"bssid\":\"%s\","
                         "\"ssid\":\"%s\","
                         "\"signalLevel\":%d}",
                         netdev->ctxt->status->bssid,
                         netdev->ctxt->status->escaped_ssid ?
                            netdev->ctxt->status->escaped_ssid :
                            netdev->ctxt->status->ssid,
                         netdev->ctxt->status->signal_level);
                if (pb->buf) {
                    hbdbus_fire_event(conn, BUBBLE_WIFISIGNALLEVELCHANGED,
                            pb->buf);
                    free(pb->buf);
                }
                else {
                    HLOG_ERR("OOM when using printbuf\n");
                    return ENOMEM;
                }
            }

            netdev->ctxt->last_update_time = t;
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

    wifi_event_free(netdev->ctxt);

    wifi_reset_hotspots(&netdev->ctxt->hotspots);

    if (netdev->ctxt->ctrl_conn) {
        wifi_close_supplicant_connection(netdev->ctxt);
    }

    free(netdev->ctxt->buf);
    free(netdev->ctxt);
    netdev->ctxt = NULL;
}

