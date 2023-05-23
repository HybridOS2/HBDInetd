/*
** wifi.h -- Some functions to use the wpa_supplicant.
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

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "internal.h"
#include "log.h"
#include "wifi.h"
#include "helpers.h"

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

int wifi_parse_scan_results(struct netdev_context *ctxt,
        const char *results, size_t max_len)
{
    const char *start = results;
    const char *last = results + max_len;
    const char *end = NULL;
    struct wifi_hotspot *one = NULL;

    end = strstr(start, "\n");
    while (end && end < last) {
        start = end + 1;

        one = calloc(1, sizeof(*one));
        end = strstr(start, "\t");
        if (end)
            one->bssid = strndup(start, end - start);
        else {
            goto failed;
        }

        start = end + 1;
        end = strstr(start, "\t");
        if (end) {
            int v = atoi(start);
            if (v < 0)
                goto failed;
            one->frequency = v;
        }
        else {
            goto failed;
        }

        start = end + 1;
        end = strstr(start, "\t");
        if (end) {
            one->signal_level = atoi(start);
        }
        else {
            goto failed;
        }

        start = end + 1;
        end = strstr(start, "\t");
        if (end) {
            one->capabilities = strndup(start, end - start);
        }
        else {
            goto failed;
        }

        start = end + 1;
        end = strstr(start, "\n");
        size_t len;
        if (end) {
            len = end - start;
        }
        else {
            len = strlen(start);
        }

        size_t nr_chars = 0;
        if (len == 0) {
            HLOG_WARN("Ignore hotspot with empty SSID\n");
            wifi_release_one_hotspot(one);
            one = NULL;
            continue;
        }

        one->ssid = malloc(len + 1);
        if (unescape_literal_text(start, len, one->ssid) <= 0) {
            HLOG_WARN("Ignore bad escaped SSID\n");
            wifi_release_one_hotspot(one);
            one = NULL;
            continue;
        }
        else if (!pcutils_string_check_utf8(one->ssid, -1, &nr_chars, NULL)
                || nr_chars == 0) {
            HLOG_WARN("Ignore bad UTF8-encoded SSID: %s\n", one->ssid);
            wifi_release_one_hotspot(one);
            one = NULL;
            continue;
        }
        else {
            HLOG_INFO("Nomalized valid UTF-8 SSID: %s\n", one->ssid);
        }

        one->escaped_ssid = pcutils_escape_string_for_json(one->ssid);
        one->netid = wifi_get_netid_from_ssid(ctxt, one->ssid);
        list_add_tail(&one->ln, &ctxt->hotspots);
    }

    return 0;

failed:
    HLOG_WARN("Ignored some results\n");
    if (one)
        wifi_release_one_hotspot(one);
    return 0;
}

int wifi_parse_networks(struct kvlist *networks,
        const char *results, size_t max_len)
{
    const char *start = results;
    const char *last = results + max_len;
    const char *end = NULL;

    end = strstr(start, "\n");  // skip first line
    while (end && end < last) {
        start = end + 1;

        int id;
        end = strstr(start, "\t");
        if (end)
            id = atoi(start);
        else
            goto failed;

        start = end + 1;
        end = strstr(start, "\t");
        if (end) {
            size_t len = end - start;
            size_t nr_chars;
            if (len == 0) {
                HLOG_INFO("Ignored empty SSID\n");
                goto next_line;
            }

            char ssid[len + 1];
            if (unescape_literal_text(start, len, ssid) < 0) {
                HLOG_INFO("Ignored SSDI with bad hex encoding: %s\n", start);
                goto next_line;
            }
            else if (!pcutils_string_check_utf8(ssid, -1, &nr_chars, NULL)
                    || nr_chars == 0) {
                HLOG_INFO("Ignored invalid UTF-8 SSID: %s\n", ssid);
                goto next_line;
            }

            kvlist_set(networks, ssid, &id);
        }
        else {
            HLOG_ERR("Bad format in network list: %s\n", start);
            goto failed;
        }

        start = end + 1;
        end = strstr(start, "\t");
        if (end) {
            // skip field bssid
        }
        else {
            HLOG_ERR("Bad format in network list: %s\n", start);
            goto failed;
        }

next_line:
        start = end + 1;
        end = strstr(start, "\n");
        // skip field flags
    }

    return 0;

failed:
    return -1;
}

int wifi_load_saved_networks(struct netdev_context *ctxt)
{
    char *reply = ctxt->buf;
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len)) {
        HLOG_ERR("Failed LIST_NETWORKS\n");
        return -1;
    }

    if (wifi_parse_networks(&ctxt->saved_networks, reply, reply_len))
        return -1;

    return 0;
}

static int
index_from_name(const char *names[], int n, const char *str, size_t len)
{
    int found = -1;

    for (int i = 0; i < n; i++) {
        if (strlen(names[i]) != len)
            continue;

        if (strncmp(names[i], str, len) == 0) {
            found = i;
            break;
        }
    }

    return found;
}

static const char *wpa_state_names[] = {
    WPA_STATE_NAME_UNKNOWN,
    WPA_STATE_NAME_DISCONNECTED,
    WPA_STATE_NAME_INACTIVE,
    WPA_STATE_NAME_INTERFACE_DISABLED,
    WPA_STATE_NAME_SCANNING,
    WPA_STATE_NAME_AUTHENTICATING,
    WPA_STATE_NAME_ASSOCIATING,
    WPA_STATE_NAME_ASSOCIATED,
    WPA_STATE_NAME_4WAY_HANDSHAKE,
    WPA_STATE_NAME_GROUP_HANDSHAKE,
    WPA_STATE_NAME_COMPLETED,
};

#define _COMPILE_TIME_ASSERT(name, x)               \
       typedef int _dummy_ ## name[(x) * 2 - 1]
_COMPILE_TIME_ASSERT(wpa_state,
        PCA_TABLESIZE(wpa_state_names) == WPA_STATE_nr);
#undef _COMPILE_TIME_ASSERT

static enum wpa_state
wpa_state_from_string(const char *start, size_t len)
{
    int found = index_from_name(wpa_state_names,
            (int)PCA_TABLESIZE(wpa_state_names), start, len);

    if (found == -1)
        return (enum wpa_state)0;

    return (enum wpa_state)found;
}

static const char *supp_pae_state_names[] = {
    SUPP_PAE_STATE_NAME_UNKNOWN,
    SUPP_PAE_STATE_NAME_INITIALIZE,
    SUPP_PAE_STATE_NAME_DISCONNECTED,
    SUPP_PAE_STATE_NAME_CONNECTING,
    SUPP_PAE_STATE_NAME_AUTHENTICATING,
    SUPP_PAE_STATE_NAME_AUTHENTICATED,
    SUPP_PAE_STATE_NAME_ABORTING,
    SUPP_PAE_STATE_NAME_HELD,
    SUPP_PAE_STATE_NAME_FORCE_AUTH,
    SUPP_PAE_STATE_NAME_FORCE_UNAUTH,
    SUPP_PAE_STATE_NAME_RESTART,
};

#define _COMPILE_TIME_ASSERT(name, x)               \
       typedef int _dummy_ ## name[(x) * 2 - 1]
_COMPILE_TIME_ASSERT(supp_pae_state,
        PCA_TABLESIZE(supp_pae_state_names) == SUPP_PAE_STATE_nr);
#undef _COMPILE_TIME_ASSERT

static enum supp_pae_state
supp_pae_state_from_string(const char *start, size_t len)
{
    int found = index_from_name(supp_pae_state_names,
            (int)PCA_TABLESIZE(supp_pae_state_names), start, len);

    if (found == -1)
        return (enum supp_pae_state)0;

    return (enum supp_pae_state)found;
}

static const char *supp_port_status_names[] = {
    SUPP_PORT_STATUS_NAME_UNKNOWN,
    SUPP_PORT_STATUS_NAME_AUTHORIZED,
    SUPP_PORT_STATUS_NAME_UNAUTHORIZED,
};

#define _COMPILE_TIME_ASSERT(name, x)               \
       typedef int _dummy_ ## name[(x) * 2 - 1]
_COMPILE_TIME_ASSERT(supp_port_status,
        PCA_TABLESIZE(supp_port_status_names) == SUPP_PORT_STATUS_nr);
#undef _COMPILE_TIME_ASSERT

static enum supp_port_status
supp_port_status_from_string(const char *start, size_t len)
{
    int found = index_from_name(supp_port_status_names,
            (int)PCA_TABLESIZE(supp_port_status_names), start, len);

    if (found == -1)
        return (enum supp_port_status)0;

    return (enum supp_port_status)found;
}

static const char *eap_state_names[] = {
    EPA_STATE_NAME_UNKNOWN,
    EAP_STATE_NAME_INITIALIZE,
    EAP_STATE_NAME_DISABLED,
    EAP_STATE_NAME_IDLE,
    EAP_STATE_NAME_RECEIVED,
    EAP_STATE_NAME_GET_METHOD,
    EAP_STATE_NAME_METHOD,
    EAP_STATE_NAME_SEND_RESPONSE,
    EAP_STATE_NAME_DISCARD,
    EAP_STATE_NAME_IDENTITY,
    EAP_STATE_NAME_NOTIFICATION,
    EAP_STATE_NAME_RETRANSMIT,
    EAP_STATE_NAME_SUCCESS,
    EAP_STATE_NAME_FAILURE,
};

#define _COMPILE_TIME_ASSERT(name, x)               \
       typedef int _dummy_ ## name[(x) * 2 - 1]
_COMPILE_TIME_ASSERT(eap_state,
        PCA_TABLESIZE(eap_state_names) == EAP_STATE_nr);
#undef _COMPILE_TIME_ASSERT

static enum eap_state
eap_state_from_string(const char *start, size_t len)
{
    int found = index_from_name(eap_state_names,
            (int)PCA_TABLESIZE(eap_state_names), start, len);

    if (found == -1)
        return (enum eap_state)0;

    return (enum eap_state)found;
}

static int wifi_parse_status(struct wifi_status *status,
        const char *results, size_t max_len)
{
    (void)max_len;
    const char *start = results;
    const char *end = NULL;
    while (start) {
        end = strstr(start, "=");
        if (end == NULL)
            break;

        size_t len = end - start;
        if (strncasecmp2ltr(start, "bssid", len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->bssid = strndup(start, len);
            HLOG_INFO("Got bssid: %s\n", status->bssid);
        }
        else if (strncasecmp2ltr(start, "ssid", len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            size_t nr_chars;
            char ssid[len + 1];
            if (unescape_literal_text(start, len, ssid) < 0) {
                HLOG_ERR("Bad hex encoding: %s\n", start);
                goto failed;
            }
            else if (!pcutils_string_check_utf8(ssid, -1, &nr_chars, NULL)
                    || nr_chars == 0) {
                HLOG_ERR("SSID is not a valid UTF-8 string: %s\n", start);
                goto failed;
            }

            status->ssid = strdup(ssid);
            status->escaped_ssid =
                pcutils_escape_string_for_json(status->ssid);
            HLOG_INFO("Got ssid: %s\n", status->ssid);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_PAIRWISE_CIPHER, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->pairwise_cipher = strndup(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_GROUP_CIPHER, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->group_cipher = strndup(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_KEY_MGMT, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->key_mgmt = strndup(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_IP_ADDRESS, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->ip_address = strndup(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_WPA_STATE, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->wpa_state = wpa_state_from_string(start, len);
            HLOG_INFO("Got wpa_state: %s\n",
                    wpa_state_names[status->wpa_state]);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_SUPP_PAE_STATE, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->supp_pae_state = supp_pae_state_from_string(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_SUPP_PORT_STATUS, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->supp_port_status = supp_port_status_from_string(start, len);
        }
        else if (strncasecmp2ltr(start, STATUS_KEY_EAP_STATE, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->eap_state = eap_state_from_string(start, len);
        }
        else {
            start = end + 1;
            end = strstr(start, "\n");
        }

        if (end)
            start = end + 1;
        else {
            break;
        }
    }

    return 0;

failed:
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

    char *reply = ctxt->buf;
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, "STATUS", reply, &reply_len)) {
        HLOG_ERR("Failed STATUS\n");
        return -1;
    }

    if (wifi_parse_status(ctxt->status, reply, reply_len)) {
        HLOG_ERR("Failed parsing STATUS\n");
        return -1;
    }

    if (ctxt->status->bssid) {
        ctxt->status->hotspot =
            wifi_get_hotspot_by_bssid(ctxt, ctxt->status->bssid);
        if (ctxt->status->hotspot == NULL) {
            HLOG_ERR("BSS %s is not in the hotspot list\n", ctxt->status->bssid);
        }
    }

    if (ctxt->status->ssid) {
        ctxt->status->netid = wifi_get_netid_from_ssid(ctxt, ctxt->status->ssid);
    }

    return 0;
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

int wifi_get_signal_level_by_bssid(struct netdev_context *ctxt,
        const char *bssid)
{
    char cmd[128];
    int n = snprintf(cmd, sizeof(cmd), "BSS %s", bssid);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        HLOG_ERR("Too small buffer for `BSS %s` command\n", bssid);
        return -1;
    }

    char *results = ctxt->buf;
    size_t max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, cmd, results, &max_len)) {
        HLOG_ERR("Failed `BSS %s` command\n", bssid);
        return -1;
    }

    const char *start = results;
    const char *end = NULL;
    while (start) {
        end = strstr(start, "=");
        if (end) {
            size_t len = end - start;
            if (strncasecmp2ltr(start, "level", len) == 0) {
                start = end + 1;
                end = strstr(start, "\n");
                if (end == NULL)
                    len = end - start;
                else {
                    len = strlen(start);
                }

                if (len == 0) {
                    HLOG_ERR("No valid level value: %s\n", start);
                    goto failed;
                }

                return atoi(start);
            }
            else {
                start = end + 1;
                end = strstr(start, "\n");
                if (end)
                    start = end + 1;
                else {
                    break;
                }
            }
        }
        else {
            break;
        }
    }

failed:
    return -1;
}

int wifi_update_hotspot_by_bssid(struct netdev_context *ctxt,
        struct wifi_hotspot *hotspot, const char *bssid)
{
    char cmd[128];
    int n = snprintf(cmd, sizeof(cmd), "BSS %s", bssid);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        HLOG_ERR("Too small buffer for `BSS %s` command\n", bssid);
        return -1;
    }

    char *results = ctxt->buf;
    size_t max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, cmd, results, &max_len)) {
        HLOG_ERR("Failed `BSS %s` command\n", bssid);
        return -1;
    }

    const char *start = results;
    const char *end = NULL;
    while (start) {
        end = strstr(start, "=");
        if (end) {
            size_t len = end - start;
            if (strncasecmp2ltr(start, "freq", len) == 0) {
                start = end + 1;
                end = strstr(start, "\n");
                if (end == NULL)
                    len = end - start;
                else {
                    len = strlen(start);
                }

                if (len == 0) {
                    goto failed;
                }

                if (hotspot->frequency == 0) {
                    hotspot->frequency = atoi(start);
                }
            }
            else if (strncasecmp2ltr(start, "flags", len) == 0) {
                start = end + 1;
                end = strstr(start, "\n");
                if (end == NULL)
                    len = end - start;
                else {
                    len = strlen(start);
                }

                if (len == 0) {
                    goto failed;
                }

                if (hotspot->capabilities == NULL) {
                    hotspot->capabilities = strndup(start, len);
                }
            }
            else if (strncasecmp2ltr(start, "level", len) == 0) {
                start = end + 1;
                end = strstr(start, "\n");
                if (end == NULL)
                    len = end - start;
                else {
                    len = strlen(start);
                }

                if (len == 0) {
                    goto failed;
                }

                hotspot->signal_level = atoi(start);
            }
            else if (strncasecmp2ltr(start, "ssid", len) == 0) {
                start = end + 1;
                end = strstr(start, "\n");
                if (end == NULL)
                    len = end - start;
                else {
                    len = strlen(start);
                }

                if (len == 0) {
                    goto failed;
                }

                if (hotspot->ssid == NULL) {
                    size_t nr_chars;
                    hotspot->ssid = malloc(len + 1);
                    if (unescape_literal_text(start, len, hotspot->ssid) <= 0) {
                        HLOG_WARN("Ignore bad escaped SSID\n");
                        goto failed;
                    }
                    else if (!pcutils_string_check_utf8(hotspot->ssid, -1,
                                &nr_chars, NULL) || nr_chars == 0) {
                        HLOG_WARN("Ignore bad UTF8-encoded SSID: %s\n",
                                hotspot->ssid);
                        goto failed;
                    }
                    else {
                        HLOG_INFO("Nomalized valid UTF-8 SSID: %s\n",
                                hotspot->ssid);
                    }

                    hotspot->escaped_ssid =
                        pcutils_escape_string_for_json(hotspot->ssid);
                }
            }
            else {
                start = end + 1;
                end = strstr(start, "\n");
                if (end)
                    start = end + 1;
                else {
                    break;
                }
            }
        }
        else {
            break;
        }
    }

    if (hotspot->ssid)
        hotspot->netid = wifi_get_netid_from_ssid(ctxt, hotspot->ssid);
    else
        hotspot->netid = -1;
    return 0;

failed:
    return -1;
}

int wifi_update_network(struct netdev_context *ctxt, int netid,
        const char *ssid, const char *keymgmt, const char *passphrase)
{
    char cmd[256];

    char hex_ssid[strlen(ssid) * 2 + 1];
    convert_to_hex_string(ssid, hex_ssid);

    int n = snprintf(cmd, sizeof(cmd),
            "SET_NETWORK %d ssid %s", netid, hex_ssid);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        HLOG_ERR("Too small buffer for `SET_NETWORK %d ssid %s` command\n",
                netid, hex_ssid);
        return -1;
    }

    char *results = ctxt->buf;
    size_t max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, cmd, results, &max_len)) {
        HLOG_ERR("Failed `%s` command\n", cmd);
        return -1;
    }

    if (strcmp(keymgmt, "WPA-PSK") == 0 ||
            strcmp(keymgmt, "WPA2-PSK") == 0) {
        sprintf(cmd, "SET_NETWORK %d key_mgmt WPA-PSK", netid);

        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }

        char hex_psk[strlen(passphrase) * 2 + 1];
        convert_to_hex_string(passphrase, hex_psk);
        n = snprintf(cmd, sizeof(cmd), "SET_NETWORK %d psk %s", netid, hex_psk);
        if (n < 0 || n >= (int)sizeof(cmd)) {
            HLOG_ERR("Too small buffer for `psk` command\n");
            return -1;
        }

        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }
    }
    else if (strcmp(keymgmt, "WEP") == 0) {
        sprintf(cmd, "SET_NETWORK %d key_mgmt NONE", netid);
        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }

        char hex_key[strlen(passphrase) * 2 + 1];
        convert_to_hex_string(passphrase, hex_key);
        n = sprintf(cmd, "SET_NETWORK %d wep_key0 %s", netid, hex_key);
        if (n < 0 || n >= (int)sizeof(cmd)) {
            HLOG_ERR("Too small buffer for `wep_key0` command\n");
            return -1;
        }

        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }

        sprintf(cmd, "SET_NETWORK %d auth_alg OPEN SHARED", netid);
        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }
    }
    else if (strcmp(keymgmt, "NONE") == 0) {
        sprintf(cmd, "SET_NETWORK %d key_mgmt NONE", netid);
        max_len = WIFI_MSG_BUF_SIZE;
        if (wifi_command(ctxt, cmd, results, &max_len)) {
            HLOG_ERR("Failed `%s` command\n", cmd);
            return -1;
        }
    }
    else {
        HLOG_ERR("Unknown key_mgmt: `%s`\n", keymgmt);
        return -1;
    }

#if 0
    sprintf(cmd, "SET_NETWORK %d scan_ssid 1", netid);
    max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, cmd, results, &max_len)) {
        HLOG_ERR("Failed `%s` command\n", cmd);
        return -1;
    }
#endif

    /* TODO: set priority for network: SET_NETWORK %d priority %d */
    return 0;
}

int wifi_add_network(struct netdev_context *ctxt, const char *ssid,
        const char *keymgmt, const char *passphrase)
{
    char *results = ctxt->buf;
    size_t max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, "ADD_NETWORK", results, &max_len)) {
        HLOG_ERR("Failed `ADD_NETWORK` command\n");
        return -1;
    }

    int netid = atoi(results);
    assert(netid >= 0);

    if (wifi_update_network(ctxt, netid, ssid, keymgmt, passphrase)) {
        char cmd[128];
        sprintf(cmd, "REMOVE_NETWORK %d", netid);

        max_len = WIFI_MSG_BUF_SIZE;
        wifi_command(ctxt, cmd, results, &max_len);
        return -1;
    }

    return netid;
}

int wifi_remove_network(struct netdev_context *ctxt, int netid)
{
    char cmd[128];

    assert(netid >= 0);

    sprintf(cmd, "REMOVE_NETWORK %d", netid);
    char *results = ctxt->buf;
    size_t max_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, cmd, results, &max_len)) {
        HLOG_ERR("Failed `%s` command\n", cmd);
        return -1;
    }

    return 0;
}

