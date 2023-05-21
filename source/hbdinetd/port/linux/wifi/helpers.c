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

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "log.h"
#include "wifi.h"
#include "helpers.h"

void wifi_reset_hotspots(struct list_head *hotspots)
{
    struct list_head *p, *n;
    list_for_each_safe(p, n, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);
        list_del(&hotspot->ln);
        free(hotspot);
    }
}

static int unescape_hex(const char *src, size_t len, char *dst)
{
    size_t i = 0;
    size_t j = 0;
    unsigned char byte = 0;

    for (i = 0, j = 0; i < len; i++, j++) {
        if (src[i] == '\\') {
            i++;
            if (i >= len)
                goto bad_encoding;

            if (src[i] == 'x') {
                i++;
                if (i >= len)
                    goto bad_encoding;

                char ch = tolower(src[i]);
                if ((ch >= '0') && (ch <= '9'))
                    byte = (ch - '0') << 4;
                else if ((ch >= 'a') && (ch <= 'f'))
                    byte = (ch - 'a' + 0x0a) << 4;

                i++;
                if (i >= len)
                    goto bad_encoding;

                ch = tolower(src[i]);
                if ((ch >= '0') && (ch <= '9'))
                    byte |= (ch - '0');
                else if ((ch >= 'a') && (ch <= 'f'))
                    byte |= (ch - 'a' + 0x0a);

                dst[j] = byte;
            }
            else if (src[i] == '\\') {
                dst[j] = '\\';
            }
            else {
                goto bad_encoding;
            }
        }
        else
            dst[j] = src[i];
    }
    dst[j] = 0;

    return 0;

bad_encoding:
    return -1;
}

int wifi_parse_scan_results(struct list_head *hotspots,
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
        if (end) {
            size_t len = end - start;
            size_t nr_chars = 0;
            if (len == 0)
                goto failed;

            one->ssid = malloc(len + 1);
            if (unescape_hex(start, len, one->ssid)) {
                goto failed;
            }
            else if (!pcutils_string_check_utf8(one->ssid, -1, &nr_chars, NULL)
                    || nr_chars == 0) {
                goto failed;
            }

            list_add_tail(hotspots, &one->ln);
        }
        else {
            size_t len = strlen(start);
            if (len == 0)
                goto failed;

            one->ssid = malloc(len + 1);
            if (unescape_hex(start, len, one->ssid)) {
                goto failed;
            }

            list_add_tail(hotspots, &one->ln);
            break;
        }
    }

    return 0;

failed:
    HLOG_WARN("Bad format or encoding in scan result: %s\n", start);
    if (one) {
        if (one->bssid)
            free(one->bssid);
        if (one->ssid)
            free(one->ssid);
        if (one->capabilities)
            free(one->capabilities);
        free(one);
    }

    return -1;
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
            char ssid[len + 1];
            if (unescape_hex(start, len, ssid)) {
                HLOG_ERR("Bad hex encoding: %s\n", start);
                goto failed;
            }
            else if (!pcutils_string_check_utf8(ssid, -1, &nr_chars, NULL)
                    || nr_chars == 0) {
                HLOG_ERR("SSID is not a valid UTF-8 string: %s\n", start);
                goto failed;
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

    HLOG_INFO("Result of LIST_NETWORKS:\n%s\n", reply);
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
        if (strncasecmp(start, "bssid", len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->bssid = strndup(start, len);
        }
        else if (strncasecmp(start, "ssid", len) == 0) {

            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            size_t nr_chars;
            char ssid[len + 1];
            if (unescape_hex(start, len, ssid)) {
                HLOG_ERR("Bad hex encoding: %s\n", start);
                goto failed;
            }
            else if (!pcutils_string_check_utf8(ssid, -1, &nr_chars, NULL)
                    || nr_chars == 0) {
                HLOG_ERR("SSID is not a valid UTF-8 string: %s\n", start);
                goto failed;
            }

            status->ssid = strdup(ssid);
        }
        else if (strncasecmp(start, STATUS_KEY_PAIRWISE_CIPHER, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->pairwise_cipher = strndup(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_GROUP_CIPHER, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->group_cipher = strndup(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_KEY_MGMT, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->key_mgmt = strndup(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_IP_ADDRESS, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->ip_address = strndup(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_WPA_STATE, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->wpa_state = wpa_state_from_string(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_SUPP_PAE_STATE, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->supp_pae_state = supp_pae_state_from_string(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_SUPP_PORT_STATUS, len) == 0) {
            start = end + 1;
            end = strstr(start, "\n");
            if (end)
                len = end - start;
            else
                len = strlen(start);

            status->supp_port_status = supp_port_status_from_string(start, len);
        }
        else if (strncasecmp(start, STATUS_KEY_EAP_STATE, len) == 0) {
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
            if (end)
                start = end + 1;
            else {
                break;
            }
        }
    }

failed:
    return -1;
}

int wpa_conf_get_current_network(struct netdev_context *ctxt)
{
    char *reply = ctxt->buf;
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    if (wifi_command(ctxt, "STATUS", reply, &reply_len)) {
        HLOG_ERR("Failed STATUS\n");
        return -1;
    }

    HLOG_INFO("Result of STATUS:\n%s\n", reply);

    if (ctxt->status == NULL) {
        ctxt->status = calloc(1, sizeof(*ctxt->status));
        if (ctxt->status == NULL) {
            HLOG_ERR("Failed allocating WiFi status structure\n");
            return -1;
        }
    }
    else {
        for (size_t i = 0; i < WIFI_STATUS_STRING_FIELDS; i++) {
            if (ctxt->status->fields[i]) {
                free(ctxt->status->fields[i]);
            }
        }

        memset(ctxt->status, 0, sizeof(*ctxt->status));
        ctxt->status->netid = -1;
    }

    if (wifi_parse_status(ctxt->status, reply, reply_len)) {
        HLOG_ERR("Failed parsing STATUS\n");
        return -1;
    }

    if (ctxt->status->ssid) {
        void *data = kvlist_get(&ctxt->saved_networks, ctxt->status->ssid);
        if (data) {
            ctxt->status->netid = *(int *)data;
        }
        else {
            HLOG_WARN("Current network is not saved one: %s\n",
                    ctxt->status->ssid);
        }
    }

    return 0;
}

int wifi_parse_bss_for_signal_level(struct wifi_hotspot *hotspot,
        const char *results, size_t max_len)
{
    (void)max_len;
    const char *start = results;
    const char *end = NULL;
    while (start) {
        end = strstr(start, "=");
        if (end) {
            size_t len = end - start;
            if (strncasecmp(start, "level", len) == 0) {
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

                int level = atoi(start);
                if (level == hotspot->signal_level)
                    return 0;
                else
                    return 1;
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

