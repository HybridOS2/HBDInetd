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

int wifi_parse_status_for_netid(struct netdev_context *ctxt,
        const char *results, size_t max_len, char **ssid_ret)
{
    (void)max_len;
    const char *start = results;
    const char *end = NULL;
    while (start) {
        end = strstr(start, "=");
        if (end) {
            size_t len = end - start;
            if (strncasecmp(start, "ssid", len) == 0) {

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

                void *data = kvlist_get(&ctxt->saved_networks, ssid);
                if (data) {
                    int id;
                    id = *(int *)data;
                    if (ssid_ret)
                        *ssid_ret = strdup(ssid);
                    return id;
                }
                else {
                    HLOG_ERR("Current network is not saved one: %s\n", ssid);
                    goto failed;
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

failed:
    return -1;
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

