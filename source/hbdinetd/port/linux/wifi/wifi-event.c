/*
** wifi-event.c -- The event handlers for wpa_supplicant.
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
#include "wifi-event.h"

#include <unistd.h>
#include <errno.h>

typedef int (*event_handler)(struct netdev_context *ctxt,
        const char *data, int len);

static int on_connected(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static int on_disconnected(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static int on_scan_results(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static int on_terminating(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static int on_eap_failure(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static int on_assoc_reject(struct netdev_context *ctxt,
        const char *data, int len)
{
    (void)ctxt;
    (void)data;
    (void)len;
    return 0;
}

static const struct event_handler {
    const char *name;
    event_handler handler;
} event_handlers[] = {
    { "CONNECTED", on_connected },
    { "DISCONNECTED", on_disconnected },
    { "STATE-CHANGE", NULL },
    { "SCAN-RESULTS", on_scan_results },
    { "LINK-SPEED", NULL },
    { "TERMINATING", on_terminating },
    { "DRIVER-STATE", NULL },
    { "EAP-FAILURE", on_eap_failure },
    { "ASSOC-REJECT", on_assoc_reject },
};

int wifi_event_init(struct netdev_context *ctxt)
{
    kvlist_init(&ctxt->event_handlers, NULL);

    for (size_t i = 0; i < PCA_TABLESIZE(event_handlers); i++) {
        if (kvlist_set(&ctxt->event_handlers, event_handlers[i].name,
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

int wifi_event_handle_message(struct netdev_context *ctxt,
        const char *msg, int len)
{
    if (msg[0] == '\0')
        return 0;

    if (strncmp(msg, "WPA:", 4) == 0) {
        if (strstr(msg, "pre-shared key may be incorrect")) {
            ctxt->auth_fail_count++;
            if (ctxt->auth_fail_count >= MAX_RETRIES_ON_AUTH_FAILURE) {

                wifi_command(ctxt, "DISCONNECT", ctxt->buf, WIFI_MSG_BUF_SIZE);
                // TODO:

                ctxt->auth_fail_count = 0;
            }
        }
    }
    else if (strncmp(msg, "CTRL-EVENT-", 11) == 0) {
        const char *event_start = msg + 11;
        const char *event_end = strchr(event_start, ' ');

        if (event_end) {
            size_t event_len = event_end - event_start;
            char *event_name = strndup(event_start, event_len);
            void *data = kvlist_get(&ctxt->event_handlers, event_name);
            if (data == NULL) {
                LOG_WARN("Unknown event name: %s\n", event_name);
            }
            else {
                event_handler handler;
                handler = *(event_handler *)data;
                if (handler)
                    return handler(ctxt, event_end + 1, len - 11 - event_len - 1);
                else {
                    LOG_WARN("Ignore event: %s\n", event_name);
                }
            }
        }
    }

    return 0;
}

