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
**
** This file is derived from Android:
**
** Copyright (C) 2008 The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>

#include "internal.h"
#include "wpa-client/wpa_ctrl.h"
#include "log.h"
#include "wifi.h"

#define IFACE_VALUE_MAX 32

static const char SUPP_CONFIG_TEMPLATE[]= WIFI_SUPP_CONFIG_TEMP;
static const char SUPP_CONFIG_FILE[]    = WIFI_SUPP_CONFIG_FILE;
static const char CONTROL_IFACE_PATH[]  = WIFI_SUPP_CTRL_DIR;
static const char SUPP_ENTROPY_FILE[]   = WIFI_ENTROPY_FILE;

static const unsigned char dummy_key[21] = { 0x02, 0x11, 0xbe, 0x33, 0x43, 0x35,
                                       0x68, 0x47, 0x84, 0x99, 0xa9, 0x2b,
                                       0x1c, 0xd3, 0xee, 0xff, 0xf1, 0xe2,
                                       0xf3, 0xf4, 0xf5 };

static const char IFNAME[]              = "IFNAME=";
#define IFNAMELEN            (sizeof(IFNAME) - 1)
static const char WPA_EVENT_IGNORE[]    = "CTRL-EVENT-IGNORE ";

int ensure_entropy_file_exists(void)
{
    int ret;
    int destfd;

    ret = access(SUPP_ENTROPY_FILE, R_OK|W_OK);
    if ((ret == 0) || (errno == EACCES)) {
        if ((ret != 0) &&
            (chmod(SUPP_ENTROPY_FILE, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) != 0)) {
            HLOG_ERR("Cannot set RW to \"%s\": %s\n", SUPP_ENTROPY_FILE, strerror(errno));
            return -1;
        }
        return 0;
    }
    destfd = TEMP_FAILURE_RETRY(open(SUPP_ENTROPY_FILE, O_CREAT|O_RDWR, 0660));
    if (destfd < 0) {
        HLOG_ERR("Cannot create \"%s\": %s\n", SUPP_ENTROPY_FILE, strerror(errno));
        return -1;
    }

    if (TEMP_FAILURE_RETRY(write(destfd, dummy_key, sizeof(dummy_key))) != sizeof(dummy_key)) {
        HLOG_ERR("Error writing \"%s\": %s\n", SUPP_ENTROPY_FILE, strerror(errno));
        close(destfd);
        return -1;
    }
    close(destfd);

    /* chmod is needed because open() didn't set permisions properly */
    if (chmod(SUPP_ENTROPY_FILE, 0660) < 0) {
        HLOG_ERR("Error changing permissions of %s to 0660: %s\n",
             SUPP_ENTROPY_FILE, strerror(errno));
        unlink(SUPP_ENTROPY_FILE);
        return -1;
    }

    return 0;
}

static int update_ctrl_interface(struct netdev_context *ctxt,
        const char *config_file)
{
    (void)ctxt;
    int srcfd, destfd;
    int nread;
    char ifc[IFACE_VALUE_MAX];
    char *pbuf;
    char *sptr;
    struct stat sb;
    int ret;

    if (stat(config_file, &sb) != 0)
        return -1;

    pbuf = (char *)malloc(sb.st_size + IFACE_VALUE_MAX);
    if (!pbuf)
        return 0;
    srcfd = TEMP_FAILURE_RETRY(open(config_file, O_RDONLY));
    if (srcfd < 0) {
        HLOG_ERR("Cannot open \"%s\": %s\n", config_file, strerror(errno));
        free(pbuf);
        return 0;
    }
    nread = TEMP_FAILURE_RETRY(read(srcfd, pbuf, sb.st_size));
    close(srcfd);
    if (nread < 0) {
        HLOG_ERR("Cannot read \"%s\": %s\n", config_file, strerror(errno));
        free(pbuf);
        return 0;
    }

    strcpy(ifc, CONTROL_IFACE_PATH);

    /* Assume file is invalid to begin with */
    ret = -1;
    /*
     * if there is a "ctrl_interface=<value>" entry, re-write it ONLY if it is
     * NOT a directory.  The non-directory value option is an Android add-on
     * that allows the control interface to be exchanged through an environment
     * variable (initialized by the "init" program when it starts a service
     * with a "socket" option).
     *
     * The <value> is deemed to be a directory if the "DIR=" form is used or
     * the value begins with "/".
     */
    if ((sptr = strstr(pbuf, "ctrl_interface="))) {
        ret = 0;
        if ((!strstr(pbuf, "ctrl_interface=DIR=")) &&
                (!strstr(pbuf, "ctrl_interface=/"))) {
            char *iptr = sptr + strlen("ctrl_interface=");
            int ilen = 0;
            int mlen = strlen(ifc);
            if (strncmp(ifc, iptr, mlen) != 0) {
                HLOG_ERR("ctrl_interface != %s\n", ifc);
                while (((ilen + (iptr - pbuf)) < nread) && (iptr[ilen] != '\n'))
                    ilen++;
                mlen = ((ilen >= mlen) ? ilen : mlen) + 1;
                memmove(iptr + mlen, iptr + ilen + 1, nread - (iptr + ilen + 1 - pbuf));
                memset(iptr, '\n', mlen);
                memcpy(iptr, ifc, strlen(ifc));
                destfd = TEMP_FAILURE_RETRY(open(config_file, O_RDWR, 0660));
                if (destfd < 0) {
                    HLOG_ERR("Cannot update \"%s\": %s\n", config_file, strerror(errno));
                    free(pbuf);
                    return -1;
                }
                TEMP_FAILURE_RETRY(write(destfd, pbuf, nread + mlen - ilen -1));
                close(destfd);
            }
        }
    }
    free(pbuf);
    return ret;
}

static int ensure_config_file_exists(struct netdev_context *ctxt,
        const char *config_file)
{
    char buf[2048];
    int srcfd, destfd;
    int nread;
    int ret;

    ret = access(config_file, R_OK|W_OK);
    if ((ret == 0) || (errno == EACCES)) {
        if ((ret != 0) &&
            (chmod(config_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) != 0)) {
            HLOG_ERR("Cannot set RW to \"%s\": %s\n", config_file, strerror(errno));
            return -1;
        }
        /* return if we were able to update control interface properly */
        if (update_ctrl_interface(ctxt, config_file) >=0) {
            return 0;
        } else {
            /* This handles the scenario where the file had bad data
             * for some reason. We continue and recreate the file.
             */
        }
    } else if (errno != ENOENT) {
        HLOG_ERR("Cannot access \"%s\": %s\n", config_file, strerror(errno));
        return -1;
    }

    srcfd = TEMP_FAILURE_RETRY(open(SUPP_CONFIG_TEMPLATE, O_RDONLY));
    if (srcfd < 0) {
        HLOG_ERR("Cannot open \"%s\": %s\n", SUPP_CONFIG_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = TEMP_FAILURE_RETRY(open(config_file, O_CREAT|O_RDWR, 0660));
    if (destfd < 0) {
        close(srcfd);
        HLOG_ERR("Cannot create \"%s\": %s\n", config_file, strerror(errno));
        return -1;
    }

    while ((nread = TEMP_FAILURE_RETRY(read(srcfd, buf, sizeof(buf)))) != 0) {
        if (nread < 0) {
            HLOG_ERR("Error reading \"%s\": %s\n", SUPP_CONFIG_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(config_file);
            return -1;
        }
        TEMP_FAILURE_RETRY(write(destfd, buf, nread));
    }

    close(destfd);
    close(srcfd);

    /* chmod is needed because open() didn't set permisions properly */
    if (chmod(config_file, 0660) < 0) {
        HLOG_ERR("Error changing permissions of %s to 0660: %s\n",
             config_file, strerror(errno));
        unlink(config_file);
        return -1;
    }

    return update_ctrl_interface(ctxt, config_file);
}

int wifi_start_supplicant(struct netdev_context *ctxt, int p2p_supported)
{
    (void)p2p_supported;
//    char cmd[512] = {0};

    /* Before starting the daemon, make sure its config file exists */
    if (ensure_config_file_exists(ctxt, SUPP_CONFIG_FILE) < 0) {
        HLOG_ERR("Wi-Fi will not be enabled\n");
        return -1;
    }

    if (ensure_entropy_file_exists() < 0) {
        HLOG_ERR("Wi-Fi entropy file was not created\n");
    }

    /* Clear out any stale socket files that might be left over. */
    //wpa_ctrl_cleanup();

    /* Reset sockets used for exiting from hung state */
    ctxt->exit_sockets[0] = ctxt->exit_sockets[1] = -1;

    /* start wpa_supplicant */
//    strncpy(cmd, "/etc/wifi/wifi start", 511);            // gengyue
//    cmd[511] = '\0';
//    system(cmd);

    return 0;
}

int wifi_stop_supplicant(struct netdev_context *ctxt)
{
    (void)ctxt;
//      system("/etc/wifi/wifi stop");                        // gengyue
      return 0;
}

#define SUPPLICANT_TIMEOUT      3000000  // microseconds
#define SUPPLICANT_TIMEOUT_STEP  100000  // microseconds
static int
wifi_connect_on_socket_path(struct netdev_context *ctxt, const char *path)
{
    int  supplicant_timeout = SUPPLICANT_TIMEOUT;

    ctxt->ctrl_conn = wpa_ctrl_open(path);
    while (ctxt->ctrl_conn == NULL && supplicant_timeout > 0){
        usleep(SUPPLICANT_TIMEOUT_STEP);
        supplicant_timeout -= SUPPLICANT_TIMEOUT_STEP;
        ctxt->ctrl_conn = wpa_ctrl_open(path);
    }

    if (ctxt->ctrl_conn == NULL) {
        HLOG_ERR("Unable to open connection to supplicant on \"%s\": %s\n",
             path, strerror(errno));
        return -1;
    }

    ctxt->monitor_conn = wpa_ctrl_open(path);
    if (ctxt->monitor_conn == NULL) {
        wpa_ctrl_close(ctxt->ctrl_conn);
        ctxt->ctrl_conn = NULL;
        return -1;
    }

    if (wpa_ctrl_attach(ctxt->monitor_conn) != 0) {
        wpa_ctrl_close(ctxt->monitor_conn);
        wpa_ctrl_close(ctxt->ctrl_conn);
        ctxt->ctrl_conn = ctxt->monitor_conn = NULL;
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ctxt->exit_sockets) == -1) {
        wpa_ctrl_close(ctxt->monitor_conn);
        wpa_ctrl_close(ctxt->ctrl_conn);
        ctxt->ctrl_conn = ctxt->monitor_conn = NULL;
        return -1;
    }

    return 0;
}

/* Establishes the control and monitor socket connections on the interface */
int wifi_connect_to_supplicant(struct netdev_context *ctxt)
{
    char socket_path[sizeof(WIFI_SUPP_CTRL_DIR) + IFNAMSIZ + 1];

    if (access(WIFI_SUPP_CTRL_DIR, F_OK) == 0) {
        int ret = snprintf(socket_path, sizeof(socket_path),
                "%s/%s", WIFI_SUPP_CTRL_DIR, ctxt->netdev->ifname);
        if (ret < 0 && ret >= (int)sizeof(socket_path))
            goto failed;
    }
    else {
        goto failed;
    }

    return wifi_connect_on_socket_path(ctxt, socket_path);

failed:
    return -1;
}

int wifi_send_command(struct netdev_context *ctxt,
        const char *cmd, char *reply, size_t *reply_len)
{
    int ret;

    if (ctxt->ctrl_conn == NULL) {
        HLOG_ERR("Not connected to wpa_supplicant - \"%s\" command dropped.\n", cmd);
        return -1;
    }

    ret = wpa_ctrl_request(ctxt->ctrl_conn, cmd, strlen(cmd), reply, reply_len, NULL);
    if (ret == -2) {
        HLOG_ERR("'%s' command timed out.\n", cmd);
        /* unblocks the monitor receive socket for termination */
        TEMP_FAILURE_RETRY(write(ctxt->exit_sockets[0], "T", 1));
        return -2;
    } else if (ret < 0 || strncmp(reply, "FAIL", 4) == 0) {
        return -1;
    }
    if (strncmp(cmd, "PING", 4) == 0) {
        reply[*reply_len] = '\0';
    }
    return 0;
}

static int
wifi_ctrl_recv(struct netdev_context *ctxt, char *reply, size_t *reply_len)
{
    int res;
    int ctrlfd = wpa_ctrl_get_fd(ctxt->monitor_conn);
    struct pollfd rfds[2];

    memset(rfds, 0, 2 * sizeof(struct pollfd));
    rfds[0].fd = ctrlfd;
    rfds[0].events |= POLLIN;
    rfds[1].fd = ctxt->exit_sockets[1];
    rfds[1].events |= POLLIN;
    res = TEMP_FAILURE_RETRY(poll(rfds, 2, -1));
    if (res < 0) {
        HLOG_ERR("Error poll = %d\n", res);
        return res;
    }
    if (rfds[0].revents & POLLIN) {
        return wpa_ctrl_recv(ctxt->monitor_conn, reply, reply_len);
    }

    /* it is not rfds[0], then it must be rfts[1] (i.e. the exit socket)
     * or we timed out. In either case, this call has failed ..
     */
    return -2;
}

static int
wifi_wait_on_socket(struct netdev_context *ctxt, char *buf, size_t buflen)
{
    size_t nread = buflen - 1;
    int result;
    char *match, *match2;

    if (ctxt->monitor_conn == NULL) {
        return snprintf(buf, buflen, WPA_EVENT_TERMINATING " - connection closed");
    }

    result = wifi_ctrl_recv(ctxt, buf, &nread);

    /* Terminate reception on exit socket */
    if (result == -2) {
        return snprintf(buf, buflen, WPA_EVENT_TERMINATING " - connection closed");
    }

    if (result < 0) {
        HLOG_ERR("wifi_ctrl_recv failed: %s\n", strerror(errno));
        return snprintf(buf, buflen, WPA_EVENT_TERMINATING " - recv error");
    }
    buf[nread] = '\0';

    HLOG_INFO("read from wpa: %s\n", buf);

    /* Check for EOF on the socket */
    if (result == 0 && nread == 0) {
        /* Fabricate an event to pass up */
        HLOG_ERR("Received EOF on supplicant socket\n");
        return snprintf(buf, buflen, WPA_EVENT_TERMINATING " - signal 0 received");
    }
    /*
     * Events strings are in the format
     *
     *     IFNAME=iface <N>CTRL-EVENT-XXX
     *        or
     *     <N>CTRL-EVENT-XXX
     *
     * where N is the message level in numerical form (0=VERBOSE, 1=DEBUG,
     * etc.) and XXX is the event name. The level information is not useful
     * to us, so strip it off.
     */

    if (strncmp(buf, IFNAME, IFNAMELEN) == 0) {
        match = strchr(buf, ' ');
        if (match != NULL) {
            if (match[1] == '<') {
                match2 = strchr(match + 2, '>');
                if (match2 != NULL) {
                    nread -= (match2 - match);
                    memmove(match + 1, match2 + 1, nread - (match - buf) + 1);
                }
            }
        } else {
            return snprintf(buf, buflen, "%s", WPA_EVENT_IGNORE);
        }
    } else if (buf[0] == '<') {
        match = strchr(buf, '>');
        if (match != NULL) {
            nread -= (match + 1 - buf);
            memmove(buf, match + 1, nread + 1);
            HLOG_ERR("supplicant generated an event without interface - %s\n",
                    buf);
        }
    } else {
        /* let the event go as is! */
        HLOG_ERR("supplicant generated an event without "
                "interface or message level - %s\n", buf);
    }

    return nread;
}

int
wifi_wait_for_event(struct netdev_context *ctxt, char *buf, size_t buflen)
{
    return wifi_wait_on_socket(ctxt, buf, buflen);
}

static void wifi_close_sockets(struct netdev_context *ctxt)
{
    if (ctxt->ctrl_conn != NULL) {
        wpa_ctrl_close(ctxt->ctrl_conn);
        ctxt->ctrl_conn = NULL;
    }

    if (ctxt->monitor_conn != NULL) {
        wpa_ctrl_detach(ctxt->monitor_conn);
        wpa_ctrl_close(ctxt->monitor_conn);
        ctxt->monitor_conn = NULL;
    }

    if (ctxt->exit_sockets[0] >= 0) {
        close(ctxt->exit_sockets[0]);
        ctxt->exit_sockets[0] = -1;
    }

    if (ctxt->exit_sockets[1] >= 0) {
        close(ctxt->exit_sockets[1]);
        ctxt->exit_sockets[1] = -1;
    }
}

void wifi_close_supplicant_connection(struct netdev_context *ctxt)
{
    int count = 10; /* wait 2 seconds to ensure init has stopped stupplicant */

    wifi_close_sockets(ctxt);

    while (count-- > 0) {
        usleep(100000);
    }
}

int wifi_command(struct netdev_context *ctxt,
        char const *cmd, char *reply, size_t reply_len)
{
    if(!cmd || !cmd[0]){
        return -1;
    }

    if (strncmp(cmd, "SAVE_CONFIG", strlen("SAVE_CONFIG")) == 0)
        return 0;

    HLOG_INFO("do cmd %s\n", cmd);

    --reply_len; // Ensure we have room to add NUL termination.
    if (wifi_send_command(ctxt, cmd, reply, &reply_len) != 0) {
        return -1;
    }

    // Strip off trailing newline.
    if (reply_len > 0 && reply[reply_len-1] == '\n') {
        reply[reply_len-1] = '\0';
    } else {
        reply[reply_len] = '\0';
    }
    return 0;
}

