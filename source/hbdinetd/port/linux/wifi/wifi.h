/*
** wifi.h -- The internal header for WiFi device on Linux.
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

#ifndef _hbdinetd_port_linux_wifi_wifi_h
#define _hbdinetd_port_linux_wifi_wifi_h

#include "wpa-client/wpa_ctrl.h"

#include "list.h"
#include "kvlist.h"

#define PATH_WPA_SUPPLICANT     "/sbin/wpa_supplicant"

#define WIFI_SUPP_CTRL_DIR      "/var/run/wpa_supplicant-hbd"
#define WIFI_SUPP_PID_FILE      "/var/run/wpa_supplicant-hbd/pid"
#define WIFI_ENTROPY_FILE       "/var/run/wpa_supplicant-hbd/entropy.bin"
#define WIFI_SUPP_CONFIG_FILE   "/etc/wpa_supplicant-hbd.conf"
#define WIFI_SUPP_CONFIG_TEMPLATE   \
    "/app/" HBDINETD_APP_NAME "/share/doc/wpa_supplicant.conf"

#define PATH_DHCLIENT           "/sbin/dhclient"
#define DHCLIENT_CONF_DIR       "/etc/dhcp/"
#define DHCLIENT_CONF_FILE      "/etc/dhcp/dhclient-hbd.conf"
#define DHCLIENT_LESS_FILE      "/etc/dhcp/dhclient-hbd.leases"
#define DHCLIENT_PID_FILE       "/var/run/dhclient-hbd.pid"
#define DHCLIENT_SCRIPT_FILE    "/sbin/dhclient-script"

#define WIFI_MSG_BUF_SIZE                   4096
#define MAX_RETRIES_ON_AUTH_FAILURE         3

#define DEF_UPDATE_INTERVAL                 10  /* seconds */

struct netdev_context {
    struct network_device *netdev;
    struct wpa_ctrl *ctrl_conn;
    struct wpa_ctrl *monitor_conn;
    int exit_sockets[2];

    /* the new network id if >= 0. */
    int new_netid;
    int trying_netid;

    unsigned auth_failure_count;
    unsigned cmd_failure_count;

    /* the buffer use for event or reply. */
    char *buf;

    time_t last_update_time;

    struct list_head hotspots;
    struct kvlist event_handlers;
    struct kvlist saved_networks;
    struct wifi_status *status;
};

#ifdef __cplusplus
extern "C" {
#endif

#if 0 /* not implemented so far */
/**
 * Load the Wi-Fi driver.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_load_driver();

/**
 * Unload the Wi-Fi driver.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_unload_driver();

/**
 * Check if the Wi-Fi driver is loaded.
 *
 * @return 0 on success, < 0 on failure.
 */
int is_wifi_driver_loaded();

/**
 * Return the path to requested firmware
 */
#define WIFI_GET_FW_PATH_STA	0
#define WIFI_GET_FW_PATH_AP	1
#define WIFI_GET_FW_PATH_P2P	2
const char *wifi_get_fw_path(int fw_type);

/**
 * Change the path to firmware for the wlan driver
 */
int wifi_change_fw_path(const char *fwpath);

#endif /* not implemented */

/**
 * Start supplicant.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_start_supplicant(struct netdev_context *ctxt, int p2pSupported);

/**
 * Stop supplicant.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_stop_supplicant(struct netdev_context *ctxt);

/**
 * Open a connection to supplicant
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_connect_to_supplicant(struct netdev_context *ctxt);

/**
 * Close connection to supplicant
 *
 * @return 0 on success, < 0 on failure.
 */
void wifi_close_supplicant_connection(struct netdev_context *ctxt);

/**
 * wifi_wait_for_event() performs a blocking call to
 * get a Wi-Fi event and returns a string representing
 * a Wi-Fi event when it occurs.
 *
 * @param buf is the buffer that receives the event
 * @param len is the maximum length of the buffer
 *
 * @returns number of bytes in buffer, 0 if no
 * event (for instance, no connection), and less than 0
 * if there is an error.
 */
int wifi_wait_for_event(struct netdev_context *ctxt, char *buf, size_t len);

/**
 * wifi_command() issues a command to the Wi-Fi driver.
 *
 * @param command is the string command (preallocated with 32 bytes)
 * @param commandlen is command buffer length
 * @param reply is a buffer to receive a reply string
 * @param reply_len on entry, this is the maximum length of
 *        the reply buffer. On exit, the length of the reply in the buffer.
 *
 * @return 0 if successful, < 0 if an error.
 */
int wifi_command(struct netdev_context *ctxt, const char *command,
        char *reply, size_t *reply_len);

/**
 * do_dhcp_request() issues a dhcp request and returns the acquired
 * information.
 *
 * All IPV4 addresses/mask are in network byte order.
 *
 * @param ipaddr return the assigned IPV4 address
 * @param gateway return the gateway being used
 * @param mask return the IPV4 mask
 * @param dns1 return the IPV4 address of a DNS server
 * @param dns2 return the IPV4 address of a DNS server
 * @param server return the IPV4 address of DHCP server
 * @param lease return the length of lease in seconds.
 *
 * @return 0 if successful, < 0 if error.
 */
int do_dhcp_request(struct netdev_context *ctxt,
        int *ipaddr, int *gateway, int *mask,
        int *dns1, int *dns2, int *server, int *lease);

/**
 * Return the error string of the last do_dhcp_request().
 */
const char *get_dhcp_error_string(struct netdev_context *ctxt);

/** issue dhcp request by calling dhclient */
int wifi_issue_dhcp_request(struct netdev_context *ctxt);

/**
 * PATH_MAX
 */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifdef __cplusplus
};  // extern "C"
#endif

#endif  // _hbdinetd_port_linux_wifi_wifi_h

