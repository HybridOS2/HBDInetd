/*
 * Copyright 2023, HybridOS Community
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "netutils/ifc.h"
#include "netutils/dhcp.h"

#include "log.h"

static char errmsg[256] = "Ok";

const char *dhcp_lasterror()
{
    return errmsg;
}

int dhcp_get_last_conf_info(uint32_t *msg_type,
        char **ipaddr, char **gateway, char **netmask,
        char **dns1, char **dns2, char **server,
        uint32_t *lease)
{
    *msg_type = DHCPACK;
    *ipaddr = strdup("192.168.2.138");
    *gateway = strdup("192.168.2.1");
    *netmask = strdup("255.255.255.0");
    *dns1 = strdup("192.168.2.1");
    *dns2 = strdup("8.8.8.8");
    *server = strdup("192.168.2.1");
    *lease = 3600;

    if (*msg_type == DHCPACK) {
        return 0;
    }

    return -1;
}

const char *dhcp_msg_type_to_name(uint32_t type)
{
    switch (type) {
    case DHCPDISCOVER: return "discover";
    case DHCPOFFER:    return "offer";
    case DHCPREQUEST:  return "request";
    case DHCPDECLINE:  return "decline";
    case DHCPACK:      return "ack";
    case DHCPNAK:      return "nak";
    case DHCPRELEASE:  return "release";
    case DHCPINFORM:   return "inform";
    default:           return "???";
    }
}

int dhcp_do_overall(const char *ifname)
{
    (void)ifname;
    return 0;
}

int dhcp_request_renew(const char *ifname,
        const char *ip, const char *server)
{
    (void)ifname;
    (void)ip;
    (void)server;
    return 0;
}

int dhcp_release_lease(const char *ifname,
        const char *ip, const char *server)
{
    (void)ifname;
    (void)ip;
    (void)server;
    return 0;
}

