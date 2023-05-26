/*
 * Copyright 2023, HybridOS Community
 * Copyright 2010, The Android Open Source Project
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

#ifndef _NETUTILS_DHCP_H_
#define _NETUTILS_DHCP_H_

#include <sys/cdefs.h>

/* DHCP message types */
#define DHCPDISCOVER         1
#define DHCPOFFER            2
#define DHCPREQUEST          3
#define DHCPDECLINE          4
#define DHCPACK              5
#define DHCPNAK              6
#define DHCPRELEASE          7
#define DHCPINFORM           8

__BEGIN_DECLS

extern int dhcp_do_overall(const char *iname);
extern int dhcp_request_renew(const char *ifname,
        const char *ipaddr, const char *serveraddr);
extern int dhcp_release_lease(const char *ifname,
        const char *ipaddr, const char *serveraddr);

extern int dhcp_get_last_conf_info(uint32_t *msg_type,
        char **ipaddr, char **gateway, char **netmask,
        char **dns1, char **dns2, char **server,
        uint32_t *lease);
const char *dhcp_msg_type_to_name(uint32_t type);

__END_DECLS

#endif /* _NETUTILS_DHCP_H_ */
