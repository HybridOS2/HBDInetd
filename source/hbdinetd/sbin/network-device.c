/*
** network-device.c -- The operations for network devices.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

void cleanup_network_devices(struct run_info *run_info)
{
    const char* name;
    void *data;
    kvlist_for_each(&run_info->devices, name, data) {
        struct network_device *netdev;
        netdev = *(struct network_device **)data;

        if (netdev->ipv4.addr) {
            free(netdev->ipv4.addr);
        }

        if (netdev->ipv4.netmask) {
            free(netdev->ipv4.netmask);
        }

        if (netdev->ipv4.hbdifa_dstaddr) {
            free(netdev->ipv4.hbdifa_dstaddr);
        }

        if (netdev->ipv6.addr) {
            free(netdev->ipv6.addr);
        }

        if (netdev->ipv6.netmask) {
            free(netdev->ipv6.netmask);
        }

        if (netdev->ipv6.hbdifa_dstaddr) {
            free(netdev->ipv6.hbdifa_dstaddr);
        }
    }

    kvlist_free(&run_info->devices);
}

int enumerate_network_devices(struct run_info *run_info)
{
    (void)run_info;

    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) == -1) {
        LOG_ERROR("getifaddrs call failed\n");
        return -1;
    }

    struct ifaddrs *address = addresses;
    while (address) {
        void *data;
        struct network_device *netdev;
        data = kvlist_get(&run_info->devices, address->ifa_name);
        if (data == NULL) {
            netdev = calloc(1, sizeof(*netdev));
            if (kvlist_set_ex(&run_info->devices, address->ifa_name,
                    &netdev) == NULL)
                goto failed;

            if (netdev->flags & IFF_LOOPBACK) {
                netdev->type = DEVICE_TYPE_LOOPBACK;
            }
            else if (address->ifa_name[0] == 'e') {
                netdev->type = DEVICE_TYPE_ETHER_WIRED;
            }
            else if (address->ifa_name[0] == 'w') {
                netdev->type = DEVICE_TYPE_ETHER_WIRELESS;
            }
            else {
                /* TODO */
                netdev->type = DEVICE_TYPE_UNKONWN;
            }

            netdev->flags = address->ifa_flags;
        }
        else {
            netdev = *(struct network_device **)data;
        }

        size_t family_size;
        int family = address->ifa_addr->sa_family;
        struct hbd_ifaddr *hbdaddr;
        if (family == AF_INET) {
            family_size = sizeof(struct sockaddr_in);
            hbdaddr = &netdev->ipv4;
        }
        else if (family == AF_INET6) {
            family_size = sizeof(struct sockaddr_in6);
            hbdaddr = &netdev->ipv6;
        }
        else {
            family_size = 0;
            hbdaddr = NULL;
        }

        if (hbdaddr) {
            if (hbdaddr->addr) {
                free(hbdaddr->addr);
                hbdaddr->addr = NULL;
            }

            if (hbdaddr->netmask) {
                free(hbdaddr->netmask);
                hbdaddr->netmask = NULL;
            }

            if (hbdaddr->hbdifa_dstaddr) {
                free(hbdaddr->hbdifa_dstaddr);
                hbdaddr->hbdifa_dstaddr = NULL;
            }

            char ap[100];
            getnameinfo(address->ifa_addr, family_size, ap, sizeof(ap),
                    0, 0, NI_NUMERICHOST);
            hbdaddr->addr = strdup(ap);

            getnameinfo(address->ifa_netmask, family_size, ap, sizeof(ap),
                    0, 0, NI_NUMERICHOST);
            hbdaddr->netmask = strdup(ap);

            if (address->ifa_flags & IFF_POINTOPOINT) {
                getnameinfo(address->ifa_dstaddr, family_size, ap, sizeof(ap),
                        0, 0, NI_NUMERICHOST);
                hbdaddr->hbdifa_dstaddr = strdup(ap);
            }
            else {
                getnameinfo(address->ifa_broadaddr, family_size, ap, sizeof(ap),
                        0, 0, NI_NUMERICHOST);
                hbdaddr->hbdifa_broadaddr = strdup(ap);
            }
        }

        address = address->ifa_next;
    }
    freeifaddrs(addresses);
    return 0;

failed:
    if (addresses)
        freeifaddrs(addresses);
    cleanup_network_devices(run_info);
    return -1;
}


