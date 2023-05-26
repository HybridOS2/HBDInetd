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

#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

#define IFNAMSIZ        63
#define IFF_UP          0x01
#define IFF_RUNNING     0x02

bool is_valid_interface_name(const char *ifname)
{
    return purc_is_valid_token(ifname, IFNAMSIZ - 1);
}

struct network_device *get_network_device_fixed_info(const char *ifname,
        struct network_device *netdev)
{
    if (netdev == NULL) {
        netdev = calloc(1, sizeof(*netdev));
        if (netdev == NULL) {
            HLOG_ERR("Failed calloc()\n");
            goto failed;
        }
    }

    if (strcmp(ifname, "lo") == 0) {
        netdev->type = DEVICE_TYPE_LOOPBACK;
    }
    else if (ifname[0] == 'w') {
        netdev->type = DEVICE_TYPE_ETHER_WIRELESS;
        netdev->hwaddr = strdup("24:41:8c:8f:1c:27");
    }
    else if (ifname[0] == 'e') {
        netdev->type = DEVICE_TYPE_ETHER_WIRED;
        netdev->hwaddr = strdup("00:e0:4c:36:01:5f");
    }
    else {
        netdev->type = DEVICE_TYPE_UNKNOWN;
    }

    if (netdev->type == DEVICE_TYPE_ETHER_WIRELESS) {
        netdev->bitrate = 100000000;
    }

failed:
    return netdev;
}

int update_network_device_dynamic_info(const char *ifname,
        struct network_device *netdev)
{
    struct hbd_ifaddr *hbdaddr;
    if (strcmp(ifname, "lo") == 0) {
        netdev->status = DEVICE_STATUS_RUNNING;

        if (netdev->flags & IFF_RUNNING) {
            hbdaddr = &netdev->ipv4;
            hbdaddr->addr = strdup("127.0.0.1");
            hbdaddr->netmask = strdup("255.0.0.0");

            hbdaddr = &netdev->ipv6;
            hbdaddr->addr = strdup("::1");
        }
    }
    else if (ifname[0] == 'e') {
        netdev->type = DEVICE_TYPE_ETHER_WIRED;

        if (netdev->flags & IFF_RUNNING) {
            hbdaddr = &netdev->ipv4;
            hbdaddr->addr = strdup("192.168.2.77");
            hbdaddr->netmask = strdup("255.255.255.0");
            hbdaddr->hbdifa_broadaddr = strdup("192.168.2.255");

            hbdaddr = &netdev->ipv6;
            hbdaddr->addr = strdup("fe80::583a:5e2d:fa3f:14ad");
        }
    }

    return 0;
}

static struct iface {
    const char *name;
    unsigned    flags;
} ifaces[] = {
    { "lo",     IFF_UP | IFF_RUNNING },
    { "eth0",   IFF_UP | IFF_RUNNING },
    { "wlan0",  0 },
};

int enumerate_network_devices(struct run_info *run_info)
{
    for (size_t i = 0; i < PCA_TABLESIZE(ifaces); i++) {
        void *data;
        struct network_device *netdev;
        data = kvlist_get(&run_info->devices, ifaces[i].name);

        if (data == NULL) {
            netdev = calloc(1, sizeof(*netdev));
            if (netdev == NULL) {
                HLOG_ERR("Failed calloc()\n");
                goto failed;
            }

            if ((netdev->ifname = kvlist_set_ex(&run_info->devices,
                        ifaces[i].name, &netdev)) == NULL) {
                HLOG_ERR("Failed kvlist_set_ex()\n");
                goto failed;
            }

            netdev->flags = ifaces[i].flags;
            get_network_device_fixed_info(ifaces[i].name, netdev);
        }
        else {
            netdev = *(struct network_device **)data;
            cleanup_network_device_dynamic_info(netdev);
        }

        update_network_device_dynamic_info(ifaces[i].name, netdev);
    }

    return 0;

failed:
    cleanup_network_devices(run_info);
    return -1;
}

int netdev_config_iface_up(const char *ifname, struct network_device *netdev)
{
    if (netdev->flags & IFF_UP)
        return 0;

    netdev->flags |= IFF_UP;
    cleanup_network_device_dynamic_info(netdev);
    return update_network_device_dynamic_info(ifname, netdev);
}

int netdev_config_iface_down(const char *ifname, struct network_device *netdev)
{
    if (!(netdev->flags & IFF_UP))
        return 0;

    netdev->flags &= ~IFF_UP;
    cleanup_network_device_dynamic_info(netdev);
    return update_network_device_dynamic_info(ifname, netdev);
}


