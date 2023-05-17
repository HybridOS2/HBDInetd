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
#include <linux/wireless.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

bool is_valid_interface_name(const char *ifname)
{
    return purc_is_valid_token(ifname, IFNAMSIZ - 1);
}

#if 0
    if (ifname[0] == 'e') {
        netdev->type = DEVICE_TYPE_ETHER_WIRED;
    }
    else if (ifname[0] == 'w') {
        netdev->type = DEVICE_TYPE_ETHER_WIRELESS;
        netdev->on = wifi_device_on;
        netdev->off = wifi_device_off;
        netdev->check = wifi_device_check;
    }
    else {
        /* TODO */
        netdev->type = DEVICE_TYPE_UNKNOWN;
    }
#endif

static int get_device_type(struct network_device * netdev,
        const char *ifname, int fd)
{
    bool opened = false;

    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return -1;
        }

        opened = true;
    }

    struct iwreq wrq;
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIWNAME, &wrq);
    if (ret == 0) {
        netdev->type = DEVICE_TYPE_ETHER_WIRELESS;
        netdev->on = wifi_device_on;
        netdev->off = wifi_device_off;
        netdev->check = wifi_device_check;
        goto done;
    }
    else {
        struct ifreq ifr;
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
        if (ret == 0) {
            netdev->type = DEVICE_TYPE_ETHER_WIRED;
            goto done;
        }

        /* TODO: other types */
        netdev->type = DEVICE_TYPE_UNKNOWN;
    }

done:
    if (opened)
        close(fd);
    return 0;
}

void cleanup_network_device(struct network_device *netdev)
{
    if (netdev->hwaddr) {
        free(netdev->hwaddr);
        netdev->hwaddr = NULL;
    }

    if (netdev->ipv4.addr) {
        free(netdev->ipv4.addr);
        netdev->ipv4.addr = NULL;
    }

    if (netdev->ipv4.netmask) {
        free(netdev->ipv4.netmask);
        netdev->ipv4.netmask = NULL;
    }

    if (netdev->ipv4.hbdifa_dstaddr) {
        free(netdev->ipv4.hbdifa_dstaddr);
        netdev->ipv4.hbdifa_dstaddr = NULL;
    }

    if (netdev->ipv6.addr) {
        free(netdev->ipv6.addr);
        netdev->ipv6.addr = NULL;
    }

    if (netdev->ipv6.netmask) {
        free(netdev->ipv6.netmask);
        netdev->ipv6.netmask = NULL;
    }

    if (netdev->ipv6.hbdifa_dstaddr) {
        free(netdev->ipv6.hbdifa_dstaddr);
        netdev->ipv6.hbdifa_dstaddr = NULL;
    }
}

struct network_device *get_network_device_fixed_info(const char *ifname,
        struct network_device *netdev)
{
    int fd = -1;
    if (netdev == NULL) {
        netdev = calloc(1, sizeof(*netdev));
        if (netdev == NULL) {
            LOG_ERROR("Failed calloc()\n");
            goto failed;
        }
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        goto failed;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        goto failed;
    }

    netdev->flags = ifr.ifr_flags;
    if (netdev->flags & IFF_LOOPBACK) {
        netdev->type = DEVICE_TYPE_LOOPBACK;
    }
    else if (get_device_type(netdev, ifname, fd)) {
        goto failed;
    }

    if (netdev->type & DEVICE_TYPE_ETHER_MASK) {
        // get the hardware address of this interface
        if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
            LOG_ERROR("Failed ioctl(): %s\n", strerror(errno));
            goto failed;
        }

        char ap[100];
        snprintf(ap, sizeof(ap), "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
        netdev->hwaddr = strdup(ap);
    }
    else if (netdev->type == DEVICE_TYPE_ETHER_WIRELESS) {
        struct iwreq wrq;
        strncpy(wrq.ifr_name, ifname, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIWRATE, &wrq)) {
            LOG_ERROR("Failed ioctl(): %s\n", strerror(errno));
            goto failed;
        }
        netdev->bitrate = wrq.u.bitrate.value;
    }

    close(fd);
    fd = -1;

failed:
    if (fd >= 0)
        close(fd);

    return netdev;
}

int update_network_device_dynamic_info(const char *ifname,
        struct network_device *netdev)
{
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) == -1) {
        LOG_ERROR("Failed getifaddrs(): %s\n", strerror(errno));
        goto failed;
    }

    struct ifaddrs *address = addresses;
    while (address) {
        if (strcmp(address->ifa_name, ifname) == 0) {

            netdev->flags = address->ifa_flags;
            netdev->status = DEVICE_STATUS_UNCERTAIN;
            if (netdev->flags & IFF_UP) {
                if (netdev->flags & IFF_RUNNING)
                    netdev->status = DEVICE_STATUS_RUNNING;
                else
                    netdev->status = DEVICE_STATUS_UP;
            }
            else
                netdev->status = DEVICE_STATUS_DOWN;

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
                char ap[100];
                getnameinfo(address->ifa_addr, family_size,
                        ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
                hbdaddr->addr = strdup(ap);

                getnameinfo(address->ifa_netmask, family_size,
                        ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
                hbdaddr->netmask = strdup(ap);

                if (address->ifa_flags & IFF_POINTOPOINT) {
                    getnameinfo(address->ifa_dstaddr, family_size,
                            ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
                    hbdaddr->hbdifa_dstaddr = strdup(ap);
                }
                else {
                    getnameinfo(address->ifa_broadaddr, family_size,
                            ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
                    hbdaddr->hbdifa_broadaddr = strdup(ap);
                }
            }
        }

        address = address->ifa_next;
    }

    freeifaddrs(addresses);
    return 0;

failed:
    return -1;
}

int update_network_device_info(struct run_info *run_info, const char *ifname)
{
    void *data;
    struct network_device *netdev;

    data = kvlist_get(&run_info->devices, ifname);
    if (data == NULL) {
        netdev = calloc(1, sizeof(*netdev));
        if (netdev == NULL) {
            LOG_ERROR("Failed calloc()\n");
            goto failed;
        }

        if ((netdev->ifname = kvlist_set_ex(&run_info->devices,
                        ifname, &netdev)) == NULL) {
            LOG_ERROR("Failed kvlist_set_ex()\n");
            goto failed;
        }

        if (get_network_device_fixed_info(ifname, netdev) == NULL) {
            goto failed;
        }
    }
    else {
        netdev = *(struct network_device **)data;
        cleanup_network_device(netdev);
    }

    if (update_network_device_dynamic_info(ifname, netdev))
        goto failed;

    return 0;

failed:
    kvlist_remove(&run_info->devices, ifname);
    return -1;
}

void cleanup_network_devices(struct run_info *run_info)
{
    const char* name;
    void *data;
    kvlist_for_each(&run_info->devices, name, data) {
        struct network_device *netdev;
        netdev = *(struct network_device **)data;

        cleanup_network_device(netdev);
        free(netdev);
    }

    kvlist_free(&run_info->devices);
}

int enumerate_network_devices(struct run_info *run_info)
{
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) == -1) {
        LOG_ERROR("Failed getifaddrs(): %s\n", strerror(errno));
        goto failed;
    }

    struct ifaddrs *address = addresses;
    while (address) {
        void *data;
        struct network_device *netdev;
        data = kvlist_get(&run_info->devices, address->ifa_name);
        if (data == NULL) {
            netdev = calloc(1, sizeof(*netdev));
            if (netdev == NULL) {
                LOG_ERROR("Failed calloc()\n");
                goto failed;
            }

            if ((netdev->ifname = kvlist_set_ex(&run_info->devices,
                        address->ifa_name, &netdev)) == NULL) {
                LOG_ERROR("Failed kvlist_set_ex()\n");
                goto failed;
            }

            netdev->flags = address->ifa_flags;

            if (netdev->flags & IFF_LOOPBACK) {
                netdev->type = DEVICE_TYPE_LOOPBACK;
            }
            else if (get_device_type(netdev, address->ifa_name, -1)) {
                LOG_ERROR("Failed get_device_type(): %s\n", strerror(errno));
                goto failed;
            }
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


