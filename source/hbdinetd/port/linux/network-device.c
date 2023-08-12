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

static const char *get_type_name(const struct network_device *netdev)
{
    switch (netdev->type) {
    case DEVICE_TYPE_UNKNOWN:
        return DEVICE_TYPE_NAME_UNKNOWN;
    case DEVICE_TYPE_LOOPBACK:
        return DEVICE_TYPE_NAME_LOOPBACK;
    case DEVICE_TYPE_MOBILE:
        return DEVICE_TYPE_NAME_MOBILE;
    case DEVICE_TYPE_ETHER_WIRED:
        return DEVICE_TYPE_NAME_ETHER_WIRED;
    case DEVICE_TYPE_ETHER_WIRELESS:
        return DEVICE_TYPE_NAME_ETHER_WIRELESS;
    }

    return NULL;
};

static const char *get_status_name(const struct network_device *netdev)
{
    switch (netdev->status) {
    case DEVICE_STATUS_UNCERTAIN:
        return DEVICE_STATUS_NAME_UNCERTAIN;
    case DEVICE_STATUS_DOWN:
        return DEVICE_STATUS_NAME_DOWN;
    case DEVICE_STATUS_UP:
        return DEVICE_STATUS_NAME_UP;
    case DEVICE_STATUS_RUNNING:
        return DEVICE_STATUS_NAME_RUNNING;
    }

    return NULL;
}

static int wired_device_config(hbdbus_conn *conn,
        struct network_device *netdev, const char *param);
static int wired_device_check(hbdbus_conn *conn,
        struct network_device *netdev);

static int wired_device_on(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;
    int ret = 0;

    if (netdev_config_iface_up(netdev->ifname, netdev)) {
        HLOG_ERR("Failed to make wired device up: %s!\n", netdev->ifname);
        ret = errno;
    }

    if (update_network_device_dynamic_info(netdev->ifname, netdev)) {
        HLOG_ERR("Failed to update status of wired device: %s!\n",
                netdev->ifname);
        ret = errno;
    }

    netdev->config = wired_device_config;
    netdev->check = wired_device_check;
    return ret;
}

static int wired_device_config(hbdbus_conn *conn, struct network_device *netdev,
        const char *param)
{
    (void)conn;

    if (netdev->status != DEVICE_STATUS_UP &&
            netdev->status != DEVICE_STATUS_RUNNING) {
        return ERR_DEVICE_NOT_READY;
    }

    int errcode = ERR_OK;
    purc_variant_t jo = NULL;
    purc_variant_t jo_tmp = NULL;

    jo = purc_variant_make_from_json_string(param, strlen(param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        errcode = EINVAL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "method")) == NULL) {
        HLOG_ERR("No `method` key\n");
        errcode = ENOKEY;
        goto done;
    }

    const char *method = purc_variant_get_string_const(jo_tmp);
    if (method == NULL) {
        HLOG_ERR("No configuring method specified.\n");
        errcode = EINVAL;
    }
    else if (strcasecmp(method, "dhcp") == 0) {
        issue_dhcp_request(conn, netdev->ifname);
    }
    else if (strcasecmp(method, "static") == 0) {
        /* TODO */
        HLOG_ERR("Not supported configuring method: %s\n", method);
        errcode = ENOTSUP;
    }
    else {
        HLOG_ERR("Bad configuring method: %s\n", method);
        errcode = EINVAL;
    }

done:
    if (jo)
        purc_variant_unref(jo);
    return errcode;
}

static int wired_device_off(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;
    int ret = 0;

    if (netdev_config_iface_down(netdev->ifname, netdev)) {
        HLOG_ERR("Failed to make wired device down: %s!\n", netdev->ifname);
        ret = errno;
    }

    netdev->check = NULL;
    return ret;
}

static int wired_device_check(hbdbus_conn *conn, struct network_device *netdev)
{
    unsigned old_status = netdev->status;
    int ret = 0;

    if (update_network_device_dynamic_info(netdev->ifname, netdev)) {
        HLOG_ERR("Failed to update status of wired device: %s!\n",
                netdev->ifname);
        ret = errno;
    }
    else if (netdev->status != old_status) {
        struct pcutils_printbuf my_buff, *pb = &my_buff;

        pcutils_printbuf_init(pb);
        pcutils_printbuf_format(pb,
                "{\"device\":\"%s\","
                "\"type\":\"%s\","
                "\"status\":\"%s\"}",
                netdev->ifname,
                get_type_name(netdev),
                get_status_name(netdev));

        if (pb->buf) {
            HLOG_INFO("Firing event: %s: %s\n", BUBBLE_DEVICECHANGED, pb->buf);
            ret = hbdbus_fire_event(conn, BUBBLE_DEVICECHANGED, pb->buf);
            free(pb->buf);
            if (ret)
                goto fatal;
        }
        else {
            HLOG_ERR("OOM when using printbuf\n");
            goto fatal;
        }
    }

    return 0;

fatal:
    return ret;
}

static void wired_device_terminate(struct network_device *netdev)
{
    (void)netdev;
}

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
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIWNAME, &wrq);
    if (ret == 0) {
        netdev->type = DEVICE_TYPE_ETHER_WIRELESS;
        netdev->on = wifi_device_on;
        netdev->config = wifi_device_config;
        netdev->off = wifi_device_off;
        netdev->check = wifi_device_check;
        netdev->terminate = wifi_device_terminate;
        goto done;
    }
    else {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
        if (ret == 0) {
            netdev->type = DEVICE_TYPE_ETHER_WIRED;
            netdev->on = wired_device_on;
            netdev->off = wired_device_off;
            netdev->terminate = wired_device_terminate;
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

struct network_device *get_network_device_fixed_info(const char *ifname,
        struct network_device *netdev)
{
    int fd = -1;
    if (netdev == NULL) {
        netdev = calloc(1, sizeof(*netdev));
        if (netdev == NULL) {
            HLOG_ERR("Failed calloc()\n");
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
            HLOG_ERR("Failed ioctl(): %s\n", strerror(errno));
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
            HLOG_ERR("Failed ioctl(): %s\n", strerror(errno));
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
        HLOG_ERR("Failed getifaddrs(): %s\n", strerror(errno));
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
                if (hbdaddr->addr) {
                    free(hbdaddr->addr);
                }

                if (hbdaddr->netmask) {
                    free(hbdaddr->netmask);
                }

                if (hbdaddr->hbdifa_dstaddr) {
                    free(hbdaddr->hbdifa_dstaddr);
                }

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

int enumerate_network_devices(struct run_info *run_info)
{
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) == -1) {
        HLOG_ERR("Failed getifaddrs(): %s\n", strerror(errno));
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
                HLOG_ERR("Failed calloc()\n");
                goto failed;
            }

            if ((netdev->ifname = kvlist_set_ex(&run_info->devices,
                        address->ifa_name, &netdev)) == NULL) {
                HLOG_ERR("Failed kvlist_set_ex()\n");
                goto failed;
            }

            netdev->flags = address->ifa_flags;

            if (netdev->flags & IFF_LOOPBACK) {
                netdev->type = DEVICE_TYPE_LOOPBACK;
            }
            else if (get_device_type(netdev, address->ifa_name, -1)) {
                HLOG_ERR("Failed get_device_type(): %s\n", strerror(errno));
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
            }

            if (hbdaddr->netmask) {
                free(hbdaddr->netmask);
            }

            if (hbdaddr->hbdifa_dstaddr) {
                free(hbdaddr->hbdifa_dstaddr);
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

static int netdev_config_iface_helper(const char *ifname, bool up)
{
    int fd;
    struct ifreq ifr;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        goto failed;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        goto failed;
    }

    if (up && (ifr.ifr_flags & IFF_UP)) {
        // do nothing
    }
    else if (!up && !(ifr.ifr_flags & IFF_UP)) {
        // do nothing
    }
    else if (up) {
        ifr.ifr_flags |= IFF_UP;

        if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
            goto failed;
        }
    }
    else {
        ifr.ifr_flags &= ~IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
            goto failed;
        }
    }

    close(fd);
    return 0;

failed:
    if (fd >= 0)
        close(fd);
    return -1;
}

int netdev_config_iface_up(const char *ifname, struct network_device *netdev)
{
    if (netdev_config_iface_helper(ifname, true))
        return -1;

    return update_network_device_dynamic_info(ifname, netdev);
}

int netdev_config_iface_down(const char *ifname, struct network_device *netdev)
{
    if (netdev_config_iface_helper(ifname, false))
        return -1;

    return update_network_device_dynamic_info(ifname, netdev);
}


