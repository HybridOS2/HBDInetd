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
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <dirent.h>

#include <netutils/ifc.h>
#include <netutils/dhcp.h>

#include "dhcpmsg.h"
#include "packet.h"
#include "log.h"

static void dump_dhcp_msg();
static char errmsg[2048];

typedef unsigned long long msecs_t;

static msecs_t get_msecs(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    } else {
        return (((msecs_t) ts.tv_sec) * ((msecs_t) 1000)) +
            (((msecs_t) ts.tv_nsec) / ((msecs_t) 1000000));
    }
}

const char *dhcp_lasterror()
{
    return errmsg;
}

static int fatal(const char *reason)
{
    HLOG_ERR("%s: %s\n", reason, strerror(errno));
    return -1;
}

static const char *ipaddr(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

typedef struct dhcp_info dhcp_info;

struct dhcp_info {
    uint32_t type;

    in_addr_t ipaddr;
    in_addr_t gateway;
    uint32_t prefixLength;

    in_addr_t dns1;
    in_addr_t dns2;

    in_addr_t serveraddr;
    uint32_t lease;
};

static dhcp_info last_good_info;

int dhcp_get_last_conf_info(uint32_t *msg_type,
        char **ipaddr, char **gateway, char **netmask,
        char **dns1, char **dns2, char **server,
        uint32_t *lease)
{
    *msg_type = last_good_info.type;
    *ipaddr = strdup(ifc_ipaddr_to_string(last_good_info.ipaddr));
    *gateway = strdup(ifc_ipaddr_to_string(last_good_info.gateway));
    *netmask = strdup(ifc_ipaddr_to_string(
                ifc_ipv4_prefix_length_to_netmask(
                    last_good_info.prefixLength)));
    *dns1 = strdup(ifc_ipaddr_to_string(last_good_info.dns1));
    *dns2 = strdup(ifc_ipaddr_to_string(last_good_info.dns2));
    *server = strdup(ifc_ipaddr_to_string(last_good_info.serveraddr));
    *lease = last_good_info.lease;

    if (last_good_info.type == DHCPACK) {
        return 0;
    }

    return -1;
}

static int dhcp_configure(const char *ifname, dhcp_info *info)
{
    last_good_info = *info;
    return ifc_configure(ifname, info->ipaddr, info->prefixLength, info->gateway,
                         info->dns1, info->dns2);
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

static void dump_dhcp_info(dhcp_info *info)
{
    char addr[20], gway[20];
    HLOG_DEBUG("--- dhcp %s (%d) ---\n",
            dhcp_msg_type_to_name(info->type), info->type);
    strcpy(addr, ipaddr(info->ipaddr));
    strcpy(gway, ipaddr(info->gateway));
    HLOG_DEBUG("ip %s gw %s prefixLength %d\n", addr, gway, info->prefixLength);
    if (info->dns1) HLOG_DEBUG("dns1: %s", ipaddr(info->dns1));
    if (info->dns2) HLOG_DEBUG("dns2: %s", ipaddr(info->dns2));
    HLOG_DEBUG("server %s, lease %d seconds\n",
            ipaddr(info->serveraddr), info->lease);
}

static int decode_dhcp_msg(dhcp_msg *msg, int len, dhcp_info *info)
{
    uint8_t *x;
    unsigned int opt;
    int optlen;

    memset(info, 0, sizeof(dhcp_info));
    if (len < (DHCP_MSG_FIXED_SIZE + 4)) return -1;

    len -= (DHCP_MSG_FIXED_SIZE + 4);

    if (msg->options[0] != OPT_COOKIE1) return -1;
    if (msg->options[1] != OPT_COOKIE2) return -1;
    if (msg->options[2] != OPT_COOKIE3) return -1;
    if (msg->options[3] != OPT_COOKIE4) return -1;

    x = msg->options + 4;

    while (len > 2) {
        opt = *x++;
        if (opt == OPT_PAD) {
            len--;
            continue;
        }
        if (opt == OPT_END) {
            break;
        }
        optlen = *x++;
        len -= 2;
        if (optlen > len) {
            break;
        }
        switch(opt) {
        case OPT_SUBNET_MASK:
            if (optlen >= 4) {
                in_addr_t mask;
                memcpy(&mask, x, 4);
                info->prefixLength = ifc_ipv4_netmask_to_prefix_length(mask);
            }
            break;
        case OPT_GATEWAY:
            if (optlen >= 4) memcpy(&info->gateway, x, 4);
            break;
        case OPT_DNS:
            if (optlen >= 4) memcpy(&info->dns1, x + 0, 4);
            if (optlen >= 8) memcpy(&info->dns2, x + 4, 4);
            break;
        case OPT_LEASE_TIME:
            if (optlen >= 4) {
                memcpy(&info->lease, x, 4);
                info->lease = ntohl(info->lease);
            }
            break;
        case OPT_SERVER_ID:
            if (optlen >= 4) memcpy(&info->serveraddr, x, 4);
            break;
        case OPT_MESSAGE_TYPE:
            info->type = *x;
            break;
        default:
            break;
        }
        x += optlen;
        len -= optlen;
    }

    info->ipaddr = msg->yiaddr;

    return 0;
}

static void hex2str(char *buf, const unsigned char *array, int len)
{
    int i;
    char *cp = buf;

    for (i = 0; i < len; i++) {
        cp += sprintf(cp, " %02x ", array[i]);
    }
}

static void dump_dhcp_msg(dhcp_msg *msg, int len)
{
    unsigned char *x;
    unsigned int n,c;
    int optsz;
    const char *name;
    char buf[2048];

    HLOG_DEBUG("===== DHCP message:\n");
    if (len < DHCP_MSG_FIXED_SIZE) {
        HLOG_DEBUG("Invalid length %d, should be %d\n", len, DHCP_MSG_FIXED_SIZE);
        return;
    }

    len -= DHCP_MSG_FIXED_SIZE;

    if (msg->op == OP_BOOTREQUEST)
        name = "BOOTREQUEST";
    else if (msg->op == OP_BOOTREPLY)
        name = "BOOTREPLY";
    else
        name = "????";
    HLOG_DEBUG("op = %s (%d), htype = %d, hlen = %d, hops = %d\n",
           name, msg->op, msg->htype, msg->hlen, msg->hops);
    HLOG_DEBUG("xid = 0x%08x secs = %d, flags = 0x%04x optlen = %d\n",
           ntohl(msg->xid), ntohs(msg->secs), ntohs(msg->flags), len);
    HLOG_DEBUG("ciaddr = %s\n", ipaddr(msg->ciaddr));
    HLOG_DEBUG("yiaddr = %s\n", ipaddr(msg->yiaddr));
    HLOG_DEBUG("siaddr = %s\n", ipaddr(msg->siaddr));
    HLOG_DEBUG("giaddr = %s\n", ipaddr(msg->giaddr));

    c = msg->hlen > 16 ? 16 : msg->hlen;
    hex2str(buf, msg->chaddr, c);
    HLOG_DEBUG("chaddr = {%s}\n", buf);

    for (n = 0; n < 64; n++) {
        if ((msg->sname[n] < ' ') || ((uint8_t)msg->sname[n] > 127)) {
            if (msg->sname[n] == 0) break;
            msg->sname[n] = '.';
        }
    }
    msg->sname[63] = 0;

    for (n = 0; n < 128; n++) {
        if ((msg->file[n] < ' ') || ((uint8_t)msg->file[n] > 127)) {
            if (msg->file[n] == 0) break;
            msg->file[n] = '.';
        }
    }
    msg->file[127] = 0;

    HLOG_DEBUG("sname = '%s'\n", msg->sname);
    HLOG_DEBUG("file = '%s'\n", msg->file);

    if (len < 4) return;
    len -= 4;
    x = msg->options + 4;

    while (len > 2) {
        if (*x == 0) {
            x++;
            len--;
            continue;
        }
        if (*x == OPT_END) {
            break;
        }
        len -= 2;
        optsz = x[1];
        if (optsz > len) break;
        if (x[0] == OPT_DOMAIN_NAME || x[0] == OPT_MESSAGE) {
            if ((unsigned int)optsz < sizeof(buf) - 1) {
                n = optsz;
            } else {
                n = sizeof(buf) - 1;
            }
            memcpy(buf, &x[2], n);
            buf[n] = '\0';
        } else {
            hex2str(buf, &x[2], optsz);
        }
        if (x[0] == OPT_MESSAGE_TYPE)
            name = dhcp_msg_type_to_name(x[2]);
        else
            name = NULL;
        HLOG_DEBUG("op %d len %d {%s} %s\n", x[0], optsz, buf, name == NULL ? "" : name);
        len -= optsz;
        x = x + optsz + 2;
    }
}

static int send_message(int sock, int if_index, dhcp_msg  *msg, int size)
{
    dump_dhcp_msg(msg, size);
    return send_packet(sock, if_index, msg, size, INADDR_ANY, INADDR_BROADCAST,
                       PORT_BOOTP_CLIENT, PORT_BOOTP_SERVER);
}

static int is_valid_reply(dhcp_msg *msg, dhcp_msg *reply, int sz)
{
    if (sz < DHCP_MSG_FIXED_SIZE) {
        HLOG_DEBUG("netcfg: Wrong size %d != %d\n", sz, DHCP_MSG_FIXED_SIZE);
        return 0;
    }
    if (reply->op != OP_BOOTREPLY) {
        HLOG_DEBUG("netcfg: Wrong Op %d != %d\n", reply->op, OP_BOOTREPLY);
        return 0;
    }
    if (reply->xid != msg->xid) {
        HLOG_DEBUG("netcfg: Wrong Xid 0x%x != 0x%x\n", ntohl(reply->xid),
                          ntohl(msg->xid));
        return 0;
    }
    if (reply->htype != msg->htype) {
        HLOG_DEBUG("netcfg: Wrong Htype %d != %d\n", reply->htype, msg->htype);
        return 0;
    }
    if (reply->hlen != msg->hlen) {
        HLOG_DEBUG("netcfg: Wrong Hlen %d != %d\n", reply->hlen, msg->hlen);
        return 0;
    }
    if (memcmp(msg->chaddr, reply->chaddr, msg->hlen)) {
        HLOG_DEBUG("netcfg: Wrong chaddr %x != %x\n", *(reply->chaddr),*(msg->chaddr));
        return 0;
    }
    return 1;
}

#define STATE_SELECTING  1
#define STATE_REQUESTING 2

#define TIMEOUT_INITIAL   4000
#define TIMEOUT_MAX      32000

static int dhcp_init_ifc(const char *ifname)
{
    dhcp_msg discover_msg;
    dhcp_msg request_msg;
    dhcp_msg reply;
    dhcp_msg *msg;
    dhcp_info info;
    int s, r, size;
    int valid_reply;
    uint32_t xid;
    unsigned char hwaddr[6];
    struct pollfd pfd;
    unsigned int state;
    unsigned int timeout;
    int if_index;

    xid = (uint32_t) get_msecs();

    if (ifc_get_hwaddr(ifname, hwaddr)) {
        return fatal("cannot obtain interface address");
    }
    if (ifc_get_ifindex(ifname, &if_index)) {
        return fatal("cannot obtain interface index");
    }

    s = open_raw_socket(ifname, hwaddr, if_index);

    timeout = TIMEOUT_INITIAL;
    state = STATE_SELECTING;
    info.type = 0;
    goto transmit;

    for (;;) {
        pfd.fd = s;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, timeout);

        if (r == 0) {
            HLOG_ERR("TIMEOUT\n");
            if (timeout >= TIMEOUT_MAX) {
                HLOG_ERR("timed out\n");
                if ( info.type == DHCPOFFER ) {
                    HLOG_ERR("no acknowledgement from DHCP server\n"
                            "configuring %s with offered parameters\n", ifname);
                    return dhcp_configure(ifname, &info);
                }
                errno = ETIME;
                close(s);
                return -1;
            }
            timeout = timeout * 2;

        transmit:
            size = 0;
            msg = NULL;
            switch(state) {
            case STATE_SELECTING:
                msg = &discover_msg;
                size = init_dhcp_discover_msg(msg, hwaddr, xid);
                break;
            case STATE_REQUESTING:
                msg = &request_msg;
                size = init_dhcp_request_msg(msg, hwaddr, xid,
                        info.ipaddr, info.serveraddr);
                break;
            default:
                r = 0;
            }
            if (size != 0) {
                r = send_message(s, if_index, msg, size);
                if (r < 0) {
                    HLOG_ERR("error sending dhcp msg: %s\n", strerror(errno));
                }
            }
            continue;
        }

        if (r < 0) {
            if ((errno == EAGAIN) || (errno == EINTR)) {
                continue;
            }
            return fatal("poll failed");
        }

        errno = 0;
        r = receive_packet(s, &reply);
        if (r < 0) {
            if (errno != 0) {
                HLOG_DEBUG("receive_packet failed (%d): %s\n", r, strerror(errno));
                if (errno == ENETDOWN || errno == ENXIO) {
                    return -1;
                }
            }
            continue;
        }

        if (HLOG_DEBUG_ENABLED)
            dump_dhcp_msg(&reply, r);
        decode_dhcp_msg(&reply, r, &info);

        if (state == STATE_SELECTING) {
            valid_reply = is_valid_reply(&discover_msg, &reply, r);
        } else {
            valid_reply = is_valid_reply(&request_msg, &reply, r);
        }
        if (!valid_reply) {
            HLOG_ERR("invalid reply\n");
            continue;
        }

        if (HLOG_DEBUG_ENABLED)
            dump_dhcp_info(&info);

        switch(state) {
        case STATE_SELECTING:
            if (info.type == DHCPOFFER) {
                state = STATE_REQUESTING;
                timeout = TIMEOUT_INITIAL;
                xid++;
                goto transmit;
            }
            break;
        case STATE_REQUESTING:
            if (info.type == DHCPACK) {
                HLOG_ERR("configuring %s\n", ifname);
                close(s);
                return dhcp_configure(ifname, &info);
            } else if (info.type == DHCPNAK) {
                HLOG_ERR("configuration request denied\n");
                close(s);
                return -1;
            } else {
                HLOG_ERR("ignoring %s message in state %d\n",
                         dhcp_msg_type_to_name(info.type), state);
            }
            break;
        }
    }
    close(s);
    return 0;
}

int dhcp_do_overall(const char *iname)
{
    if (ifc_init()) {
        HLOG_ERR("failed to call ifc_init(): %s\n", strerror(errno));
        return -1;
    }

    if (ifc_set_addr(iname, 0)) {
        HLOG_ERR("failed to set ip addr for %s to 0.0.0.0: %s\n",
                iname, strerror(errno));
        return -1;
    }

    if (ifc_up(iname)) {
        HLOG_ERR("failed to bring up interface %s: %s\n",
                iname, strerror(errno));
        return -1;
    }

    return dhcp_init_ifc(iname);
}

int dhcp_request_renew(const char *ifname, const char *ip, const char *server)
{
    dhcp_msg discover_msg;
    dhcp_msg request_msg;
    dhcp_msg reply;
    dhcp_msg *msg;
    dhcp_info info;
    int s, r, size;
    int valid_reply;
    uint32_t xid;
    unsigned char hwaddr[6];
    struct pollfd pfd;
    unsigned int state;
    unsigned int timeout;
    int if_index;

    in_addr_t ipaddr = inet_addr(ip);
    in_addr_t serveraddr = inet_addr(server);

    xid = (uint32_t) get_msecs();

    if (ifc_init()) {
        HLOG_ERR("failed to call ifc_init(): %s\n", strerror(errno));
        return -1;
    }

    if (ifc_get_hwaddr(ifname, hwaddr)) {
        return fatal("cannot obtain interface address");
    }
    if (ifc_get_ifindex(ifname, &if_index)) {
        return fatal("cannot obtain interface index");
    }

    s = open_raw_socket(ifname, hwaddr, if_index);

    timeout = TIMEOUT_INITIAL;
    state = STATE_REQUESTING;
    info.type = 0;
    info.ipaddr = ipaddr;
    info.serveraddr = serveraddr;
    goto transmit;

    for (;;) {
        pfd.fd = s;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, timeout);

        if (r == 0) {
            HLOG_ERR("TIMEOUT\n");
            if (timeout >= TIMEOUT_MAX) {
                HLOG_ERR("timed out\n");
                if ( info.type == DHCPOFFER ) {
                    HLOG_ERR("no acknowledgement from DHCP server\n"
                            "configuring %s with offered parameters\n", ifname);
                    return dhcp_configure(ifname, &info);
                }
                errno = ETIME;
                close(s);
                return -1;
            }
            timeout = timeout * 2;

        transmit:
            size = 0;
            msg = NULL;
            switch(state) {
            case STATE_SELECTING:
                msg = &discover_msg;
                size = init_dhcp_discover_msg(msg, hwaddr, xid);
                break;
            case STATE_REQUESTING:
                msg = &request_msg;
                size = init_dhcp_request_msg(msg, hwaddr, xid,
                        info.ipaddr, info.serveraddr);
                break;
            default:
                r = 0;
            }
            if (size != 0) {
                r = send_message(s, if_index, msg, size);
                if (r < 0) {
                    HLOG_ERR("error sending dhcp msg: %s\n", strerror(errno));
                }
            }
            continue;
        }

        if (r < 0) {
            if ((errno == EAGAIN) || (errno == EINTR)) {
                continue;
            }
            return fatal("poll failed");
        }

        errno = 0;
        r = receive_packet(s, &reply);
        if (r < 0) {
            if (errno != 0) {
                HLOG_DEBUG("receive_packet failed (%d): %s\n", r, strerror(errno));
                if (errno == ENETDOWN || errno == ENXIO) {
                    return -1;
                }
            }
            continue;
        }

        if (HLOG_DEBUG_ENABLED)
            dump_dhcp_msg(&reply, r);
        decode_dhcp_msg(&reply, r, &info);

        if (state == STATE_SELECTING) {
            valid_reply = is_valid_reply(&discover_msg, &reply, r);
        } else {
            valid_reply = is_valid_reply(&request_msg, &reply, r);
        }
        if (!valid_reply) {
            HLOG_ERR("invalid reply\n");
            continue;
        }

        if (HLOG_DEBUG_ENABLED)
            dump_dhcp_info(&info);

        switch(state) {
        case STATE_SELECTING:
            if (info.type == DHCPOFFER) {
                state = STATE_REQUESTING;
                timeout = TIMEOUT_INITIAL;
                xid++;
                goto transmit;
            }
            break;
        case STATE_REQUESTING:
            if (info.type == DHCPACK) {
                HLOG_ERR("configuring %s\n", ifname);
                close(s);
                return dhcp_configure(ifname, &info);
            } else if (info.type == DHCPNAK) {
                HLOG_ERR("configuration request denied\n");
                close(s);
                return -1;
            } else {
                HLOG_ERR("ignoring %s message in state %d\n",
                         dhcp_msg_type_to_name(info.type), state);
            }
            break;
        }
    }
    close(s);
    return 0;
}

int dhcp_release_lease(const char *ifname, const char *ip, const char *server)
{
    dhcp_msg release_msg;
    uint32_t xid;
    unsigned char hwaddr[6];
    int if_index;
    int s, r, size;
    in_addr_t ipaddr = inet_addr(ip);
    in_addr_t serveraddr = inet_addr(server);

    xid = (uint32_t)get_msecs();

    if (ifc_init()) {
        HLOG_ERR("failed to call ifc_init(): %s\n", strerror(errno));
        return -1;
    }

    if (ifc_get_hwaddr(ifname, hwaddr)) {
        return fatal("cannot obtain interface address");
    }
    if (ifc_get_ifindex(ifname, &if_index)) {
        return fatal("cannot obtain interface index");
    }

    dhcp_msg *msg = &release_msg;
    s = open_raw_socket(ifname, hwaddr, if_index);
    size = init_dhcp_release_msg(msg, hwaddr, xid, ipaddr, serveraddr);
    r = send_message(s, if_index, msg, size);
    if (r < 0) {
        HLOG_ERR("error sending dhcp msg: %s\n", strerror(errno));
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

