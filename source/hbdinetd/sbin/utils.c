/*
** tools.c -- The implementation of utilities and helpers.
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

#include "internal.h"
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>

#include <sys/types.h>
#include <unistd.h>

const char *error_messages[] = {
    "Ok",                                       // ERR_OK
    "an error ocures in library operation.",    // ERR_LIBRARY_OPERATION
    "can not get devices list.",                // ERR_NONE_DEVICE_LIST
    "wrong procedure name.",                    // ERR_WRONG_PROCEDURE
    "wrong Json format.",                       // ERR_WRONG_JSON
    "can not find device name in param.",       // ERR_NO_DEVICE_NAME_IN_PARAM
    "can not find device in system.",           // ERR_NO_DEVICE_IN_SYSTEM
    "invalid network device type.",             // ERR_DEVICE_TYPE
    "some error in load library.",              // ERR_LOAD_LIBRARY
    "device is not WiFi device.",               // ERR_NOT_WIFI_DEVICE 
    "device has not openned.",                  // ERR_DEVICE_NOT_OPENNED 
    "an error ocurs in open wifi device.",      // ERR_OPEN_WIFI_DEVICE
    "an error ocurs in close wifi device.",     // ERR_CLOSE_WIFI_DEVICE
    "an error ocurs in open ethernet device.",  // ERR_OPEN_ETHERNET_DEVICE
    "an error ocurs in close ethernet device.", // ERR_CLOSE_ETHERNET_DEVICE
    "an error ocurs in open mobile device.",    // ERR_OPEN_MOBILE_DEVICE
    "an error ocurs in close mobile device.",   // ERR_CLOSE_MOBILE_DEVICE
    "device does not connect any network.",     // ERR_DEVICE_NOT_CONNECT
    "device is disalbe in library.",            // ERR_LIB_DEVICE_DISABLE
    "invalid ssid in library.",                 // ERR_LIB_INVALID_SSID
    "invalid password in library.",             // ERR_LIB_INVALID_PASSWORD
    "device is busy in library.",               // ERR_LIB_DEVICE_BUSY
    "the network is not existence in library.", // ERR_LIB_NET_EXISTENCE
    "an error in adding network in library.",   // ERR_LIB_ADD_NETWORK
    "an error in setting network in library.",  // ERR_LIB_SET_NETWORK
    "an error in selecting network in library.",// ERR_LIB_SELECT_NETWORK
    "an error in enable network in library.",   // ERR_LIB_ENABLE_NETWORK
    "an error in reconnecting net in lib.",     // ERR_LIB_RECONNECT_NETWORK
    "WRONG PASSWORD!"                           // ERR_LIB_WRONG_PASSWORD
};

const char *get_error_message(int errcode)
{
    if (errcode > 0) {
        return strerror(errcode);
    }

    errcode = -errcode;
    if (errcode < 0 || errcode >= (int)PCA_TABLESIZE(error_messages))
        return "Unknow error code.";

    return error_messages[errcode];
}

struct network_device *check_network_device(struct run_info *info,
        const char *method_param, int expect_type, int *errcode)
{
    purc_variant_t jo = NULL, jo_tmp;
    struct network_device *netdev = NULL;

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        *errcode = EINVAL;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "device")) == NULL) {
        *errcode = ENOKEY;
        goto failed;
    }

    const char *ifname = purc_variant_get_string_const(jo_tmp);
    if (ifname == NULL || !is_valid_interface_name(ifname)) {
        HLOG_ERR("Bad interface name: %s\n", ifname);
        *errcode = EINVAL;
        goto failed;
    }

    netdev = retrieve_network_device_from_ifname(info, ifname);
    if (netdev == NULL) {
        HLOG_ERR("Not existed interface name: %s\n", ifname);
        *errcode = ENOENT;
        goto failed;
    }

    if (expect_type != DEVICE_TYPE_UNKNOWN
            && netdev->type != expect_type) {
        *errcode = EINVAL;
        goto failed;
    }

    if (update_network_device_dynamic_info(ifname, netdev)) {
        HLOG_ERR("Failed to update interface information: %s\n", ifname);
        *errcode = errno;
        goto failed;
    }

    if (jo)
        purc_variant_unref(jo);

    return netdev;

failed:
    if (jo)
        purc_variant_unref(jo);

    return NULL;
}

#define SZ_IN_STACK_ARGS    16

#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

int start_daemon(const char *pathname, const char *arg, ...)
{
    char **argv = NULL;
    char *argv_in_stack[SZ_IN_STACK_ARGS];
    va_list ap, ap1;

    if (access(pathname, F_OK | R_OK | X_OK)) {
        HLOG_ERR("Bad executable: %s\n", pathname);
        return -1;
    }

    va_start(ap, arg);
    va_copy(ap1, ap);

    size_t nr_args = 0;
    char *p = (char *)arg;
    while (p) {
        nr_args++;
        p = va_arg(ap1, char *);
    }
    va_end(ap1);

    if (nr_args < 1) {
        HLOG_ERR("Bad arg: %s\n", arg);
        return -1;
    }

    if (nr_args <= SZ_IN_STACK_ARGS) {
        argv = argv_in_stack;
    }
    else {
        argv = calloc(nr_args, sizeof(char *));
        if (argv == NULL) {
            HLOG_ERR("Failed to allocate argv for %u args!\n",
                    (unsigned)nr_args);
            return -1;
        }
    }

    p = (char *)arg;
    size_t i = 0;
    while (p) {
        argv[i] = p;
        i++;
        p = va_arg(ap, char *);
    }
    va_end(ap);

    pid_t cpid = vfork();
    if (cpid == -1) {
        if (argv != argv_in_stack)
            free(argv);
        HLOG_ERR("Failed vfork(): %s.\n", strerror(errno));
        return -1;
    }
    else if (cpid == 0) {
        if (execv(pathname, argv)) {
            HLOG_ERR("Failed execv: %s\n", pathname);
            exit(1);
        }
    }
    else {
        if (argv != argv_in_stack)
            free(argv);
    }

    return 0;
}

#ifndef __clang__
#pragma GCC diagnostic pop
#endif

