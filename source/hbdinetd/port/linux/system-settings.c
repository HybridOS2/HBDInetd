/*
** system-settings.c -- The operations for system wide settings.
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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

#define PATH_RESOLV_CONF    "/etc/resolv.conf"

struct system_settings {
    size_t length;
    char *resolv_conf;
};

int save_system_settings(hbdbus_conn *conn)
{
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);

    info->saved_settings = calloc(1, sizeof(struct system_settings));
    if (info->saved_settings) {
        info->saved_settings->resolv_conf = load_file_contents(PATH_RESOLV_CONF,
                &info->saved_settings->length);
    }

    return 0;
}

int update_system_settings(hbdbus_conn *conn, struct network_device *netdev)
{
    (void)conn;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);

    if (netdev->dns1 && netdev->dns1[0]) {
        pcutils_printbuf_format(pb, "nameserver %s\n", netdev->dns1);
    }

    if (netdev->dns2 && netdev->dns2[0]) {
        pcutils_printbuf_format(pb, "nameserver %s\n", netdev->dns2);
    }

    if (netdev->search && netdev->search[0]) {
        pcutils_printbuf_format(pb, "search %s\n", netdev->search);
    }

    int ret = 0;
    if (pb->buf) {
        ret = save_file_contents(PATH_RESOLV_CONF, pb->buf, pb->bpos);
        free(pb->buf);
    }
    else {
        ret = -1;
    }

    return ret;
}

int restore_system_settings(hbdbus_conn *conn)
{
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    assert(info);

    if (info->saved_settings && info->saved_settings->resolv_conf) {
        save_file_contents(PATH_RESOLV_CONF,
                info->saved_settings->resolv_conf, info->saved_settings->length);
        free(info->saved_settings->resolv_conf);
        free(info->saved_settings);
        info->saved_settings = NULL;
    }

    return 0;
}

