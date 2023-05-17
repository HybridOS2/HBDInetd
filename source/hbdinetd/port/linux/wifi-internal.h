/*
** wifi-internal.c -- The internal header for WiFi device on Linux port.
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

#ifndef _hbdinetd_port_linux_wifi_internal_h
#define _hbdinetd_port_linux_wifi_internal_h

struct netdev_context {
    const char *wpa_splk_cnf;
    char *wpa_splk_socket;
};

#endif /* not defined _hbdinetd_port_linux_wifi_internal_h */

