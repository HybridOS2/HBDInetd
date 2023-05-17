/*
** wifi-device.c -- The basic operators for wifi devices.
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

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

#include "wifi-internal.h"

int wifi_device_on(struct run_info *info, struct network_device *netdev)
{
    (void)info;
    (void)netdev;
    return 0;
}

int wifi_device_off(struct run_info *info, struct network_device *netdev)
{
    (void)info;
    (void)netdev;
    return 0;
}

int wifi_device_check(struct run_info *info, struct network_device *netdev)
{
    (void)info;
    (void)netdev;
    return 0;
}

