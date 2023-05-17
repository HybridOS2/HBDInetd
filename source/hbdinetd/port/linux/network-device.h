/*
** network-device.h -- The internal header for network device on Linux.
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

#ifndef _hbdinetd_port_linux_network_device_h
#define _hbdinetd_port_linux_network_device_h

#ifdef __cplusplus
extern "C" {
#endif

int netdev_config_iface_up(const char *ifname, struct network_device *netdev);
int netdev_config_iface_down(const char *ifname, struct network_device *netdev);

#ifdef __cplusplus
};  // extern "C"
#endif

#endif  // _hbdinetd_port_linux_network_device_h

