/*
** hbdinetd.h -- The main header of HBDInetd.
**
** Copyright (c) 2023 FMSoft (http://www.fmsoft.cn)
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

#ifndef __hbdinetd_h
#define __hbdinetd_h

#define HBDINETD_APP_NAME               "cn.fmsoft.hybridos.inetd"
#define HBDINETD_RUNNER_NAME            "daemon"

// methods for All Network Devices 
#define METHOD_NET_OPEN_DEVICE          "openDevice"
#define METHOD_NET_CLOSE_DEVICE         "closeDevice"
#define METHOD_NET_GET_DEVICE_STATUS    "getDeviceStatus"

// methods for WiFi Device
#define METHOD_WIFI_START_SCAN          "wifiStartScanHotspots"
#define METHOD_WIFI_STOP_SCAN           "wifiStopScanHotspots"
#define METHOD_WIFI_CONNECT_AP          "wifiConnect"
#define METHOD_WIFI_DISCONNECT_AP       "wifiDisconnect"
#define METHOD_WIFI_GET_NETWORK_INFO    "wifiGetNetworkInfo"

// method for Ethernet Device
// method for Mobile Device

// events for All Network Devices
#define NETWORKDEVICECHANGED            "NETWORKDEVICECHANGED"

// events for WiFi Device
#define WIFIHOTSPOTSCHANGED             "WIFIHOTSPOTSCHANGED"
#define WIFISIGNALSTRENGTHCHANGED       "WIFISIGNALSTRENGTHCHANGED"

// events for Ethernet Device
// events for Mobile Device

#define DEVICE_TYPE_ETHER_MASK      0x1000

// device type
enum {
#define DEVICE_TYPE_NAME_UNKNOWN            "unknown"
    DEVICE_TYPE_UNKNOWN = 0,
#define DEVICE_TYPE_NAME_LOOPBACK           "loopback"
    DEVICE_TYPE_LOOPBACK,
#define DEVICE_TYPE_NAME_MOBILE             "mobile"
    DEVICE_TYPE_MOBILE,
#define DEVICE_TYPE_NAME_ETHER_WIRED        "wired"
    DEVICE_TYPE_ETHER_WIRED = DEVICE_TYPE_ETHER_MASK | 0x00,
#define DEVICE_TYPE_NAME_ETHER_WIRELESS     "wifi"
    DEVICE_TYPE_ETHER_WIRELESS = DEVICE_TYPE_ETHER_MASK | 0x01,
};

// device status
enum {
#define DEVICE_STATUS_NAME_UNCERTAIN        "uncertain"
    DEVICE_STATUS_UNCERTAIN = 0,
#define DEVICE_STATUS_NAME_DOWN             "down"
    DEVICE_STATUS_DOWN,
#define DEVICE_STATUS_NAME_UP               "up"
    DEVICE_STATUS_UP,
#define DEVICE_STATUS_NAME_RUNNING          "running"
    DEVICE_STATUS_RUNNING
};

// errors
#define ERR_OK                          0
#define ERR_LIBRARY_OPERATION           -1
#define ERR_NONE_DEVICE_LIST            -2
#define ERR_WRONG_PROCEDURE             -3
#define ERR_WRONG_JSON                  -4
#define ERR_NO_DEVICE_NAME_IN_PARAM     -5
#define ERR_NO_DEVICE_IN_SYSTEM         -6
#define ERR_DEVICE_TYPE                 -7
#define ERR_LOAD_LIBRARY                -8
#define ERR_NOT_WIFI_DEVICE             -9
#define ERR_DEVICE_NOT_OPENNED          -10
#define ERR_OPEN_WIFI_DEVICE            -11
#define ERR_CLOSE_WIFI_DEVICE           -12
#define ERR_OPEN_ETHERNET_DEVICE        -13
#define ERR_CLOSE_ETHERNET_DEVICE       -14
#define ERR_OPEN_MOBILE_DEVICE          -15
#define ERR_CLOSE_MOBILE_DEVICE         -16
#define ERR_DEVICE_NOT_CONNECT          -17
#define ERR_LIB_DEVICE_DISABLE          -18
#define ERR_LIB_INVALID_SSID            -19
#define ERR_LIB_INVALID_PASSWORD        -20
#define ERR_LIB_DEVICE_BUSY             -21
#define ERR_LIB_NET_EXISTENCE           -22
#define ERR_LIB_ADD_NETWORK             -23
#define ERR_LIB_SET_NETWORK             -24
#define ERR_LIB_SELECT_NETWORK          -25
#define ERR_LIB_ENABLE_NETWORK          -26
#define ERR_LIB_RECONNECT_NETWORK       -27
#define ERR_LIB_WRONG_PASSWORD          -28

// for network changed
#define NETWORK_CHANGED_NAME            ((0x01) << 0)
#define NETWORK_CHANGED_TYPE            ((0x01) << 1)
#define NETWORK_CHANGED_STATUS          ((0x01) << 2)
#define NETWORK_CHANGED_MAC             ((0x01) << 3)
#define NETWORK_CHANGED_IP              ((0x01) << 4)
#define NETWORK_CHANGED_BROADCAST       ((0x01) << 5)
#define NETWORK_CHANGED_SUBNETMASK      ((0x01) << 6)

// for string length
#define HOTSPOT_STRING_LENGTH           64
#define NETWORK_DEVICE_NAME_LENGTH      32
#define NETWORK_ADDRESS_LENGTH          32

#endif  // __hbdinetd__h
