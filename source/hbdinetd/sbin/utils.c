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
