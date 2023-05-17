/*
** wifi-event.h -- The internal header for handling wap_supplicant events.
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

#ifndef _hbdinetd_port_linux_wifi_wifi_event_h
#define _hbdinetd_port_linux_wifi_wifi_event_h

#include "internal.h"
#include "wpa-client/wpa_ctrl.h"

#include "list.h"
#include "kvlist.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the event handlers.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_event_init(struct netdev_context *ctxt);

/**
 * Free the event handlers.
 *
 * @return 0 on success, < 0 on failure.
 */
void wifi_event_free(struct netdev_context *ctxt);

/**
 * Handle an event message.
 *
 * @return 0 on success, < 0 on failure.
 */
int wifi_event_handle_message(struct run_info *info,
        struct netdev_context *ctxt, const char *msg, int len);

#ifdef __cplusplus
};  // extern "C"
#endif

#endif  // _hbdinetd_port_linux_wifi_wifi_event_h

