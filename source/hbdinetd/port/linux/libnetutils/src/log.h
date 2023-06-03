/**
 * @file log.h
 * @author Vincent Wei (https://github.com/VincentWei)
 * @date 2023/05/10
 * @brief Log facilities.
 *
 * Copyright (c) 2023 FMSoft (http://www.fmsoft.cn)
 *
 * This file is part of HBDInetd.
 *
 * HBDInetd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HBDInetd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#undef NDEBUG

#ifndef __log_h_
#define __log_h_

#include <purc/purc-helpers.h>

#define HLOG_ERR(x, ...)   \
    purc_log_error("%s: " x, __func__, ##__VA_ARGS__)

#define HLOG_WARN(x, ...)    \
    purc_log_warn("%s: " x, __func__, ##__VA_ARGS__)

#define HLOG_NOTE(x, ...)    \
    purc_log_notice("%s: " x, __func__, ##__VA_ARGS__)

#ifdef NDEBUG
#   define HLOG_DEBUG(x, ...)
#   define HLOG_INFO(x, ...)
#   define HLOG_INFO_ONCE(x, ...)
#else
#   define HLOG_DEBUG(x, ...)   \
        purc_log_debug("%s: " x, __func__, ##__VA_ARGS__)

#   define HLOG_INFO(x, ...)    \
        purc_log_info("%s: " x, __func__, ##__VA_ARGS__)

#   define HLOG_INFO_ONCE(x, ...) do {                          \
        static bool once = false;                               \
        if (!once) {                                            \
            purc_log_info("%s: " x, __func__, ##__VA_ARGS__);   \
            once = true;                                        \
        }                                                       \
    } while (0)
#endif

#define HLOG_DEBUG_ENABLED  (purc_get_log_levels() & PURC_LOG_MASK_DEBUG)

#endif /* not defined __log_h_ */

