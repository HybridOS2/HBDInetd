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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

const char *error_messages[] = {
    "Ok",                                       // ERR_OK
    "Error when interacting with data bus.",    // ERR_DATA_BUS
    "Error in device controller.",              // ERR_DEVICE_CONTROLLER
    "Two many failures occurred.",              // ERR_TWO_MANY_FAILURES
    "Uncertain result; see event.",             // ERR_UNCERTAIN_RESULT
    "Invalid SSID.",                            // ERR_WPA_INVALID_SSID
    "Invalid passphrase.",                      // ERR_WPA_INVALID_PASSPHRASE
    "Invalid key management method.",           // ERR_WPA_INVALID_KEYMGMT
    "Wrong passphrase.",                        // ERR_WPA_WRONG_PASSPHRASE
    "Timeout.",                                 // ERR_WPA_TIMEOUT
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

struct network_device *check_network_device_ex(struct run_info *info,
        const char *method_param, int expect_type,
        const char *extra_key, purc_variant_t *extra_value, int *errcode)
{
    purc_variant_t jo = NULL, jo_tmp;
    struct network_device *netdev = NULL;

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        HLOG_ERR("Bad parameter: %s\n", method_param);
        *errcode = EINVAL;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "device")) == NULL) {
        HLOG_ERR("Not 'device' key: %s\n", method_param);
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

    if (extra_key) {
        *extra_value = purc_variant_object_get_by_ckey(jo, extra_key);
        if (*extra_value) {
            purc_variant_ref(*extra_value);
        }
    }

    if (jo)
        purc_variant_unref(jo);

    return netdev;

failed:
    if (jo)
        purc_variant_unref(jo);

    return NULL;
}

size_t escape_ssid(const char *ssid, char *escaped)
{
    size_t i = 0;
    while (*ssid != '\0') {
        unsigned char ch = (unsigned char)*ssid;

        if (ch <= 0x7f) {
            switch (ch) {
            case '\"':
                escaped[i++] = '\\';
                escaped[i++] = '\"';
                break;
            case '\\':
                escaped[i++] = '\\';
                escaped[i++] = '\\';
                break;
            case '\033':
                escaped[i++] = '\\';
                escaped[i++] = 'e';
                break;
            case '\n':
                escaped[i++] = '\\';
                escaped[i++] = 'n';
                break;
            case '\r':
                escaped[i++] = '\\';
                escaped[i++] = 'r';
                break;
            case '\t':
                escaped[i++] = '\\';
                escaped[i++] = 't';
                break;
            default:
                escaped[i++] = ch;
                break;
            }
        }
        else {
            escaped[i++] = '\\';
            escaped[i++] = 'x';

            unsigned char h_val = (ch & 0xf0) >> 4;
            if (h_val < 0x0a) {
                escaped[i++] = h_val + '0';
            }
            else {
                escaped[i++] = h_val + + 'a' - 0xa;
            }

            unsigned char l_val = ch & 0x0f;
            if (l_val < 0x0a) {
                escaped[i++] = h_val + '0';
            }
            else {
                escaped[i++] = h_val + 'a' - 0xa;
            }
        }

        ssid++;
    }

    escaped[i] = 0;
    return i;
}

ssize_t unescape_ssid(const char *escaped, size_t len, char *dst)
{
    size_t i = 0;
    size_t j = 0;
    unsigned char byte = 0;

    for (i = 0; i < len; i++) {
        if (escaped[i] == '\\') {
            i++;
            if (i >= len)
                goto bad_encoding;

            if (escaped[i] == 'x') {
                i++;
                if (i >= len)
                    goto bad_encoding;

                char ch = tolower(escaped[i]);
                if ((ch >= '0') && (ch <= '9'))
                    byte = (ch - '0') << 4;
                else if ((ch >= 'a') && (ch <= 'f'))
                    byte = (ch - 'a' + 0x0a) << 4;
                else
                    goto bad_encoding;

                i++;
                if (i >= len)
                    goto bad_encoding;

                ch = tolower(escaped[i]);
                if ((ch >= '0') && (ch <= '9'))
                    byte |= (ch - '0');
                else if ((ch >= 'a') && (ch <= 'f'))
                    byte |= (ch - 'a' + 0x0a);
                else
                    goto bad_encoding;

                dst[j++] = byte;
            }
            else if (escaped[i] == '\\') {
                dst[j++] = '\\';
            }
            else if (escaped[i] == '"') {
                dst[j++] = '"';
            }
            else if (escaped[i] == '\\') {
                dst[j++] = '\\';
            }
            else if (escaped[i] == 'e') {
                dst[j++] = '\033';
            }
            else if (escaped[i] == 'n') {
                dst[j++] = '\n';
            }
            else if (escaped[i] == 'r') {
                dst[j++] = '\r';
            }
            else if (escaped[i] == 't') {
                dst[j++] = '\t';
            }
            else {
                goto bad_encoding;
            }
        }
        else
            dst[j++] = escaped[i];
    }

    dst[j] = 0;
    return j;

bad_encoding:
    return -1;
}

char *escape_ssid_alloc(const char *ssid)
{
    size_t len = strlen(ssid);
    char escaped[len * 4 + 1];

    size_t escaped_len = escape_ssid(ssid, escaped);
    if (escaped_len == len)
        return NULL;

    return strdup(escaped);
}

int print_frequency(unsigned int frequency, char *buf, size_t buf_sz)
{
    const char *format = "%.0f MHz";
    double val = frequency;

    assert(buf_sz > 0);
    if (frequency > 1000) {
        format = "%.1f GHz";
        val /= 1000.0;
    }

    int n = snprintf(buf, buf_sz, format, val);
    if (n < 0 || (size_t)n >= buf_sz) {
        goto failed;
    }

    return 0;

failed:
    buf[0] = 0;
    return -1;
}

int print_hotspots(const struct list_head *hotspots,
        struct pcutils_printbuf *pb)
{
    size_t nr_hotspots = 0;
    struct list_head *p;

    list_for_each(p, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        char frequency[64];
        print_frequency(hotspot->frequency, frequency, sizeof(frequency));

        pcutils_printbuf_format(pb,
                "{"
                "\"bssid\":\"%s\","
                "\"ssid\":\"%s\","
                "\"frequency\":\"%s\","
                "\"capabilities\":\"%s\","
                "\"signalLevel\":%d,"
                "\"isConnected\":%s"
                "},",
                hotspot->bssid,
                hotspot->ssid,
                frequency,
                hotspot->capabilities,
                hotspot->signal_level,
                hotspot->is_connected ? "true": "false");

        nr_hotspots++;
    }

    if (nr_hotspots > 0)
        pcutils_printbuf_shrink(pb, 1);
    return 0;
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

    nr_args += 2; // for pathname and terminating NULL
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
    argv[i++] = (char *)pathname;
    nr_args--;
    while (nr_args) {
        argv[i++] = p;
        nr_args--;
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
            HLOG_ERR("Failed execv(%s): %s\n", pathname, strerror(errno));
            _exit(1);
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

int stop_daemon(const char *pid_file)
{
    int fd = open(pid_file, O_RDONLY);
    if (fd >= 0) {
        char buf[64];

        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0)
            goto failed;

        close(fd);
        fd = -1;

        buf[n] = 0;
        long pid = strtol(buf, NULL, 10);
        if (pid <= 0)
            goto failed;

        return kill((pid_t)pid, SIGKILL);
    }

failed:
    if (fd >= 0)
        close(fd);
    return -1;
}

