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
    "Wrong passphrase or key.",                 // ERR_WPA_WRONG_PASSPHRASE
    "Timeout.",                                 // ERR_TIMEOUT
    "There already is an unresolved attempt.",  // ERR_UNRESOLVED_ATTEMPT
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

/* check whether wpa/wpa2 passphrase is valid */
int check_wpa_passphrase(const char *keymgmt, const char *passphrase)
{
    if (strcmp(keymgmt, "WPA-PSK") == 0 ||
            strcmp(keymgmt, "WPA2-PSK") == 0) {
        size_t len = strlen(passphrase);
        if (len < 8 || len > 63)
            return ERR_WPA_INVALID_PASSPHRASE;

        for (int i = 0; passphrase[i]; i++) {
            if ((passphrase[i] < 32) || (passphrase[i] > 126)) {
                return ERR_WPA_INVALID_PASSPHRASE;
            }
        }
    }
    else if (strcmp(keymgmt, "WEP") == 0) {
    }
    else if (strcmp(keymgmt, "NONE") == 0) {
    }
    else {
        return ERR_WPA_INVALID_KEYMGMT;
    }

    return 0;
}

int update_network_device_config(struct network_device *netdev,
        const char *method, const char *config)
{
    purc_variant_t jo = NULL, jo_tmp;
    jo = purc_variant_make_from_json_string(config, strlen(config));
    if (jo == NULL) {
        HLOG_ERR("Bad JSON data: %s\n", config);
        goto failed;
    }

    /* reset config fields */
    for (int i = 0; i < NETWORK_DEVICE_CONF_FIELDS_NR; i++) {
        if (netdev->fields[i]) {
            free(netdev->fields[i]);
            netdev->fields[i] = NULL;
        }
    }

    if (netdev->ipv4.gateway) {
        free(netdev->ipv4.gateway);
        netdev->ipv4.gateway = NULL;
    }

    if (netdev->ipv6.gateway) {
        free(netdev->ipv6.gateway);
        netdev->ipv6.gateway = NULL;
    }

    static const char *config_names[] = {
        "dns1",
        "dns2",
        "search",
    };

    for (size_t i = 0; i < PCA_TABLESIZE(config_names); i++) {
        if ((jo_tmp = purc_variant_object_get_by_ckey(jo, config_names[i]))) {
            const char *str = purc_variant_get_string_const(jo_tmp);
            if (str && str[0])
                netdev->fields[i] = strdup(str);
        }
    }

    if (netdev->method)
        free(netdev->method);
    netdev->method = strdup(method);

#ifdef BUILDING_FAKE__
    static const char *addr_names[] = {
        "address",
        "netmask",
        "broadcast",
    };

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "inet4")) &&
            purc_variant_is_object(jo_tmp)) {

        purc_variant_t jo_tmp_tmp;
        for (size_t i = 0; i < PCA_TABLESIZE(addr_names); i++) {
            if (netdev->ipv4.fields[i]) free(netdev->ipv4.fields[i]);

            if ((jo_tmp_tmp = purc_variant_object_get_by_ckey(jo_tmp,
                            addr_names[i]))) {
                const char *str = purc_variant_get_string_const(jo_tmp_tmp);
                if (str && str[0])
                    netdev->ipv4.fields[i] = strdup(str);
            }
        }
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "inet6")) &&
            purc_variant_is_object(jo_tmp)) {

        purc_variant_t jo_tmp_tmp;
        for (size_t i = 0; i < PCA_TABLESIZE(addr_names); i++) {
            if (netdev->ipv6.fields[i]) free(netdev->ipv4.fields[i]);

            if ((jo_tmp_tmp = purc_variant_object_get_by_ckey(jo_tmp,
                            addr_names[i]))) {
                const char *str = purc_variant_get_string_const(jo_tmp_tmp);
                if (str && str[0])
                    netdev->ipv6.fields[i] = strdup(str);
            }
        }
    }
#else
    if (update_network_device_dynamic_info(netdev->ifname, netdev))
        goto failed;
#endif

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "inet4")) &&
            purc_variant_is_object(jo_tmp)) {
        purc_variant_t jo_tmp_tmp;
        jo_tmp_tmp = purc_variant_object_get_by_ckey(jo_tmp, "gateway");
        const char *str = purc_variant_get_string_const(jo_tmp_tmp);
        if (str && str[0])
            netdev->ipv4.gateway = strdup(str);
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "inet6")) &&
            purc_variant_is_object(jo_tmp)) {
        purc_variant_t jo_tmp_tmp;
        jo_tmp_tmp = purc_variant_object_get_by_ckey(jo_tmp, "gateway");
        const char *str = purc_variant_get_string_const(jo_tmp_tmp);
        if (str && str[0])
            netdev->ipv6.gateway = strdup(str);
    }

    purc_variant_unref(jo);
    return 0;

failed:
    if (jo)
        purc_variant_unref(jo);
    return -1;
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

void cleanup_network_device_dynamic_info(struct network_device *netdev)
{
    HLOG_INFO("called\n");

    for (int i = 0; i < HBD_IFADDR_FIELDS_NR; i++) {
        if (netdev->ipv4.fields[i]) {
            free(netdev->ipv4.fields[i]);
            netdev->ipv4.fields[i] = NULL;
        }
    }

    for (int i = 0; i < HBD_IFADDR_FIELDS_NR; i++) {
        if (netdev->ipv6.fields[i]) {
            free(netdev->ipv6.fields[i]);
            netdev->ipv6.fields[i] = NULL;
        }
    }
}

void cleanup_network_device(struct network_device *netdev)
{
    if (netdev->hwaddr) {
        free(netdev->hwaddr);
        netdev->hwaddr = NULL;
    }

    for (int i = 0; i < NETWORK_DEVICE_CONF_FIELDS_NR; i++) {
        if (netdev->fields[i]) {
            free(netdev->fields[i]);
            netdev->fields[i] = NULL;
        }
    }

    cleanup_network_device_dynamic_info(netdev);
}

int update_network_device_info(struct run_info *run_info, const char *ifname)
{
    void *data;
    struct network_device *netdev;

    data = kvlist_get(&run_info->devices, ifname);
    if (data == NULL) {
        netdev = calloc(1, sizeof(*netdev));
        if (netdev == NULL) {
            HLOG_ERR("Failed calloc()\n");
            goto failed;
        }

        if ((netdev->ifname = kvlist_set_ex(&run_info->devices,
                        ifname, &netdev)) == NULL) {
            HLOG_ERR("Failed kvlist_set_ex()\n");
            goto failed;
        }

        if (get_network_device_fixed_info(ifname, netdev) == NULL) {
            goto failed;
        }
    }
    else {
        netdev = *(struct network_device **)data;
        cleanup_network_device(netdev);
    }

    if (update_network_device_dynamic_info(ifname, netdev))
        goto failed;

    return 0;

failed:
    kvlist_remove(&run_info->devices, ifname);
    return -1;
}

void cleanup_network_devices(struct run_info *run_info)
{
    const char* name;
    void *data;
    kvlist_for_each(&run_info->devices, name, data) {
        struct network_device *netdev;
        netdev = *(struct network_device **)data;

        if (netdev->terminate) {
            netdev->terminate(netdev);
        }

        cleanup_network_device(netdev);
        free(netdev);
    }

    kvlist_free(&run_info->devices);
}

size_t convert_to_hex_string(const char *src, char *hex)
{
    size_t i = 0;
    unsigned char ch;
    while ((ch = *src)) {

        unsigned char h_val = (ch & 0xf0) >> 4;
        if (h_val < 0x0a) {
            hex[i++] = '0' + h_val;
        }
        else {
            hex[i++] = 'a' + (h_val - 0xa);
        }

        unsigned char l_val = ch & 0x0f;
        if (l_val < 0x0a) {
            hex[i++] = '0' + l_val;
        }
        else {
            hex[i++] = 'a' + (l_val - 0xa);
        }

        src++;
    }

    hex[i] = 0;
    return i;
}

size_t escape_string_to_literal_text(const char *src, char *escaped)
{
    size_t i = 0;
    while (*src != '\0') {
        unsigned char ch = (unsigned char)*src;

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
                escaped[i++] = '0' + h_val;
            }
            else {
                escaped[i++] = 'a' + (h_val - 0xa);
            }

            unsigned char l_val = ch & 0x0f;
            if (h_val < 0x0a) {
                escaped[i++] = '0' + l_val;
            }
            else {
                escaped[i++] = 'a' + (l_val - 0xa);
            }
        }

        src++;
    }

    escaped[i] = 0;
    return i;
}

ssize_t unescape_literal_text(const char *escaped, size_t len, char *dst)
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

char *escape_string_to_literal_text_alloc(const char *src)
{
    size_t len = strlen(src);
    char escaped[len * 4 + 1];

    size_t escaped_len = escape_string_to_literal_text(src, escaped);
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

int print_one_hotspot(const struct wifi_hotspot *hotspot, int curr_netid,
        struct pcutils_printbuf *pb)
{
#if 0
    char frequency[64];
    print_frequency(hotspot->frequency, frequency, sizeof(frequency));
#endif

    pcutils_printbuf_format(pb,
            "{"
            "\"bssid\":\"%s\","
            "\"ssid\":\"%s\","
            "\"frequency\":%d,"
            "\"capabilities\":\"%s\","
            "\"signalLevel\":%d,"
            "\"isSaved\":%s,"
            "\"isConnected\":%s"
            "}",
            hotspot->bssid,
            hotspot->escaped_ssid ? hotspot->escaped_ssid : hotspot->ssid,
            hotspot->frequency,
            hotspot->capabilities,
            hotspot->signal_level,
            (hotspot->netid >= 0) ? "true":"false",
            (curr_netid >= 0 && curr_netid == hotspot->netid) ? "true":"false");
    return 0;
}

int print_hotspot_list(const struct list_head *hotspots, int curr_netid,
        struct pcutils_printbuf *pb)
{
    size_t nr_hotspots = 0;

    struct list_head *p;
    list_for_each(p, hotspots) {
        struct wifi_hotspot *hotspot;
        hotspot = list_entry(p, struct wifi_hotspot, ln);

        print_one_hotspot(hotspot, curr_netid, pb);
        pcutils_printbuf_strappend(pb, ",");

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

char *load_file_contents(const char *path, size_t *length)
{
    char *buf = NULL;

    FILE *f = fopen(path, "r");

    if (f) {
        if (fseek(f, 0, SEEK_END))
            goto failed;

        long len = ftell(f);
        if (len < 0)
            goto failed;

        buf = malloc(len + 1);
        if (buf == NULL)
            goto failed;

        fseek(f, 0, SEEK_SET);
        if (fread(buf, 1, len, f) < (size_t)len) {
            free(buf);
            buf = NULL;
        }
        buf[len] = '\0';

        if (length)
            *length = (size_t)len;
failed:
        fclose(f);
    }
    else {
        goto done;
    }

done:
    return buf;
}

int save_file_contents(const char *path, const char *contents, size_t len)
{
    int fd = open(path, O_RDWR | O_TRUNC);

    if (fd >= 0) {
        ssize_t n = write(fd, contents, len);
        if (n < 0)
            goto failed;

        close(fd);
    }

    return 0;

failed:
    if (fd >= 0)
        close(fd);
    return -1;
}

