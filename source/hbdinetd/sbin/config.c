/*
** dhclient.c -- The DHCP client thread of HBDInetd.
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

#undef NDEBUG

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>

#include <fcntl.h>
#include <unistd.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

#include "netutils/dhcp.h"
#include "netutils/ifc.h"

enum {
    CONFIG_METHOD_STATIC = 0,
    CONFIG_METHOD_DHCP,
};

struct iface_config {
    const char *name;

    /* TODO: reserved for future */
    int         method;

    uint32_t    addr;
    uint32_t    srv;

    uint32_t    lease;
    int         renew_tries;
    time_t      config_time;
    time_t      expire_time;

    char       *fields[0];
#define DHIF_STR_FIELDS_NR  4

    char       *server;
    char       *dns1;
    char       *dns2;
    char       *search;

    struct hbd_ifaddr   ipv4;
    struct hbd_ifaddr   ipv6;
};

struct this_run {
    purc_atom_t rid_main;
    struct kvlist ifaces;
};

static int init_instance(struct this_run *run, purc_atom_t rid_main)
{
    if (ifc_init())
        return -1;

    run->rid_main = rid_main;
    kvlist_init(&run->ifaces, NULL);
    return 0;
}

static void cleanup_iface_config(struct iface_config *ifconf, bool free_itself)
{
    for (int i = 0; i < DHIF_STR_FIELDS_NR; i++) {
        if (ifconf->fields[i])
            free(ifconf->fields[i]);
    }

    for (int i = 0; i < HBD_IFADDR_FIELDS_NR; i++) {
        if (ifconf->ipv4.fields[i])
            free(ifconf->ipv4.fields[i]);
    }

    if (free_itself) {
        free(ifconf);
    }
    else {
        memset(ifconf, 0, sizeof(*ifconf));
    }
}

static void deinit_instance(struct this_run *run)
{
    const char* name;
    void *data;
    kvlist_for_each(&run->ifaces, name, data) {
        struct iface_config *ifconf;
        ifconf = *(struct iface_config **)data;

        cleanup_iface_config(ifconf, true);
    }

    kvlist_free(&run->ifaces);
    ifc_close();
}

static void shutdown_handler(struct this_run *info,
        const pcrdr_msg *request, pcrdr_msg *response)
{
    purc_atom_t endpoint_atom;
    const char *endpoint_name = purc_get_endpoint(&endpoint_atom);
    assert(endpoint_name);  /* must be valid */

    const char *name;
    void *data;
    kvlist_for_each(&info->ifaces, name, data) {
        struct iface_config *ifconf;
        ifconf = *(struct iface_config **)data;

        if (ifconf->server)
            dhcp_release_lease(ifconf->name, ifconf->addr, ifconf->srv);
        cleanup_iface_config(ifconf, false);
    }

    response->type = PCRDR_MSG_TYPE_RESPONSE;
    response->requestId = purc_variant_ref(request->requestId);
    response->sourceURI = purc_variant_make_string(endpoint_name, false);
    response->retCode = PCRDR_SC_OK;
    response->resultValue = (uint64_t)endpoint_atom;
    response->dataType = PCRDR_MSG_DATA_TYPE_VOID;
    response->data = PURC_VARIANT_INVALID;
}

static const char *get_dhcp_result(struct iface_config *ifconf)
{
    const char *status = NULL;

    uint32_t msg_type;
    in_addr_t gateway, netmask, dns1, dns2;
    int ret = dhcp_get_last_conf_info(&msg_type, &ifconf->addr, &gateway,
        &netmask, &dns1, &dns2, &ifconf->srv, &ifconf->lease);
    if (ret) {
        status = dhcp_msg_type_to_name(msg_type);
        goto failed;
    }

    ifconf->server = strdup(ifc_ipaddr_to_string(ifconf->srv));
    ifconf->dns1 = dns1 ? strdup(ifc_ipaddr_to_string(dns1)) : NULL;
    ifconf->dns2 = dns2 ? strdup(ifc_ipaddr_to_string(dns2)) : NULL;
    ifconf->ipv4.addr = strdup(ifc_ipaddr_to_string(ifconf->addr));
    ifconf->ipv4.netmask = strdup(ifc_ipaddr_to_string(netmask));
    ifconf->ipv4.gateway = strdup(ifc_ipaddr_to_string(gateway));

    ifconf->config_time = purc_monotonic_time_after(0);
    ifconf->expire_time = purc_monotonic_time_after(ifconf->lease);
    ifconf->renew_tries = 0;

    HLOG_INFO("Lease: %u\n", ifconf->lease);
    return NULL;

failed:
    HLOG_ERR("Failed due to %s\n", status);
    return status;
}

static char *make_config_json(struct iface_config *ifconf)
{
    assert(ifconf);

    char *result;
    int ret = asprintf(&result,
            "{"
                "\"device\":\"%s\","
                "\"server\":\"%s\","
                "\"dns1\":\"%s\","
                "\"dns2\":\"%s\","
                "\"search\":\"%s\","
                "\"inet\":{"
                    "\"address\":\"%s\","
                    "\"netmask\":\"%s\","
                    "\"gateway\":\"%s\""
                "},"
                "\"inet6\":{"
                    "\"address\":\"%s\","
                    "\"netmask\":\"%s\","
                    "\"gateway\":\"%s\""
                "}"
            "}",
            ifconf->name,
            ifconf->server ? ifconf->server : "",
            ifconf->dns1 ? ifconf->dns1 : "",
            ifconf->dns2 ? ifconf->dns2 : "",
            ifconf->search ? ifconf->search : "",
            ifconf->ipv4.addr ? ifconf->ipv4.addr : "",
            ifconf->ipv4.netmask ? ifconf->ipv4.netmask : "",
            ifconf->ipv4.gateway ? ifconf->ipv4.gateway : "",
            ifconf->ipv6.addr ? ifconf->ipv6.addr : "",
            ifconf->ipv6.netmask ? ifconf->ipv6.netmask : "",
            ifconf->ipv6.gateway ? ifconf->ipv6.gateway : "");

    if (ret < 0)
        return NULL;

    return result;
}

static void do_config(struct iface_config *ifconf, purc_atom_t requester)
{
    dhcp_do_overall(ifconf->name);
    const char *status = get_dhcp_result(ifconf);

    const char *endpoint_name = purc_get_endpoint(NULL);

    pcrdr_msg *event;
    event = pcrdr_make_event_message(
                PCRDR_MSG_TARGET_INSTANCE,
                requester,
                status ? CONFIG_EV_FAILED : CONFIG_EV_SUCCEEDED,
                endpoint_name,
                PCRDR_MSG_ELEMENT_TYPE_ID, ifconf->name,
                status,
                PCRDR_MSG_DATA_TYPE_VOID, NULL, 0);

    if (status == NULL) {
        char *json = make_config_json(ifconf);
        if (json) {
            event->dataType = PCRDR_MSG_DATA_TYPE_JSON;
            event->data = purc_variant_make_string_reuse_buff(json,
                    strlen(json) + 1, false);
        }
    }

    purc_inst_move_message(requester, event);
    pcrdr_release_message(event);
}

static void release_handler(struct this_run *info, const pcrdr_msg *request)
{
    const char *ifname = NULL;
    if (request->elementType == PCRDR_MSG_ELEMENT_TYPE_ID) {
        ifname = purc_variant_get_string_const(request->elementValue);
    }

    assert(ifname);

    void *data;
    struct iface_config *ifconf = NULL;
    if ((data = kvlist_get(&info->ifaces, ifname))) {
        ifconf = *(struct iface_config **)data;
    }

    if (ifconf == NULL) {
        HLOG_ERR("Failed due to bad ifname: %s\n", ifname);
    }
    else {
        dhcp_release_lease(ifname, ifconf->addr, ifconf->srv);
        cleanup_iface_config(ifconf, false);
        kvlist_remove(&info->ifaces, ifname);
    }
}

static void config_handler(struct this_run *info, purc_atom_t requester,
        const pcrdr_msg *request)
{
    const char *ifname = NULL;
    if (request->elementType == PCRDR_MSG_ELEMENT_TYPE_ID) {
        ifname = purc_variant_get_string_const(request->elementValue);
    }

    assert(ifname);

    void *data;
    struct iface_config *ifconf = NULL;
    if ((data = kvlist_get(&info->ifaces, ifname))) {
        ifconf = *(struct iface_config **)data;
        cleanup_iface_config(ifconf, false);
    }
    else {
        ifconf = calloc(1, sizeof(*ifconf));
        if (ifconf)
            ifconf->name = kvlist_set_ex(&info->ifaces, ifname, &ifconf);
    }

    if (ifconf == NULL || ifconf->name == NULL) {
        HLOG_ERR("Failed due to OOM\n");
        return;
    }

    do_config(ifconf, requester);
}

static const char *get_renew_result(struct iface_config *ifconf)
{
    const char *status = NULL;
    uint32_t msg_type;
    in_addr_t gateway, netmask, dns1, dns2;
    int ret = dhcp_get_last_conf_info(&msg_type, &ifconf->addr, &gateway,
        &netmask, &dns1, &dns2, &ifconf->srv, &ifconf->lease);
    if (ret) {
        status = dhcp_msg_type_to_name(msg_type);
        goto failed;
    }

    /* always update DNS servers */
    if (ifconf->dns1) free(ifconf->dns1);
    if (ifconf->dns2) free(ifconf->dns2);
    ifconf->dns1 = dns1 ? strdup(ifc_ipaddr_to_string(dns1)) : NULL;
    ifconf->dns2 = dns2 ? strdup(ifc_ipaddr_to_string(dns2)) : NULL;

    ifconf->config_time = purc_monotonic_time_after(0);
    ifconf->expire_time = purc_monotonic_time_after(ifconf->lease);
    ifconf->renew_tries = 0;

    HLOG_INFO("Lease: %u\n", ifconf->lease);
    return NULL;

failed:
    HLOG_ERR("Failed due to %s\n", status);
    return status;
}

static void check_to_renew(struct this_run *info)
{
    const char* name;
    void *data;
    kvlist_for_each(&info->ifaces, name, data) {
        struct iface_config *ifconf;
        ifconf = *(struct iface_config **)data;

        if (ifconf->server == NULL) {
            continue;
        }

        struct timespec config_ts = {ifconf->config_time, 0 };
        double elapsed = purc_get_elapsed_seconds(&config_ts, NULL);

        if (ifconf->renew_tries > 1 && elapsed >= ifconf->lease) {
            cleanup_iface_config(ifconf, false);
            do_config(ifconf, info->rid_main);
        }
        else if (ifconf->renew_tries > 0 && elapsed >= ifconf->lease * 0.875) {
            if (dhcp_request_renew(ifconf->name, ifconf->addr, ifconf->srv) == 0) {
                get_renew_result(ifconf);
            }
            else
                ifconf->renew_tries++;
        }
        else if (elapsed >= ifconf->lease * 0.5) {
            if (dhcp_request_renew(ifconf->name, ifconf->addr, ifconf->srv) == 0) {
                get_renew_result(ifconf);
            }
            else
                ifconf->renew_tries++;
        }
    }
}

static void event_loop(struct this_run *info)
{
    size_t n;
    int ret;

    do {
        ret = purc_inst_holding_messages_count(&n);
        if (ret) {
            HLOG_ERR("purc_inst_holding_messages_count failed: %d\n", ret);
        }
        else if (n == 0) {
            check_to_renew(info);
            pcutils_usleep(30000); // 30ms.
            continue;
        }

        purc_clr_error();

        pcrdr_msg *msg = purc_inst_take_away_message(0);

        if (msg->type == PCRDR_MSG_TYPE_EVENT) {
            const char *event_name;
            event_name = purc_variant_get_string_const(msg->eventName);

            HLOG_INFO("got an event message not interested in:\n");
            HLOG_INFO("    type:        %d\n", msg->type);
            HLOG_INFO("    target:      %d\n", msg->target);
            HLOG_INFO("    targetValue: %d\n", (int)msg->targetValue);
            HLOG_INFO("    eventName:   %s\n", event_name);
            HLOG_INFO("    sourceURI: %s\n",
                    purc_variant_get_string_const(msg->sourceURI));
        }
        else if (msg->type == PCRDR_MSG_TYPE_REQUEST) {
            const char* source_uri;
            purc_atom_t requester;

            source_uri = purc_variant_get_string_const(msg->sourceURI);
            if (source_uri == NULL || (requester = purc_atom_try_string_ex(
                            PURC_ATOM_BUCKET_DEF, source_uri)) == 0) {
                HLOG_INFO("No sourceURI or the requester disappeared\n");
                pcrdr_release_message(msg);
                continue;
            }

            if (msg->target != PCRDR_MSG_TARGET_INSTANCE) {
                HLOG_INFO("Not a request sent to instance.\n");
                pcrdr_release_message(msg);
                continue;
            }

            const char *op;
            op = purc_variant_get_string_const(msg->operation);
            HLOG_INFO("Got a request message for operation `%s` from %s\n",
                    op, purc_variant_get_string_const(msg->sourceURI));

            const char *request_id;
            request_id = purc_variant_get_string_const(msg->requestId);

            pcrdr_msg *response = pcrdr_make_void_message();
            if (strcmp(op, CONFIG_OP_SHUTDOWN) == 0) {
                /* for operation `shutdown`, request_id must not be `-` */
                assert(strcmp(request_id, PCRDR_REQUESTID_NORETURN));
                shutdown_handler(info, msg, response);
                purc_inst_move_message(requester, response);
                pcrdr_release_message(response);
                pcrdr_release_message(msg);
                break;
            }
            else if (strcmp(op, CONFIG_OP_RELEASE) == 0) {
                release_handler(info, msg);
            }
            else if (strcmp(op, CONFIG_OP_CONFIG) == 0) {
                config_handler(info, requester, msg);
            }
            else {
                /* for other requests, reponse PCRDR_SC_BAD_REQUEST */
                response->type = PCRDR_MSG_TYPE_RESPONSE;
                response->requestId = purc_variant_ref(msg->requestId);
                response->sourceURI = purc_variant_make_string(
                        purc_get_endpoint(NULL), false);
                response->retCode = PCRDR_SC_BAD_REQUEST;
                response->resultValue = 0;
                response->dataType = PCRDR_MSG_DATA_TYPE_VOID;
                response->data = PURC_VARIANT_INVALID;
            }

            if (strcmp(request_id, PCRDR_REQUESTID_NORETURN)) {
                purc_inst_move_message(requester, response);
            }
            pcrdr_release_message(response);
        }
        else if (msg->type == PCRDR_MSG_TYPE_RESPONSE) {
            HLOG_INFO("Got a response message for request: %s from %s\n",
                    purc_variant_get_string_const(msg->requestId),
                    purc_variant_get_string_const(msg->sourceURI));
        }

        pcrdr_release_message(msg);

        int last_error = purc_get_last_error();
        if (UNLIKELY(last_error)) {
            HLOG_WARN("Encounter error when handle message: %s\n",
                    purc_get_error_message(last_error));
        }

    } while (true);
}

struct thread_arg {
    const struct run_info *mainrun;
    sem_t          *wait;
    purc_atom_t     rid;
};

static void* config_thread_entry(void* arg)
{
    struct thread_arg *my_arg = (struct thread_arg *)arg;
    sem_t *sw = my_arg->wait;
    purc_atom_t rid_main = my_arg->mainrun->rid, rid = 0;

    int ret = purc_init_ex(PURC_MODULE_EJSON,
            HBDINETD_APP_NAME, HBDINETD_RUN_CONFIG, NULL);
    if (ret == PURC_ERROR_OK) {
        rid = my_arg->rid = purc_inst_create_move_buffer(
                PCINST_MOVE_BUFFER_FLAG_NONE, 16);
    }

    if (my_arg->mainrun->verbose) {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT | PURC_LOG_MASK_INFO,
                my_arg->mainrun->log_facility);
    }
    else {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT,
                my_arg->mainrun->log_facility);
    }

    sem_post(sw);

    if (rid) {
        struct this_run info;

        if (init_instance(&info, rid_main) == 0) {
            event_loop(&info);
            deinit_instance(&info);
        }
        purc_inst_destroy_move_buffer();
    }

    if (ret == PURC_ERROR_OK) {
        HLOG_INFO("This runner is going to be cleaned up and the thread is exiting.\n");
        purc_cleanup();
    }

    return NULL;
}

#define SEM_NAME_SYNC_START     "sync-dhclient-start"

static pthread_t config_th;
purc_atom_t config_start(const struct run_info *mainrun)
{
    int ret;
    struct thread_arg arg = { mainrun, NULL, 0 };

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

ALLOW_DEPRECATED_DECLARATIONS_BEGIN
    sem_unlink(SEM_NAME_SYNC_START);
    arg.wait = sem_open(SEM_NAME_SYNC_START, O_CREAT | O_EXCL, 0644, 0);
    if (arg.wait == SEM_FAILED) {
        HLOG_ERR("Failed to create semaphore: %s\n", strerror(errno));
        goto failed;
    }

    ret = pthread_create(&config_th, &attr, config_thread_entry, &arg);
    if (ret) {
        HLOG_ERR("Failed to create thread for DHCP client: %s\n",
                strerror(errno));
        sem_close(arg.wait);
        sem_unlink(SEM_NAME_SYNC_START);
        goto failed;
    }
    pthread_attr_destroy(&attr);

    sem_wait(arg.wait);
    sem_close(arg.wait);
    sem_unlink(SEM_NAME_SYNC_START);
ALLOW_DEPRECATED_DECLARATIONS_END

    return arg.rid;

failed:
    pthread_attr_destroy(&attr);
    return 0;
}

void config_sync_exit(void)
{
    pthread_join(config_th, NULL);
}

