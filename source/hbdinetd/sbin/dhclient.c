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

struct this_run_info {
    unsigned nr_cors;
};

static int init_instance(struct this_run_info *info)
{
    (void)info;
    return 0;
}

static void deinit_instance(struct this_run_info *info)
{
    (void)info;
}

static void shutdown_handler(struct this_run_info *info,
        const pcrdr_msg *request, pcrdr_msg *response)
{
    (void)info;

    purc_atom_t endpoint_atom;
    const char *endpoint_name = purc_get_endpoint(&endpoint_atom);
    assert(endpoint_name);  /* must be valid */

    response->type = PCRDR_MSG_TYPE_RESPONSE;
    response->requestId = purc_variant_ref(request->requestId);
    response->sourceURI = purc_variant_make_string(endpoint_name, false);
    response->retCode = PCRDR_SC_OK;
    response->resultValue = (uint64_t)endpoint_atom;
    response->dataType = PCRDR_MSG_DATA_TYPE_VOID;
    response->data = PURC_VARIANT_INVALID;
}

static void event_loop(struct this_run_info *info)
{
    size_t n;
    int ret;

    do {
        ret = purc_inst_holding_messages_count(&n);
        if (ret) {
            HLOG_ERR("purc_inst_holding_messages_count failed: %d\n", ret);
        }
        else if (n == 0) {
            pcutils_usleep(50000); // 50ms.
            continue;
        }

        purc_clr_error();

        pcrdr_msg *msg = purc_inst_take_away_message(0);

        if (msg->type == PCRDR_MSG_TYPE_EVENT) {
            const char *event_name;
            event_name = purc_variant_get_string_const(msg->eventName);

            if (strcmp(event_name, "quit") == 0 &&
                    msg->target == PCRDR_MSG_TARGET_INSTANCE &&
                    msg->targetValue == 0) {
                HLOG_INFO("got the quit from %s\n",
                        purc_variant_get_string_const(msg->sourceURI));
                pcrdr_release_message(msg);
                break;
            }
            else {
                HLOG_INFO("got an event message not interested in:\n");
                HLOG_INFO("    type:        %d\n", msg->type);
                HLOG_INFO("    target:      %d\n", msg->target);
                HLOG_INFO("    targetValue: %d\n", (int)msg->targetValue);
                HLOG_INFO("    eventName:   %s\n", event_name);
                HLOG_INFO("    sourceURI: %s\n",
                        purc_variant_get_string_const(msg->sourceURI));
            }
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

            const char *op;
            op = purc_variant_get_string_const(msg->operation);

            HLOG_INFO("Got a request message for operation %s from %s\n",
                    op, purc_variant_get_string_const(msg->sourceURI));

            pcrdr_msg *response = pcrdr_make_void_message();
            if (msg->target == PCRDR_MSG_TARGET_INSTANCE &&
                    strcmp(op, DHCLI_OP_SHUTDOWN) == 0) {
                shutdown_handler(info, msg, response);
                purc_inst_move_message(requester, response);
                pcrdr_release_message(msg);
                pcrdr_release_message(response);
                break;
            }

            /* for other requests, reponse PCRDR_SC_BAD_REQUEST */
            response->type = PCRDR_MSG_TYPE_RESPONSE;
            response->requestId = purc_variant_ref(msg->requestId);
            response->sourceURI = purc_variant_make_string(
                    purc_get_endpoint(NULL), false);
            response->retCode = PCRDR_SC_BAD_REQUEST;
            response->resultValue = 0;
            response->dataType = PCRDR_MSG_DATA_TYPE_VOID;
            response->data = PURC_VARIANT_INVALID;

            const char *request_id;
            request_id = purc_variant_get_string_const(msg->requestId);
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

    } while(true);
}

struct thread_arg {
    const struct run_info *mainrun;
    sem_t          *wait;
    purc_atom_t     rid;
};

static void* dhcli_thread_entry(void* arg)
{
    struct thread_arg *my_arg = (struct thread_arg *)arg;
    sem_t *sw = my_arg->wait;
    purc_atom_t rid = 0;

    int ret = purc_init_ex(PURC_MODULE_EJSON,
            HBDINETD_APP_NAME, HBDINETD_RUNNER_DHCLIENT, NULL);
    if (ret == PURC_ERROR_OK) {
        rid = my_arg->rid = purc_inst_create_move_buffer(
                PCINST_MOVE_BUFFER_FLAG_NONE, 16);
    }

    fprintf(stderr, "log facility of main run: %d\n", my_arg->mainrun->log_facility);
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
        struct this_run_info info;

        if (init_instance(&info) == 0) {
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

static pthread_t dhcli_th;
purc_atom_t dhcli_start(const struct run_info *mainrun)
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

    ret = pthread_create(&dhcli_th, &attr, dhcli_thread_entry, &arg);
    if (ret) {
        HLOG_ERR("Failed to create thread for DHCP client: %s\n",
                strerror(errno));
        sem_close(arg.wait);
        goto failed;
    }
    pthread_attr_destroy(&attr);

    sem_wait(arg.wait);
    sem_close(arg.wait);
ALLOW_DEPRECATED_DECLARATIONS_END

    return arg.rid;

failed:
    pthread_attr_destroy(&attr);
    return 0;
}

void dhcli_sync_exit(void)
{
    fprintf(stderr, "called: %s\n", __func__);
    pthread_join(dhcli_th, NULL);
}

