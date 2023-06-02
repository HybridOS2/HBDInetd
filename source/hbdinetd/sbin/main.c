/*
** main.c -- The main entry of HBDInetd.
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "hbdinetd.h"
#include "internal.h"
#include "log.h"

struct run_info run_info;

static void handle_signal_action(int sig_number)
{
    if (sig_number == SIGINT) {
        fprintf(stderr, "SIGINT caught, quit...\n");
        run_info.running = false;
    }
    else if (sig_number == SIGPIPE) {
        fprintf(stderr, "SIGPIPE caught; the server might have quitted!\n");
    }
    else if (sig_number == SIGCHLD) {
        pid_t pid;
        int status;

        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (WIFEXITED (status)) {
                if (WEXITSTATUS(status))
                    fprintf (stderr, "Player (%d) exited: return value: %d\n", 
                            pid, WEXITSTATUS(status));
            }
            else if (WIFSIGNALED(status)) {
                fprintf(stderr, "Player (%d) exited because of signal %d\n",
                        pid, WTERMSIG (status));
            }
        }
    }
}

static int setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = handle_signal_action;

    if (sigaction(SIGINT, &sa, 0) != 0) {
        HLOG_ERR("Failed to call sigaction for SIGINT: %s\n",
                strerror(errno));
        return -1;
    }

    if (sigaction(SIGPIPE, &sa, 0) != 0) {
        HLOG_ERR("Failed to call sigaction for SIGPIPE: %s\n",
                strerror(errno));
        return -1;
    }

    if (sigaction(SIGCHLD, &sa, 0) != 0) {
        HLOG_ERR("Failed to call sigaction for SIGCHLD: %s\n",
                strerror (errno));
        return -1;
    }

    return 0;
}

static void print_copying(FILE *fp)
{
    fprintf(fp,
            "\n"
            "HBDInetd - the network interface manager for HybridOS.\n"
            "\n"
            "Copyright (C) 2023 FMSoft <https://www.fmsoft.cn>\n"
            "\n"
            "HBDInetd is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n"
            "\n"
            "HBDInetd is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
            "GNU General Public License for more details.\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program.  If not, see http://www.gnu.org/licenses/.\n"
            );
    fprintf(fp, "\n");
}

static ssize_t cb_stdio_write(void *ctxt, const void *buf, size_t count)
{
    FILE *fp = ctxt;
    return fwrite(buf, 1, count, fp);
}

#define MY_VRT_OPTS \
    (PCVRNT_SERIALIZE_OPT_SPACED | PCVRNT_SERIALIZE_OPT_PRETTY | \
     PCVRNT_SERIALIZE_OPT_NOSLASHESCAPE)

void dump_json_object(FILE *fp, purc_variant_t v)
{
    if (fp == stderr) {
        purc_variant_serialize(v, run_info.dump_stm, 0, MY_VRT_OPTS, NULL);
    }
    else {
        purc_rwstream_t stm;
        stm = purc_rwstream_new_for_dump(fp, cb_stdio_write);
        purc_rwstream_destroy(stm);
    }
}

/* Command line help. */
static void print_usage(FILE *fp)
{
    fprintf(fp, "HBDInetd (%s) - the network interface manager for HybridOS\n\n",
            HBDINETD_VERSION_STRING);

    fprintf(fp,
            "Usage: "
            "hbdinetd [ options ... ]\n\n"
            ""
            "The following options can be supplied to the command:\n\n"
            ""
            "  -a --app=<app_name>          - Connect to HBDBus with the specified app name.\n"
            "  -r --runner=<runner_name>    - Connect to HBDBus with the specified runner name.\n"
            "  -d --daemon                  - Run hbdinetd as a daemon.\n"
            "  -v --verbose                 - Log verbose messages.\n"
            "  -V --version                 - Display version information and exit.\n"
            "  -C --copying                 - Display copying information and exit.\n"
            "  -h --help                    - Show this help.\n"
            "\n"
            );
}

static char short_options[] = "a:r:dvVh";
static struct option long_opts[] = {
    {"app"            , required_argument , NULL , 'a' } ,
    {"runner"         , required_argument , NULL , 'r' } ,
    {"daemon"         , no_argument       , NULL , 'd' } ,
    {"verbos"         , no_argument       , NULL , 'v' } ,
    {"version"        , no_argument       , NULL , 'V' } ,
    {"copying"        , no_argument       , NULL , 'c' } ,
    {"help"           , no_argument       , NULL , 'h' } ,
    {0, 0, 0, 0}
};

static int read_option_args(int argc, char **argv)
{
    int o, idx = 0;

    while ((o = getopt_long(argc, argv, short_options, long_opts, &idx)) >= 0) {
        if (-1 == o || EOF == o)
            break;
        switch (o) {
            case 'h':
                print_usage(stdout);
                return 1;

            case 'C':
                print_copying(stdout);
                return 1;

            case 'V':
                fprintf(stdout, "HBDInetd: %s\n", HBDBUS_VERSION_STRING);
                return 1;

            case 'a':
                if (strlen(optarg) < PURC_LEN_APP_NAME)
                    strcpy(run_info.app_name, optarg);
                break;

            case 'r':
                if (strlen(optarg) < PURC_LEN_RUNNER_NAME)
                    strcpy(run_info.runner_name, optarg);
                break;

            case 'd':
                run_info.daemon = true;
                break;

            case 'v':
                run_info.verbose = true;
                break;

            case '?':
                fprintf(stderr, "Run with the option `-h` for usage.\n");
                return -1;

            default:
                goto bad_arg;
        }
    }

    if (optind < argc) {
        goto bad_arg;
    }

    return 0;

bad_arg:
    fprintf(stderr, "Bad command line option."
            "Please run with the option `-h` for usage.\n");
    return -1;
}

static int
set_null_stdio(void)
{
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return -1;

    if (dup2(fd, 0) < 0 ||
            dup2(fd, 1) < 0 ||
            dup2(fd, 2) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static uid_t
daemonize(void)
{
    pid_t pid;

    if (chdir("/") != 0)
        return -1;

    if (set_null_stdio())
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;

    if (pid > 0)
        _exit(0);

    if (setsid() < 0)
        return -1;

    return 0;
}

static int my_wait_message(int timeout_ms)
{
    size_t count = 0;

    if (purc_inst_holding_messages_count(&count))
        return -1;

    if (count == 0) {
        if (timeout_ms > 1000) {
            pcutils_sleep(timeout_ms / 1000);
        }

        if (timeout_ms > 0) {
            unsigned int ms = timeout_ms % 1000;
            if (ms) {
                pcutils_usleep(ms * 1000);
            }
        }

        if (purc_inst_holding_messages_count(&count))
            return -1;
    }

    return (count > 0) ? 1 : 0;
}

static int shutdown_dhclient_runner(purc_atom_t rid_dhcli)
{
    int err_code = PURC_ERROR_OK;

    pcrdr_msg *shutdown_msg = pcrdr_make_request_message(
            PCRDR_MSG_TARGET_INSTANCE, rid_dhcli,
            CONFIG_OP_SHUTDOWN,
            NULL,
            purc_get_endpoint(NULL),
            PCRDR_MSG_ELEMENT_TYPE_VOID, NULL,
            NULL, PCRDR_MSG_DATA_TYPE_VOID, NULL, 0);

    if (shutdown_msg) {
        size_t n = purc_inst_move_message(rid_dhcli, shutdown_msg);
        pcrdr_release_message(shutdown_msg);
        if (n == 0) {
            err_code = PCRDR_ERROR_UNEXPECTED;
            goto failed;
        }
    }
    else {
        err_code = PURC_ERROR_OUT_OF_MEMORY;
        goto failed;
    }

    int left_ms = PCRDR_DEF_TIME_EXPECTED * 1000;
    while (left_ms > 0) {
        if (my_wait_message(10) == 0)
            left_ms -= 10;
        else
            break;
    }

    if (left_ms <= 0) {
        err_code = PCRDR_ERROR_TIMEOUT;
        goto failed;
    }

    pcrdr_msg *msg = purc_inst_take_away_message(0);
    if (msg == NULL) {
        err_code = PCRDR_ERROR_UNEXPECTED;
        goto failed;
    }
    pcrdr_release_message(msg);

failed:
    return err_code;
}

int issue_dhcp_request(hbdbus_conn *conn, const char *ifname)
{
    struct run_info *info = hbdbus_conn_get_user_data(conn);
    int err_code = PURC_ERROR_OK;

    pcrdr_msg *msg = pcrdr_make_request_message(
            PCRDR_MSG_TARGET_INSTANCE, info->rid_dhcli,
            CONFIG_OP_CONFIG,
            PCRDR_REQUESTID_NORETURN,
            purc_get_endpoint(NULL),
            PCRDR_MSG_ELEMENT_TYPE_ID, ifname,
            NULL, PCRDR_MSG_DATA_TYPE_VOID, NULL, 0);

    if (msg) {
        size_t n = purc_inst_move_message(info->rid_dhcli, msg);
        pcrdr_release_message(msg);
        if (n == 0) {
            err_code = PCRDR_ERROR_UNEXPECTED;
            goto failed;
        }
    }

failed:
    return err_code;
}

static void
handle_event_from_other_runners(hbdbus_conn *conn, const pcrdr_msg *msg)
{
    const char *event_name;
    event_name = purc_variant_get_string_const(msg->eventName);

    const char *ifname = NULL;
    ifname = purc_variant_get_string_const(msg->elementValue);

    const char *reason = NULL;
    reason = purc_variant_get_string_const(msg->property);

    HLOG_INFO("got an event message:\n");
    HLOG_INFO("    type:            %d\n", msg->type);
    HLOG_INFO("    target:          %d\n", msg->target);
    HLOG_INFO("    targetValue:     %d\n", (int)msg->targetValue);
    HLOG_INFO("    eventName:       %s\n", event_name);
    HLOG_INFO("    elementValue:    %s\n", ifname);
    HLOG_INFO("    properttValue:   %s\n", reason);
    HLOG_INFO("    sourceURI:       %s\n",
            purc_variant_get_string_const(msg->sourceURI));
    HLOG_INFO("    data:            %s\n",
            msg->data ? purc_variant_get_string_const(msg->data) : "(void)");

    void *data = kvlist_get(&run_info.devices, ifname);
    if (data == NULL) {
        HLOG_ERR("Not a managed network interface: %s\n", ifname);
        return;
    }

    struct pcutils_printbuf my_buff, *pb = &my_buff;
    pcutils_printbuf_init(pb);

    const char *event = NULL;
    if (strcmp(event_name, CONFIG_EV_SUCCEEDED) == 0) {
        const char *config = purc_variant_get_string_const(msg->data);
        assert(config);

        struct network_device *netdev = *(struct network_device **)data;
        if (update_network_device_config(netdev, "dhcp", config)) {
            HLOG_ERR("Failed to update device %s with configuration: %s\n",
                    ifname, config);
            goto done;
        }

        char *escaped_config = pcutils_escape_string_for_json(config);

        if (update_system_settings(conn, netdev)) {
            HLOG_ERR("Failed to update system settings\n");
            goto done;
        }

        pcutils_printbuf_format(pb,
                "{"
                    "\"device\":\"%s\","
                    "\"method\":\"dhcp\","
                    "\"config\":\"%s\""
                "}",
              ifname, escaped_config);
        free(escaped_config);

        event = BUBBLE_DEVICECONFIGURED;
    }
    else if (strcmp(event_name, CONFIG_EV_FAILED) == 0) {
        pcutils_printbuf_format(pb,
                "{"
                    "\"device\":\"%s\","
                    "\"method\":\"dhcp\","
                    "\"reason\":\"%s\""
                "}",
                ifname, reason);
        event = BUBBLE_DEVICECONFIGFAILED;
    }

done:
    if (pb->buf) {
        int ret = 0;

        if (event) {
            HLOG_INFO("Firing an event: %s\n", event);
            ret = hbdbus_fire_event(conn, event, pb->buf);
        }

        if (ret) {
            HLOG_ERR("Failed when firing event: %s\n", event);
        }

        free(pb->buf);
    }
    else {
        HLOG_ERR("OOM when using printbuf\n");
    }
}

int main(int argc, char **argv)
{
    int cnnfd = -1, maxfd, ret;
    hbdbus_conn* conn;
    fd_set rfds;
    struct timeval tv;

    ret = read_option_args(argc, argv);
    if (ret > 0)
        return EXIT_SUCCESS;
    else if (ret < 0)
        return EXIT_FAILURE;

    run_info.log_facility = PURC_LOG_FACILITY_STDOUT;
    if (run_info.daemon) {
        if (daemonize()) {
            fprintf(stderr, "Failed to daemonize HBDInetd: %s\n",
                    strerror(errno));
            return EXIT_FAILURE;
        }
        else {
            uid_t euid = geteuid();
            if (euid == 0) {
                run_info.log_facility = PURC_LOG_FACILITY_SYSLOG;
            }
            else {
                run_info.log_facility = PURC_LOG_FACILITY_FILE;
            }
        }
    }

    if (!run_info.app_name[0] ||
            !purc_is_valid_app_name(run_info.app_name)) {
        strcpy(run_info.app_name, HBDINETD_APP_NAME);
    }

    if (!run_info.runner_name[0] ||
            !purc_is_valid_runner_name(run_info.runner_name)) {
        strcpy(run_info.runner_name, HBDINETD_RUN_MAIN);
    }

    if ((run_info.rid_dhcli = config_start(&run_info)) == 0) {
        fprintf(stderr,
                "Failed to initialize the built-in DHCP client runner\n");
        return EXIT_FAILURE;
    }

    ret = purc_init_ex(PURC_MODULE_EJSON, run_info.app_name,
            run_info.runner_name, NULL);
    if (ret != PURC_ERROR_OK) {
        fprintf(stderr, "Failed to initialize the PurC instance: %s\n",
            purc_get_error_message(ret));
        return EXIT_FAILURE;
    }

    run_info.rid = purc_inst_create_move_buffer(PCINST_MOVE_BUFFER_FLAG_NONE,
            16);

    if (run_info.verbose) {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT | PURC_LOG_MASK_INFO,
                run_info.log_facility);
    }
    else {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT,
                run_info.log_facility);
    }

    run_info.dump_stm = purc_rwstream_new_for_dump(stderr, cb_stdio_write);

    kvlist_init(&run_info.devices, NULL);

    run_info.running = true;
    if (setup_signals() < 0)
        goto failed;

    cnnfd = hbdbus_connect_via_unix_socket(HBDBUS_US_PATH,
            run_info.app_name, run_info.runner_name, &conn);
    if (cnnfd < 0) {
        HLOG_ERR("Failed to connect to HBDBus server: %s\n",
                hbdbus_get_err_message(cnnfd));
        goto failed_hbdbus;
    }

    purc_assemble_endpoint_name(hbdbus_conn_own_host_name(conn),
            run_info.app_name, run_info.runner_name,
            run_info.self_endpoint);

    hbdbus_conn_set_user_data(conn, &run_info);
    enumerate_network_devices(&run_info);

    register_common_interfaces(conn);

    save_system_settings(conn);

    maxfd = cnnfd;
    do {
        int retval;

        FD_ZERO(&rfds);
        FD_SET(cnnfd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;    // 100ms
        retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            if (errno == EINTR)
                continue;
            else
                break;
        }
        else if (retval) {
            if (FD_ISSET(cnnfd, &rfds)) {
                int err_code = hbdbus_read_and_dispatch_packet(conn);
                if (err_code) {
                    HLOG_ERR("Failed hbdbus_read_and_dispatch_packet(): %s\n",
                            hbdbus_get_err_message(err_code));
                    if (err_code == HBDBUS_EC_IO)
                        break;
                }

            }
        }
        else {
            size_t n;

            /* check netdevice here */
            const char* name;
            void *data;
            kvlist_for_each(&run_info.devices, name, data) {
                struct network_device *netdev;
                netdev = *(struct network_device **)data;
                if (netdev->check) {
                    netdev->check(conn, netdev);
                }
            }

            if (purc_inst_holding_messages_count(&n) == 0 && n > 0) {
                pcrdr_msg *msg = purc_inst_take_away_message(0);
                if (msg->type == PCRDR_MSG_TYPE_EVENT) {
                    handle_event_from_other_runners(conn, msg);
                }
                else {
                    HLOG_WARN("Got a message not intersted in\n");
                }

                pcrdr_release_message(msg);
            }
        }

    } while (run_info.running && (run_info.shutdown_time == 0 ||
                time(NULL) < run_info.shutdown_time));

failed:
    restore_system_settings(conn);
    revoke_common_interfaces(conn);

failed_hbdbus:
    if (cnnfd >= 0)
        hbdbus_disconnect(conn);

    cleanup_network_devices(&run_info);
    if (run_info.dump_stm)
        purc_rwstream_destroy(run_info.dump_stm);

    if ((ret = shutdown_dhclient_runner(run_info.rid_dhcli))) {
        HLOG_ERR("Failed to shutdown dhclient runner: %s\n",
            purc_get_error_message(ret));
    }

    purc_inst_destroy_move_buffer();
    purc_cleanup();

    if (run_info.rid_dhcli)
        config_sync_exit();

    return EXIT_SUCCESS;
}

