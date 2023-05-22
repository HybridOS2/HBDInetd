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
        HLOG_ERR("Failed to call sigaction for SIGINT: %s\n", strerror (errno));
        return -1;
    }

    if (sigaction(SIGPIPE, &sa, 0) != 0) {
        HLOG_ERR("Failed to call sigaction for SIGPIPE: %s\n", strerror (errno));
        return -1;
    }

    if (sigaction(SIGCHLD, &sa, 0) != 0) {
        HLOG_ERR("Failed to call sigaction for SIGCHLD: %s\n", strerror (errno));
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
            "  -a --app=<app_name>          - Connect to HBDInetd with the specified app name.\n"
            "  -r --runner=<runner_name>    - Connect to HBDInetd with the specified runner name.\n"
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

    purc_log_facility_k facility = PURC_LOG_FACILITY_STDOUT;
    if (run_info.daemon) {
        if (daemonize()) {
            fprintf(stderr, "Failed to daemonize HBDInetd: %s\n",
                    strerror(errno));
            return EXIT_FAILURE;
        }
        else {
            uid_t euid = geteuid();
            if (euid == 0) {
                facility = PURC_LOG_FACILITY_SYSLOG;
            }
            else {
                facility = PURC_LOG_FACILITY_FILE;
            }
        }
    }

    if (!run_info.app_name[0] ||
            !purc_is_valid_app_name(run_info.app_name)) {
        strcpy(run_info.app_name, HBDINETD_APP_NAME);
    }

    if (!run_info.runner_name[0] ||
            !purc_is_valid_runner_name(run_info.runner_name)) {
        strcpy(run_info.runner_name, HBDINETD_RUNNER_MAIN);
    }

    ret = purc_init_ex(PURC_MODULE_EJSON, run_info.app_name,
            run_info.runner_name, NULL);
    if (ret != PURC_ERROR_OK) {
        fprintf(stderr, "Failed to initialize the PurC instance: %s\n",
            purc_get_error_message(ret));
        return EXIT_FAILURE;
    }

    if (run_info.verbose) {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT | PURC_LOG_MASK_INFO, facility);
    }
    else {
        purc_enable_log_ex(PURC_LOG_MASK_DEFAULT, facility);
    }

    run_info.dump_stm = purc_rwstream_new_for_dump(stderr, cb_stdio_write);

    kvlist_init(&run_info.devices, NULL);

    run_info.running = true;
    if (setup_signals() < 0)
        goto failed;

    cnnfd = hbdbus_connect_via_unix_socket(HBDBUS_US_PATH,
            run_info.app_name, run_info.runner_name, &conn);

    if (cnnfd < 0) {
        fprintf(stderr, "Failed to connect to HBDInetd server: %s\n",
                hbdbus_get_err_message(cnnfd));
        goto failed;
    }

    purc_assemble_endpoint_name(hbdbus_conn_own_host_name(conn),
            run_info.app_name, run_info.runner_name,
            run_info.self_endpoint);

    hbdbus_conn_set_user_data(conn, &run_info);
    enumerate_network_devices(&run_info);

    register_common_interfaces(conn);

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
        }

    } while (run_info.running && (run_info.shutdown_time == 0 ||
                time(NULL) < run_info.shutdown_time));

failed:
    revoke_common_interfaces(conn);
    if (cnnfd >= 0)
        hbdbus_disconnect(conn);

    cleanup_network_devices(&run_info);
    if (run_info.dump_stm)
        purc_rwstream_destroy(run_info.dump_stm);


    purc_cleanup();

    return EXIT_SUCCESS;
}

