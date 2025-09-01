/**
 * Copyright (C) 2017, 2018, 2019, 2021, 2025 Genome Research Ltd. All
 * rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Keith James <kdj@sanger.ac.uk>
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "config.h"
#include "baton.h"
#include "operations.h"
#include "utilities.h"

static int debug_flag          = 0;
static int help_flag           = 0;
static int no_error_flag       = 0;
static int server_version_flag = 0;
static int silent_flag         = 0;
static int single_server_flag  = 0;
static int unbuffered_flag     = 0;
static int unsafe_flag         = 0;
static int verbose_flag        = 0;
static int version_flag        = 0;
static int wlock_flag          = 0;

static size_t default_buffer_size = 1024 * 64 * 16 * 2;

int main(const int argc, char *argv[]) {
    option_flags flags = 0;
    int exit_status    = 0;
    char *zone_name = NULL;
    const char *json_file = NULL;
    FILE *input     = NULL;
    long max_connect_time = DEFAULT_MAX_CONNECT_TIME;

    while (1) {
        static struct option long_options[] = {
            // Flag options
            {"debug",          no_argument, &debug_flag,          1},
            {"help",           no_argument, &help_flag,           1},
            {"no-error",       no_argument, &no_error_flag,       1},
            {"server-version", no_argument, &server_version_flag, 1},
            {"silent",         no_argument, &silent_flag,         1},
            {"single-server",  no_argument, &single_server_flag,  1},
            {"unbuffered",     no_argument, &unbuffered_flag,     1},
            {"unsafe",         no_argument, &unsafe_flag,         1},
            {"verbose",        no_argument, &verbose_flag,        1},
            {"version",        no_argument, &version_flag,        1},
            {"wlock",          no_argument, &wlock_flag,          1},
            // Indexed options
            {"connect-time",  required_argument, NULL, 'c'},
            {"file",          required_argument, NULL, 'f'},
            {"zone",          required_argument, NULL, 'z'},
            {0, 0, 0, 0}
        };

        int option_index = 0;
        const int c = getopt_long_only(argc, argv, "c:f:z:",
                                       long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1) break;

        switch (c) {
            case 'c':
                errno = 0;
                char *end_ptr;
                const long val = strtol(optarg, &end_ptr, 10);

                if ((errno == ERANGE && val == LONG_MAX) ||
                    (errno != 0 && val == 0)             ||
                    end_ptr == optarg) {
                    fprintf(stderr, "Invalid --connect-time '%s'\n", optarg);
                    exit(1);
                }

                max_connect_time = val;
                break;

            case 'f':
                json_file = optarg;
                break;

            case 'z':
                zone_name = optarg;
                break;

            case '?':
                // getopt_long already printed an error message
                break;

            default:
                // Ignore
                break;
        }
    }

    const char *help =
        "Name\n"
        "    baton-do\n"
        "\n"
        "Synopsis\n"
        "\n"
        "    baton-do [--file <JSON file>] [--connect-time <n>] [--silent]\n"
        "             [--unbuffered] [--verbose] [--version] [--wlock]\n"
        "             [--zone]\n"
        "\n"
        "Description\n"
        "    Performs remote operations as described in the JSON\n"
        "    input file.\n"
        "\n"
        "    --connect-time   The duration in seconds after which a connection\n"
        "                     to iRODS will be refreshed (closed and reopened\n"
        "                     between JSON documents) to allow iRODS server\n"
        "                     resources to be released. Optional, defaults to\n"
        "                     10 minutes.\n"
        "    --file           The JSON file describing the operations.\n"
        "                     Optional, defaults to STDIN.\n"
        "    --no-error       Do not return a non-zero exit code on iRODS\n"
        "                     errors. Errors will still be reported in-band\n"
        "                     as JSON responses.\n"
        "    --server-version Print the version of the server and exit.\n"
        "    --silent         Silence error messages.\n"
        "    --single-server  Only connect to a single iRODS server\n"
        "    --unbuffered     Flush print operations for each JSON object.\n"
 
        "    --verbose        Print verbose messages to STDERR.\n"
        "    --version        Print the version number and exit.\n"
        "    --wlock          Enable server-side advisory write locking.\n"
        "                     Optional, defaults to false.\n"
        "    --zone           The zone to operate within. Optional.\n";

    if (help_flag) {
        printf("%s\n",help);
        exit(0);
    }

    if (version_flag) {
        printf("%s\n", VERSION);
        exit(0);
    }

    if (server_version_flag) {
        baton_session_t *session = new_baton_session();
        int status = baton_connect(session);
        if (status != 0) {
            logmsg(ERROR, "Failed to get server version");
            exit(1);
        }

        baton_error_t error;
        char *server_version = get_server_version(session->conn, &error);

        baton_disconnect(session);
        free_baton_session(session);

        if (error.code != 0) {
            logmsg(ERROR, "Failed to get server version");
            exit(1);
        }
        printf("%s\n", server_version);
        exit(0);
    }

    if (single_server_flag) flags = flags | SINGLE_SERVER;
    if (unbuffered_flag)    flags = flags | FLUSH;
    if (unsafe_flag)        flags = flags | UNSAFE_RESOLVE;
    if (wlock_flag)         flags = flags | WRITE_LOCK;

    if (debug_flag)   set_log_threshold(DEBUG);
    if (verbose_flag) set_log_threshold(NOTICE);
    if (silent_flag)  set_log_threshold(FATAL);

    declare_client_name(argv[0]);
    input = maybe_stdin(json_file);
    if (!input) {
        exit(1);
    }

    operation_args_t args = { .flags            = flags,
                              .buffer_size      = default_buffer_size,
                              .zone_name        = zone_name,
                              .max_connect_time = max_connect_time};

    const int status = do_operation(input, baton_json_dispatch_op, &args);
    if (input != stdin) fclose(input);

    if (status != 0 && !no_error_flag) exit_status = 5;

    exit(exit_status);
}
