/**
 * Copyright (C) 2013, 2014, 2015, 2017, 2019, 2021, 2025 Genome Research
 * Ltd. All rights reserved.
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
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "baton.h"

static int acl_flag        = 0;
static int avu_flag        = 0;
static int checksum_flag   = 0;
static int coll_flag       = 0;
static int debug_flag      = 0;
static int help_flag       = 0;
static int obj_flag        = 0;
static int replicate_flag  = 0;
static int silent_flag     = 0;
static int size_flag       = 0;
static int timestamp_flag  = 0;
static int unbuffered_flag = 0;
static int unsafe_flag     = 0;
static int verbose_flag    = 0;
static int version_flag    = 0;

int main(const int argc, char *argv[]) {
    option_flags flags = SEARCH_COLLECTIONS | SEARCH_OBJECTS;
    int exit_status = 0;
    char *zone_name = NULL;
    const char *json_file = NULL;
    FILE *input     = NULL;
    unsigned long max_connect_time = DEFAULT_MAX_CONNECT_TIME;

    while (1) {
        static struct option long_options[] = {
            // Flag options
            {"acl",        no_argument, &acl_flag,        1},
            {"avu",        no_argument, &avu_flag,        1},
            {"checksum",   no_argument, &checksum_flag,   1},
            {"coll",       no_argument, &coll_flag,       1},
            {"debug",      no_argument, &debug_flag,      1},
            {"help",       no_argument, &help_flag,       1},
            {"obj",        no_argument, &obj_flag,        1},
            {"replicate",  no_argument, &replicate_flag,  1},
            {"silent",     no_argument, &silent_flag,     1},
            {"size",       no_argument, &size_flag,       1},
            {"timestamp",  no_argument, &timestamp_flag,  1},
            {"unbuffered", no_argument, &unbuffered_flag, 1},
            {"unsafe",     no_argument, &unsafe_flag,     1},
            {"verbose",    no_argument, &verbose_flag,    1},
            {"version",    no_argument, &version_flag,    1},
            // Indexed options
            {"connect-time", required_argument, NULL, 'c'},
            {"file",         required_argument, NULL, 'f'},
            {"zone",         required_argument, NULL, 'z'},
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
                const unsigned long val = strtoul(optarg, &end_ptr, 10);

                if ((errno == ERANGE && val == ULONG_MAX) ||
                    (errno != 0 && val == 0)              ||
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

    if (coll_flag && !obj_flag)  {
        flags = flags ^ SEARCH_OBJECTS;
    }
    else if (obj_flag && !coll_flag)  {
        flags = flags ^ SEARCH_COLLECTIONS;
    }

    if (unsafe_flag)     flags = flags | UNSAFE_RESOLVE;
    if (unbuffered_flag) flags = flags | FLUSH;

    if (acl_flag)        flags = flags | PRINT_ACL;
    if (avu_flag)        flags = flags | PRINT_AVU;
    if (checksum_flag)   flags = flags | PRINT_CHECKSUM;
    if (replicate_flag)  flags = flags | PRINT_REPLICATE;
    if (size_flag)       flags = flags | PRINT_SIZE;
    if (timestamp_flag)  flags = flags | PRINT_TIMESTAMP;

    const char *help =
        "Name\n"
        "    baton-metaquery\n"
        "\n"
        "Synopsis\n"
        "\n"
        "    baton-metaquery [--acl] [--avu] [--checksum] [--coll]\n"
        "                    [--connect-time <n>] [--file <JSON file>]\n"
        "                    [--obj ] [--replicate] [--silent] [--size]\n"
        "                    [--timestamp] [--unbuffered] [--unsafe]\n"
        "                    [--verbose] [--version] [--zone <name>]\n"
        "\n"
        "Description\n"
        "    Finds items in iRODS by AVU, given a query constructed\n"
        "from a JSON input file.\n"
        "\n"
        "  --acl          Print access control lists in output.\n"
        "  --avu          Print AVU lists in output.\n"
        "  --checksum     Print data object checksums in output.\n"
        "  --connect-time The duration in seconds after which a connection\n"
        "                 to iRODS will be refreshed (closed and reopened\n"
        "                 between JSON documents) to allow iRODS server\n"
        "                 resources to be released. Optional, defaults to\n"
        "                 10 minutes.\n"
        "  --coll         Limit search to collection metadata only.\n"
        "  --file         The JSON file describing the query. Optional,\n"
        "                 defaults to STDIN.\n"
        "  --obj          Limit search to data object metadata only.\n"
        "  --replicate    Report data object replicates.\n"
        "  --silent       Silence error messages.\n"
        "  --timestamp    Print timestamps in output.\n"
        "  --unbuffered   Flush print operations for each JSON object.\n"
        "  --unsafe       Permit unsafe relative iRODS paths.\n"
        "  --verbose      Print verbose messages to STDERR.\n"
        "  --version      Print the version number and exit.\n"
        "  --zone         The zone to search. Optional.\n";

    if (help_flag) {
        printf("%s\n",help);
        exit(0);
    }

    if (version_flag) {
        printf("%s\n", VERSION);
        exit(0);
    }

    if (debug_flag)   set_log_threshold(DEBUG);
    if (verbose_flag) set_log_threshold(NOTICE);
    if (silent_flag)  set_log_threshold(FATAL);

    declare_client_name(argv[0]);
    input = maybe_stdin(json_file);
    if (!input) {
        exit(1);
    }

    operation_args_t args = { .flags            = flags,
                              .zone_name        = zone_name,
                              .max_connect_time = max_connect_time };

    const int status = do_operation(input, baton_json_metaquery_op, &args);
    if (input != stdin) fclose(input);

    if (status != 0) exit_status = 5;

    exit(exit_status);
}
