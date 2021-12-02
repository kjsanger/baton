/**
 * Copyright (C) 2021 Genome
 * Research Ltd. All rights reserved.
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
 * @file signal_handler.c
 * @author Michael Kubiak <mk35@sanger.ac.uk>
 */

#include "baton.h"

#include <signal.h>

rcComm_t **conn = NULL;
int signals[] = {SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGSEGV, SIGBUS, 0};
int test = 0;

void test_handler() {test=1;} // for testing the signal handler

void handle_signal(int signal){
    logmsg(FATAL, "Signal %i (%s) received", signal, strsignal(signal));
    if (conn) {
        logmsg(FATAL, "Disconnecting from iRODS");
        rcDisconnect(*conn);
        *conn = NULL;
    }
    if (test == 0) {
      exit(signal);
    }
}

int apply_signal_handler(rcComm_t **connection) {
    conn = connection;

    struct sigaction saction;
    saction.sa_handler = &handle_signal;
    saction.sa_flags = 0;
    sigemptyset(&saction.sa_mask);
    int sigstatus;

    // Exit gracefully on fatal signals
    for (int i = 0; signals[i] != 0; i++) {
        sigstatus = sigaction(signals[i], &saction, NULL);
        if (sigstatus != 0) {
            logmsg(FATAL, "Failed to set the iRODS client handler for signal %s", strsignal(signals[i]));
            return -1;
        }
    }

    // Ignore SIGPIPE
    saction.sa_handler = SIG_IGN;
    sigstatus = sigaction(SIGPIPE, &saction, NULL);
    if (sigstatus != 0) {
        logmsg(FATAL, "Failed to set the iRODS client SIGPIPE handler");
        return -1;
    }

    return 0;
}
