/*
 * Copyright (C) 2014-2018 Sebastian Roland <seroland86@gmail.com>
 *
 * This file is part of Keeto.
 *
 * Keeto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Keeto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Keeto.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>

static int
pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp,
    void *app_data)
{
    return PAM_SUCCESS;
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        printf("argc != 2\n");
        return -1;
    }

    char *service_name = "sshd";
    char *user = argv[1];

    pam_handle_t *pamh = NULL;
    struct pam_conv pam_conversation = { pam_conv, NULL };
    int rc = pam_start(service_name, user, &pam_conversation, &pamh);
    if (rc != PAM_SUCCESS) {
        printf("failed to initialize pam (%s)\n", pam_strerror(pamh, rc));
        return -1;
    }
    /* do authentication */
    rc = pam_authenticate(pamh, 0);
    switch (rc) {
    case PAM_SUCCESS:
        printf("PAM_SUCCESS\n");
        break;
    default:
        printf("authentication error (%s)\n", pam_strerror(pamh,rc));
    }
    /* cleanup */
    rc = pam_end(pamh, 1);
    if (rc != PAM_SUCCESS) {
        printf("failed to destroy pam (%s)\n", pam_strerror(pamh,rc));
        return -1;
    }
    return 0;
}

