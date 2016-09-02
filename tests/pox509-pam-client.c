/*
 * Copyright (C) 2014-2016 Sebastian Roland <seroland86@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>

int
pam_conversation(int num_msg, struct pam_message **msg,
    struct pam_response **resp, void *app_data)
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
    user = argv[1];
    int end_status = 1;

    struct pam_conv *pam_conversation = { pam_conversation, NULL };
    pam_handle_t *pamh = NULL;
    int rc = pam_start(service_name, user, pam_conversation, &pamh);
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

    rc = pam_end(pamh, end_status);
    if (rc != PAM_SUCCESS) {
        printf("failed to destroy pam (%s)\n", pam_strerror(pamh,rc));
        return -1;
    }

    return 1;
}

