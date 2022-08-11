/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "mctp-vdm-nvda.h"
#include "mctp-vdm-commands.h"

#include "ctrld/mctp-ctrl.h"

/* MCTP-VDM response binary file */
#define MCTP_VDM_RESP_OUTPUT_FILE       "/var/mctp-vdm-output.bin"

/* Global definitions */
uint8_t g_verbose_level = 0;

/* Global commandline options */
static const struct option options[] = {
    { "verbose",    no_argument,        0, 'v' },
    { "teid",       required_argument,  0, 't'},
    { "intf",       required_argument,  0, 'i'},
    { "cmd",        required_argument,  0, 'c' },
    { "help",       no_argument,        0, 'h' },
    { 0 },
};

/* MCTP-VDM utility usage function */
static void usage(void)
{
	fprintf(stderr, "usage: mctp-vdm-util -t [eid] -c [cmd] [params]\n");
	fprintf(stderr, "-t/-teid: Endpoint EID\n");
	fprintf(stderr, "-c/-cmd: Command\n");
//	fprintf(stderr, "intf: PCIe or SPI\n");
	fprintf(stderr, "Available commands:\n \
		selftest - need 4 bytes as the payload\n \
		boot_complete_v1\n \
		boot_complete_v2_slot_0, boot_complete_v2_slot_1\n \
		set_heartbeat_enable, set_heartbeat_disable\n \
		heartbeat\n \
		query_boot_status\n \
		download_log\n \
		restart_notification\n \
		background_copy_init\n \
		background_copy_disable, background_copy_enable\n \
		background_copy_disable_one, background_copy_enable_one\n \
		background_copy_query_status, background_copy_query_progress\n");
}

struct ctx {
    bool verbose;
};

struct ctx ctx = {0};

static int check_hex_number(char *s) {
	char ch = *s;
	int  len = 0;

	while ((ch=*s++) != 0) {
	    if (len == 2 || isxdigit(ch) == 0) {
		return -1;
	    }
	    len ++;
	}
	return 0;
}

/*
 * Main function
 */
int main(int argc, char * const *argv)
{
    int         rc = -1;
    int 	i = 0, len = 0;
    char        item[MCTP_VDM_COMMAND_NAME_SIZE] = {'\0'};
    char 	payload[MCTP_VDM_SELFTEST_PAYLOAD_SIZE] = { '\0' };
    char        intf[16] = {0};
    char        path[32] = {0};
    int         fd = 0;
    uint8_t     teid = 0;
    uint8_t payload_required = 0;

    for (;;) {
        rc = getopt_long(argc, argv, "vt:i:c:h", options, NULL);
        if (rc == -1)
            break;

        switch (rc) {
            case 'v':
                ctx.verbose = true;
                break;
            case 't':
                teid = (uint8_t)strtol(optarg, NULL, 10);
                printf("teid = %d\n", teid);
                break;
            case 'c':
                snprintf(item, sizeof(item),"%s", optarg);
                printf("Test command = %s\n", item);
		payload_required = (strcmp(item, "selftest") == 0);
                break;
            case 'i':
                snprintf(intf, sizeof(intf), "%s", optarg);
                break;
            case 'h':
                usage();
                return EXIT_SUCCESS;
            default:
                fprintf(stderr, "Invalid argument\n");
                return EXIT_FAILURE;
        }
    }
    /* need more data as the payload passing to selftest commands */
    if (payload_required && optind == argc) {
	    fprintf (stderr, "Error! Selftest command needs 4 bytes payload.\n\n");
	    usage();
	    return EXIT_FAILURE;
    }
    else if (payload_required == 0 && optind != argc) {
	    fprintf (stderr, "Error! we don't need the paylod.\n\n");
	    usage();
	    return EXIT_FAILURE;
    }
    /* For selftest command, we may need more data as the payload
    * for which items to be tested.
    */
    for (i = optind, len = 0; i < argc && i < MCTP_VDM_SELFTEST_PAYLOAD_SIZE;
	    i++, len++) {
	    rc = check_hex_number(&argv[i][0]);
	    if (rc == -1) {
		    fprintf (stderr, "Error! we need hex-based data.\n\n");
		    usage();
		    return EXIT_FAILURE;
	    }

	    payload[len] = strtol(argv[i], NULL, 16);
    }

    path[0] = 0;
    snprintf(&path[1], sizeof(path) - 1, "mctp-pcie-mux");
    /*  Disable option for interface selection which will be the feature.
    if (!strncmp (intf, "pcie", 4)) {
	    snprintf (&path[1], sizeof(path) - 1, "mctp-pcie-mux");
    }
    else if (!strncmp (intf, "spi", 3)) {
	    snprintf (&path[1], sizeof(path) - 1, "mctp-spi-mux");
    }
    else {
	    fprintf(stderr, "please specify the interface spi or pcie\n");
	    return EXIT_FAILURE;
    }*/


    /* Establish the socket connection */
    rc = mctp_usr_socket_init(&fd, path, MCTP_MESSAGE_TYPE_VDIANA);
    if (MCTP_REQUESTER_SUCCESS != rc) {
        fprintf (stderr, "Failed to open mctp socket\n");
        return EXIT_FAILURE;
    }

	
    if (!strcmp(item, "selftest")) {
		rc = selftest(fd, teid, payload, len);
        if (rc) {
            fprintf(stderr, "fail to do selfets: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "boot_complete_v1")) {

        rc = boot_complete_v1(fd, teid);
        if (rc) {
            fprintf(stderr, "fail to do boot complete: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "boot_complete_v2_slot_0")) {

        rc = boot_complete_v2(fd, teid, MCTP_VDM_BOOT_COMPLETE_VALID,
                                            MCTP_VDM_BOOT_COMPLETE_SLOT0);
        if (rc) {
            fprintf(stderr, "fail to do boot complete v2: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "boot_complete_v2_slot_1")) {

        rc = boot_complete_v2(fd, teid, MCTP_VDM_BOOT_COMPLETE_VALID,
                                            MCTP_VDM_BOOT_COMPLETE_SLOT1);
        if (rc) {
            fprintf(stderr, "fail to do boot complete v2: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "set_heartbeat_enable")) {
        rc = set_heartbeat_enable(fd, teid, MCTP_VDM_HEARTBEAT_ENABLE);
        if (rc) {
            fprintf(stderr, "fail to enable heartbeat %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "set_heartbeat_disable")) {
        rc = set_heartbeat_enable(fd, teid, MCTP_VDM_HEARTBEAT_DISABLE);
        if (rc) {
            fprintf(stderr, "fail to disable heartbeat %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "heartbeat")) {
        rc = heartbeat(fd, teid);
        if (rc) {
            fprintf(stderr, "fail to send heartbeat event: %d\n", rc);
            goto exit;
        }
    } else if (!strcmp(item, "restart_notification")) {
        rc = restart_notification(fd, teid);
        if (rc) {
            fprintf(stderr, "fail to send restart notification: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "query_boot_status")) {
        rc = query_boot_status(fd, teid);
        if (rc) {
            fprintf(stderr, "fail to send query_boot_status event: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "download_log")) {
        rc = download_log(fd, teid, MCTP_VDM_RESP_OUTPUT_FILE, ctx.verbose);
        if (rc) {
            fprintf(stderr, "fail to download log: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_disable")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_DISABLE);
        if (rc) {
            fprintf(stderr, "fail to disable background copy: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_enable")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_ENABLE);
        if (rc) {
            fprintf(stderr, "fail to enable background copy: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_disable_one")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT);
        if (rc) {
            fprintf(stderr, "fail to disable one bg copy: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_enable_one")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT);
        if (rc) {
            fprintf(stderr, "fail to enble one bg copy: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_init")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_INIT);
        if (rc) {
            fprintf(stderr, "fail to init bg: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_query_status")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS);
        if (rc) {
            fprintf(stderr, "fail to query bg: %d\n", rc);
            goto exit;
        }
    }
    else if (!strcmp(item, "background_copy_query_progress")) {
        rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_PROGRESS);
        if (rc) {
            fprintf(stderr, "fail to query prog bg: %d\n", rc);
            goto exit;
        }
    }
    else {
        fprintf(stderr, "Unknown test cmd\n");
    }

exit:
    if (fd) {
        close(fd);
    }

    return rc;
}
