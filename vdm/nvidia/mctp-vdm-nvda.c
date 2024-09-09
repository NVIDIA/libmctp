/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
#include <poll.h>
#include <linux/limits.h>

#include <systemd/sd-bus.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"

#include "mctp-vdm-nvda.h"
#include "mctp-vdm-commands.h"

#include "ctrld/mctp-ctrl.h"
#include "ctrld/mctp-sdbus.h"

#include "mctp-socket.h"

/* MCTP-VDM response binary file */
#define MCTP_VDM_RESP_OUTPUT_FILE "/var/mctp-vdm-output.bin"

/* MCTP control destination */
#define MCTP_CTRL_DEST "xyz.openbmc_project.MCTP.Control"

#define _cleanup_(f) __attribute__((cleanup(f)))

/* Global definitions */
uint8_t g_verbose_level = 0;

/* Global socket name */
char g_sock_name[32] = { 0 };

/* Is the endpoint enabled? */
int g_enabled = 0;

/* Global commandline options */
static const struct option options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "teid", required_argument, 0, 't' },
	{ "cmd", required_argument, 0, 'c' },
	{ "file", required_argument, 0, 'f' },
	{ "help", no_argument, 0, 'h' },
	{ "more", no_argument, 0, 'm' },
	{ "json", no_argument, 0, 'j' },
	{ 0 },
};

/* List of commands that support JSON output */
const char *commands_supported_json_flag[] = { "query_boot_status",
					       "background_copy_init",
					       "background_copy_disable",
					       "background_copy_enable",
					       "background_copy_disable_one",
					       "background_copy_enable_one",
					       "background_copy_query_status",
					       "background_copy_query_progress",
					       "background_copy_query_pending",
					       "in_band_disable",
					       "in_band_enable",
					       "in_band_query_status" };

#define VMD_CMD_ASSERT_GOTO(cond, label, fmt, ...)                             \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "at %s:%d " fmt, __func__, __LINE__,   \
				##__VA_ARGS__);                                \
			goto label;                                            \
		}                                                              \
	} while (0)

/* MCTP-VDM utility usage function */
static void usage(void)
{
	fprintf(stderr, "usage: mctp-vdm-util -t [eid] -c [cmd] [params]\n");
	fprintf(stderr, "-t/-teid: Endpoint EID\n");
	fprintf(stderr, "-c/-cmd: Command\n");
	fprintf(stderr, "Available commands:\n \
		selftest - need 4 bytes as the payload\n \
		boot_complete_v1\n \
		boot_complete_v2_slot_0, boot_complete_v2_slot_1\n \
		set_heartbeat_enable, set_heartbeat_disable\n \
		heartbeat\n \
		query_boot_status -m (more descriptive boot status - not required)\n \
		download_log -f filename(not required)\n \
		restart_notification\n \
		debug_token_install - need n bytes debug token\n \
		debug_token_erase\n \
		debug_token_query\n \
		program_certificate_chain - need 2048 bytes certificate\n \
		background_copy_init\n \
		background_copy_disable, background_copy_enable\n \
		background_copy_disable_one, background_copy_enable_one\n \
		background_copy_query_status, background_copy_query_progress\n \
		background_copy_query_pending\n \
		in_band_disable, in_band_enable\n \
		in_band_query_status\n \
		boot_ap\n \
		enable_boot_mode\n \
		disable_boot_mode\n \
		query_boot_mode\n \
		cak_install\n \
		cak_test\n \
		cak_lock\n \
		dot_disable\n \
		dot_token_install\n \
		query_force_grant_revoked_status\n \
		enable_force_grant_revoked, disable_force_grant_revoked\n \
		query_revoke_ap_otp_status\n \
		reset_erot\n \
		revoke_ap_otp\n \
		");
}

struct ctx {
	bool verbose;
};

struct ctx ctx = { 0 };

static int iterate_dbus_dict(sd_bus_message *m, const char *type, uint8_t eid,
			     int (*callback)(sd_bus_message *m, uint8_t eid))
{
	int rc = 0;
	int found = 0;

	/* Enter the nested structre in order to retrieve sd-bus message */
	while ((rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,
						    type)) > 0) {
		rc = callback(m, eid);
		/* We can't break since we have to interate all elements */
		if (rc == 1) {
			found = 1;
		}

		/* Exit the nested structure*/
		rc = sd_bus_message_exit_container(m);
		if (rc < 0)
			fprintf(stderr,
				"%s: sd_bus_message_exit_container rc = %d\n",
				__func__, rc);
	}
	return found;
}

static int cb_dbus_properity(sd_bus_message *m, uint8_t eid)
{
	int rc;
	size_t len;
	char type = 0;
	const char *contents;
	const char *name;
	const void *ptr;

	(void)eid;

	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &name);
	MCTP_ASSERT_RET(rc >= 0, -1, "sd_bus_message_read_basic fail rc=%d\n",
			rc);

	rc = sd_bus_message_peek_type(m, NULL, &contents);
	MCTP_ASSERT_RET(rc >= 0, -1, "sd_bus_message_peek_type fail rc=%d\n",
			rc);

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, contents);
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_enter_contain fail rc=%d\n", rc);

	rc = sd_bus_message_peek_type(m, &type, &contents);
	/* hit some error, skip msg and do exit container*/
	if (rc < 0) {
		fprintf(stderr, "sd_bus_message_peek_type fail rc=%d\n", rc);
	}

	/* Get socket name from Address properity */
	if (type == SD_BUS_TYPE_ARRAY && strcmp(name, "Address") == 0) {
		rc = sd_bus_message_read_array(m, 'y', &ptr, &len);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"sd_bus_message_read_array fail rc=%d\n", rc);

		memcpy(g_sock_name, ptr, len);
	} else if (type == SD_BUS_TYPE_BOOLEAN &&
		   strcmp(name, "Enabled") == 0) {
		rc = sd_bus_message_read_basic(m, 'b', &g_enabled);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"sd_bus_message_read_basic fail rc=%d\n", rc);
	} else {
		rc = sd_bus_message_skip(m, NULL);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"%s: sd_bus_message_skip fail rc=%d\n",
				__func__, rc);
	}

	rc = sd_bus_message_exit_container(m);
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_exit_container fail rc=%d\n", rc);
	return 0;
}

static int cb_dbus_interfaces(sd_bus_message *m, uint8_t eid)
{
	int rc = 0;
	const char *iface;

	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &iface);
	MCTP_ASSERT_RET(rc >= 0, -1, "sd_bus_message_read_basic fail rc= %d\n",
			rc);

	if (strcmp(iface, "xyz.openbmc_project.Common.UnixSocket") != 0 &&
	    strcmp(iface, "xyz.openbmc_project.Object.Enable") != 0) {
		rc = sd_bus_message_skip(m, NULL);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"%s: sd_bus_message_skip fail rc=%d\n",
				__func__, rc);
		return 0;
	}

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_enter_contain fail rc=%d\n", rc);

	/* Traverse D-Bus properities */
	rc = iterate_dbus_dict(m, "sv", eid, cb_dbus_properity);
	if (rc < 0)
		fprintf(stderr, "cb_dbus_properity fail rc=%d\n", rc);

	rc = sd_bus_message_exit_container(m);
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_exit_container fail rc=%d\n", rc);

	return 0;
}

static int cb_dbus_paths(sd_bus_message *m, uint8_t eid)
{
	int rc;
	const char *obj_path;
	char path[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE] = { 0 };

	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &obj_path);
	MCTP_ASSERT_RET(rc >= 0, -1, "sd_bus_message_read_basic fail rc=%d\n",
			rc);

	/* Compare object paths to match the one by eid */
	snprintf(path, sizeof(path), "/xyz/openbmc_project/mctp/0/%d", eid);
	if (strcmp(path, obj_path) != 0) {
		rc = sd_bus_message_skip(m, NULL);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"%s: sd_bus_message_skip fail rc=%d\n",
				__func__, rc);
		return 0;
	}

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sa{sv}}");
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_enter_container fail rc=%d\n", rc);

	/* Traverse all interfaces per object */
	rc = iterate_dbus_dict(m, "sa{sv}", eid, cb_dbus_interfaces);
	if (rc < 0)
		fprintf(stderr, "cb_dbus_interfaces fail rc=%d\n", rc);

	rc = sd_bus_message_exit_container(m);
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_exit_container fail rc=%d\n", rc);
	return 1;
}

static int sock_name_helper(sd_bus *bus, const char *service, uint8_t eid)
{
	int rc;
	int found = 0;
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
	_cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;

	rc = sd_bus_call_method(bus, service, "/xyz/openbmc_project/mctp",
				"org.freedesktop.DBus.ObjectManager",
				"GetManagedObjects", &err, &m, NULL);
	if (rc < 0) {
		/* Return the negative value to switch another interface */
		return -1;
	}

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY,
					    "{oa{sa{sv}}}");
	MCTP_ASSERT_RET(rc >= 0, -1,
			"%s: sd_bus_message_enter_container fail rc= %d\n",
			service, rc);

	/* traverse object paths */
	found = iterate_dbus_dict(m, "oa{sa{sv}}", eid, cb_dbus_paths);
	if (found < 0) {
		fprintf(stderr, "sd_bus_message_exit_container fail rc=%d\n",
			found);
	}

	rc = sd_bus_message_exit_container(m);
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_exit_container fail rc=%d\n", rc);
	return found;
}

static int check_hex_number(char *s)
{
	char ch = *s;
	int len = 0;

	while ((ch = *s++) != 0) {
		if (len == 2 || isxdigit(ch) == 0) {
			return -1;
		}
		len++;
	}
	return 0;
}

/*
 * Function to check if a command supports JSON output
 */
static bool is_json_supported(const char *command)
{
	int num_supported_commands = sizeof(commands_supported_json_flag) /
				     sizeof(commands_supported_json_flag[0]);

	for (int i = 0; i < num_supported_commands; ++i) {
		if (strcmp(command, commands_supported_json_flag[i]) == 0) {
			return true;
		}
	}
	return false;
}

/*
 * Function to get destination by EID
 */
int get_destination_by_path(sd_bus *bus, const uint8_t eid, char *service_name)
{
	int rc;
	const char *name;
	char path[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE] = { 0 };

	_cleanup_(sd_bus_message_unrefp) sd_bus_message *msg = NULL;
	_cleanup_(sd_bus_error_free) sd_bus_error err = SD_BUS_ERROR_NULL;

	snprintf(path, sizeof(path), "/xyz/openbmc_project/mctp/0/%d", eid);

	rc = sd_bus_call_method(bus, "xyz.openbmc_project.ObjectMapper",
				"/xyz/openbmc_project/object_mapper",
				"xyz.openbmc_project.ObjectMapper", "GetObject",
				&err, &msg, "sas", path, 0, NULL);
	if (rc < 0) {
		printf("sd_bus_call_method failed: %s, %s\n", strerror(-rc),
		       err.message);
		return -1;
	}

	rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "{sas}");
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_enter_container fail: %s\n",
			strerror(-rc));

	for (;;) {
		rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_DICT_ENTRY,
						    "sas");
		if (rc == 0) {
			/* end ot array */
			break;
		}
		MCTP_ASSERT_RET(rc >= 0, -1,
				"sd_bus_message_enter_container fail: %s\n",
				strerror(-rc));

		/* get destionation */
		rc = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &name);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"sd_bus_message_read_basic fail: %s\n",
				strerror(-rc));

		/* check if it is a CTP control destination */
		if (strstr(name, MCTP_CTRL_DEST)) {
			strncpy(service_name, name, strlen(name));
			return 0;
		}

		/* skip array as we only need to the destination */
		rc = sd_bus_message_skip(msg, NULL);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"%s: sd_bus_message_skip fail rc=%d\n",
				__func__, rc);

		rc = sd_bus_message_exit_container(msg);
		MCTP_ASSERT_RET(rc >= 0, -1,
				"sd_bus_message_exit_container fail: %s\n",
				strerror(-rc));
	}

	rc = sd_bus_message_exit_container(msg);
	MCTP_ASSERT_RET(rc >= 0, -1, "sd_bus_message_exit_container fail: %s\n",
			strerror(-rc));

	return 0;
}

/*
 * Main function
 */
int main(int argc, char *const *argv)
{
	int rc = -1;
	int i = 0, len = 0;
	int fd = 0;
	int found = 0;
	char item[MCTP_VDM_COMMAND_NAME_SIZE] = { '\0' };
	char file[PATH_MAX] = { 0 };
	char service_name[PATH_MAX] = { 0 };
	unsigned int max_len = 0;
	uint8_t teid = 0;
	bool more = false;
	bool json_output = false;
	bool print_test_command = false;
	bool print_teid = false;
	uint8_t payload_required = 0;
	uint8_t payload[MCTP_CERTIFICATE_CHAIN_SIZE] = { '\0' };
	sd_bus *bus = NULL;

	for (;;) {
		rc = getopt_long(argc, argv, "jmvt:c:f:h", options, NULL);
		if (rc == -1)
			break;

		switch (rc) {
		case 'j':
			json_output = true;
			break;
		case 'm':
			more = true;
			break;
		case 'v':
			ctx.verbose = true;
			break;
		case 't':
			teid = (uint8_t)strtol(optarg, NULL, 10);
			print_teid = true;
			break;
		case 'c':
			snprintf(item, sizeof(item), "%s", optarg);
			print_test_command = true;
			payload_required = (strcmp(item, "selftest") == 0);
			payload_required |=
				(strcmp(item, "debug_token_install") == 0);
			payload_required |=
				(strcmp(item, "program_certificate_chain") ==
				 0);
			payload_required |= (strcmp(item, "cak_install") == 0);
			payload_required |= (strcmp(item, "cak_lock") == 0);
			payload_required |= (strcmp(item, "dot_disable") == 0);
			payload_required |=
				(strcmp(item, "dot_token_install") == 0);

			if (strcmp(item, "selftest") == 0)
				max_len = 8;
			else if (strcmp(item, "debug_token_install") == 0)
				max_len = MCTP_DEBUG_TOKEN_SIZE;
			else if (strcmp(item, "program_certificate_chain") == 0)
				max_len = MCTP_CERTIFICATE_CHAIN_SIZE;
			else if (strcmp(item, "cak_install") == 0)
				max_len = MCTP_CAK_COMMAND_PAYLOAD_LEN;
			else if (strcmp(item, "cak_lock") == 0)
				max_len = MCTP_ECDSA_P_384_DOT_ENABLE_KEY;
			else if (strcmp(item, "dot_disable") == 0)
				max_len = MCTP_ECDSA_P_384_DOT_ENABLE_KEY;
			else if (strcmp(item, "dot_token_install") == 0)
				max_len = MCTP_DOT_TOKEN_SIZE;
			else
				max_len = 0;
			break;
		case 'f':
			snprintf(file, sizeof(file), "%s", optarg);
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Invalid argument\n");
			return EXIT_FAILURE;
		}
	}

	if (json_output && !is_json_supported(item)) {
		printf("The following command %s does not expect argument -j\n",
		       item);
		return EXIT_FAILURE;
	}

	if (print_teid && !json_output) {
		printf("teid = %d\n", teid);
	}

	if (print_test_command && !json_output) {
		printf("Test command = %s\n", item);
	}

	mctp_set_log_stdio(ctx.verbose ? MCTP_LOG_DEBUG : MCTP_LOG_WARNING);

	/* need more data as the payload passing to selftest commands */
	if (payload_required && optind == argc) {
		fprintf(stderr,
			"Error! the command needs n-bytes payload.\n\n");
		usage();
		return EXIT_FAILURE;
	} else if (payload_required == 0 && optind != argc) {
		fprintf(stderr, "Error! we don't need the paylod.\n\n");
		usage();
		return EXIT_FAILURE;
	}
	/* For selftest command, we may need more data as the payload
	* for which items to be tested.
	*/
	for (i = optind, len = 0; i < argc && (unsigned int)len < max_len;
	     i++, len++) {
		rc = check_hex_number(&argv[i][0]);
		if (rc == -1) {
			fprintf(stderr, "Error! we need %u-bytes data.\n\n",
				max_len);
			usage();
			return EXIT_FAILURE;
		}

		payload[len] = strtol(argv[i], NULL, 16);
	}

	rc = sd_bus_default(&bus);
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "sd_bus_default failed\n");

	rc = get_destination_by_path(bus, teid, service_name);
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "get destination failed\n");

	found = sock_name_helper(bus, service_name, teid);

	/* free D-Bus*/
	sd_bus_unref(bus);

	MCTP_ASSERT_RET(found == 1, EXIT_FAILURE, "can't find the interface\n");

	MCTP_ASSERT_RET(g_enabled == 1, EXIT_FAILURE,
			"Endpoint is in disabled state\n");

	/* Establish the socket connection */
	rc = mctp_usr_socket_init(&fd, g_sock_name, MCTP_MESSAGE_TYPE_VDIANA,
				  MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, EXIT_FAILURE,
			"Failed to open mctp socket\n");

	if (!strcmp(item, "selftest")) {
		rc = selftest(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to do selftest: %d\n",
				    rc);
	} else if (!strcmp(item, "boot_complete_v1")) {
		rc = boot_complete_v1(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to do boot complete: %d\n", rc);
	} else if (!strcmp(item, "boot_complete_v2_slot_0")) {
		rc = boot_complete_v2(fd, teid, MCTP_VDM_BOOT_COMPLETE_VALID,
				      MCTP_VDM_BOOT_COMPLETE_SLOT0, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to do boot complete v2: %d\n", rc);
	} else if (!strcmp(item, "boot_complete_v2_slot_1")) {
		rc = boot_complete_v2(fd, teid, MCTP_VDM_BOOT_COMPLETE_VALID,
				      MCTP_VDM_BOOT_COMPLETE_SLOT1, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to do boot complete v2: %d\n", rc);
	} else if (!strcmp(item, "set_heartbeat_enable")) {
		rc = set_heartbeat_enable(fd, teid, MCTP_VDM_HEARTBEAT_ENABLE,
					  VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable heartbeat: %d\n", rc);
	} else if (!strcmp(item, "set_heartbeat_disable")) {
		rc = set_heartbeat_enable(fd, teid, MCTP_VDM_HEARTBEAT_DISABLE,
					  VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable heartbeat: %d\n", rc);
	} else if (!strcmp(item, "heartbeat")) {
		rc = heartbeat(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to send heartbeat event: %d\n", rc);
	} else if (!strcmp(item, "restart_notification")) {
		rc = restart_notification(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to send restart notification: %d\n",
				    rc);
	} else if (!strcmp(item, "query_boot_status")) {
		if (json_output) {
			rc = query_boot_status_json(fd, teid);
		} else {
			rc = query_boot_status(fd, teid, VERBOSE_EN, more);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query boot status: %d\n", rc);
	} else if (!strcmp(item, "download_log")) {
		/* no filename is specified and go to the default file name */
		if (file[0] == 0) {
			snprintf(file, sizeof(file), MCTP_VDM_RESP_OUTPUT_FILE);
		}
		rc = download_log(fd, teid, file, ctx.verbose);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to download log: %d\n",
				    rc);
	} else if (!strcmp(item, "background_copy_disable")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_DISABLE);
		} else {
			rc = background_copy(fd, teid,
					     MCTP_VDM_BACKGROUND_COPY_DISABLE,
					     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_enable")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_ENABLE);
		} else {
			rc = background_copy(fd, teid,
					     MCTP_VDM_BACKGROUND_COPY_ENABLE,
					     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_disable_one")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid,
				MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT);
		} else {
			rc = background_copy(
				fd, teid,
				MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT,
				VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_enable_one")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid,
				MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT);
		} else {
			rc = background_copy(
				fd, teid,
				MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT,
				VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_init")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_INIT);
		} else {
			rc = background_copy(fd, teid,
					     MCTP_VDM_BACKGROUND_COPY_INIT,
					     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to init bg: %d\n", rc);
	} else if (!strcmp(item, "background_copy_query_status")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid,
				MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS);
		} else {
			rc = background_copy(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS,
				VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to query bg: %d\n",
				    rc);
	} else if (!strcmp(item, "background_copy_query_progress")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_PROGRESS);
		} else {
			rc = background_copy(fd, teid,
					     MCTP_VDM_BACKGROUND_COPY_PROGRESS,
					     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query prog bg: %d\n", rc);
	} else if (!strcmp(item, "background_copy_query_pending")) {
		if (json_output) {
			rc = background_copy_json(
				fd, teid, MCTP_VDM_BACKGROUND_COPY_PENDING);
		} else {
			rc = background_copy(fd, teid,
					     MCTP_VDM_BACKGROUND_COPY_PENDING,
					     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query pending bg: %d\n", rc);
	} else if (!strcmp(item, "debug_token_install")) {
		rc = debug_token_install(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to install debug token: %d\n", rc);
	} else if (!strcmp(item, "debug_token_erase")) {
		rc = debug_token_erase(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to erase debug token: %d\n", rc);
	} else if (!strcmp(item, "debug_token_query")) {
		rc = debug_token_query(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to query debug token: %d\n", rc);
	} else if (!strcmp(item, "debug_token_query_v2")) {
		rc = debug_token_query_v2(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to query debug token: %d\n", rc);
	} else if (!strcmp(item, "program_certificate_chain")) {
		rc = certificate_install(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to program certificate chain: %d\n",
				    rc);
	} else if (!strcmp(item, "in_band_disable")) {
		if (json_output) {
			rc = in_band_json(fd, teid, MCTP_VDM_IN_BAND_DISABLE);
		} else {
			rc = in_band(fd, teid, MCTP_VDM_IN_BAND_DISABLE,
				     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable in-band: %d\n", rc);
	} else if (!strcmp(item, "in_band_enable")) {
		if (json_output) {
			rc = in_band_json(fd, teid, MCTP_VDM_IN_BAND_ENABLE);
		} else {
			rc = in_band(fd, teid, MCTP_VDM_IN_BAND_ENABLE,
				     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable in-band: %d\n", rc);
	} else if (!strcmp(item, "in_band_query_status")) {
		if (json_output) {
			rc = in_band_json(fd, teid,
					  MCTP_VDM_IN_BAND_QUERY_STATUS);
		} else {
			rc = in_band(fd, teid, MCTP_VDM_IN_BAND_QUERY_STATUS,
				     VERBOSE_EN);
		}
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query in-band: %d\n", rc);
	} else if (!strcmp(item, "boot_ap")) {
		rc = boot_ap(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to boot ap: %d\n", rc);
	} else if (!strcmp(item, "enable_boot_mode")) {
		rc = set_query_boot_mode(fd, teid, MCTP_VDM_BOOTMODE_ENABLE,
					 VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable_boot_mode: %d\n", rc);
	} else if (!strcmp(item, "disable_boot_mode")) {
		rc = set_query_boot_mode(fd, teid, MCTP_VDM_BOOTMODE_DISABLE,
					 VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable_boot_mode: %d\n", rc);
	} else if (!strcmp(item, "query_boot_mode")) {
		rc = set_query_boot_mode(fd, teid, MCTP_VDM_BOOTMODE_QUERY,
					 VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to set_query_boot_mode: %d\n", rc);
	} else if (!strcmp(item, "in_band_query_status")) {
		rc = in_band(fd, teid, MCTP_VDM_IN_BAND_QUERY_STATUS,
			     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query in-band: %d\n", rc);
	} else if (!strcmp(item, "cak_install")) {
		rc = cak_install(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query cak_install: %d\n", rc);
	} else if (!strcmp(item, "cak_lock")) {
		rc = cak_lock(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to cak lock: %d\n",
				    rc);
	} else if (!strcmp(item, "cak_test")) {
		rc = cak_test(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to cak_test: %d\n",
				    rc);
	} else if (!strcmp(item, "dot_disable")) {
		rc = dot_disable(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to dot_disable: %d\n",
				    rc);
	} else if (!strcmp(item, "dot_token_install")) {
		rc = dot_token_install(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to dot_token_install: %d\n", rc);
	} else if (!strcmp(item, "query_force_grant_revoked_status")) {
		rc = force_grant_revoke(
			fd, teid, MCTP_VDM_QUERY_FORCE_GRANT_REVOKED_STATUS,
			VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query grant revoked status %d\n",
				    rc);
	} else if (!strcmp(item, "enable_force_grant_revoked")) {
		rc = force_grant_revoke(fd, teid,
					MCTP_VDM_ENABLE_FORCE_GRANT_REVOKED,
					VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to force enable grant revoked %d\n",
				    rc);
	} else if (!strcmp(item, "disable_force_grant_revoked")) {
		rc = force_grant_revoke(fd, teid,
					MCTP_VDM_DISABLE_FORCE_GRANT_REVOKED,
					VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to force disable grant revoked %d\n",
				    rc);
	} else if (!strcmp(item, "reset_erot")) {
		rc = reset_erot(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to reset EROT %d\n",
				    rc);
	} else if (!strcmp(item, "revoke_ap_otp")) {
		rc = revoke_ap_otp(fd, teid, MCTP_VDM_REVOKE_AP_OTP,
				   VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to revoke AP otp %d\n",
				    rc);
	} else if (!strcmp(item, "query_revoke_ap_otp_status")) {
		rc = revoke_ap_otp(fd, teid, MCTP_VDM_REVOKE_QUERY_STATUS,
				   VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query revoke AP otp status %d\n",
				    rc);
	} else {
		fprintf(stderr, "Unknown test cmd\n");
	}

exit:
	if (fd) {
		close(fd);
	}

	return rc;
}
