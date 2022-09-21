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

#include <systemd/sd-bus.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "mctp-vdm-nvda.h"
#include "mctp-vdm-commands.h"

#include "ctrld/mctp-ctrl.h"
#include "ctrld/mctp-sdbus.h"

/* MCTP-VDM response binary file */
#define MCTP_VDM_RESP_OUTPUT_FILE "/var/mctp-vdm-output.bin"

#define _cleanup_(f) __attribute__((cleanup(f)))

/* Global definitions */
uint8_t g_verbose_level = 0;

/* Global socket name */
uint8_t g_sock_name[32] = { 0 };

/* Global commandline options */
static const struct option options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "teid", required_argument, 0, 't' },
	{ "cmd", required_argument, 0, 'c' },
	{ "help", no_argument, 0, 'h' },
	{ 0 },
};

static char *dbus_services[] = {
	"xyz.openbmc_project.MCTP.Control.PCIe",
	"xyz.openbmc_project.MCTP.Control.SPI",
};

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
		query_boot_status\n \
		download_log\n \
		restart_notification\n \
		debug_token_install - need 256 bytes debug token\n \
		debug_token_erase\n \
		debug_token_query\n \
		program_certificate_chain - need 2048 bytes certificate\n \
		background_copy_init\n \
		background_copy_disable, background_copy_enable\n \
		background_copy_disable_one, background_copy_enable_one\n \
		background_copy_query_status, background_copy_query_progress\n");
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

	/* Enter the nested structre in order to retrieve sdbus message */
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
				__FUNCTION__, rc);
	}
	return found;
}

static int cb_dbus_properity(sd_bus_message *m, uint8_t eid)
{
	int rc;
	int len;
	char type = 0;
	const char *contents;
	const char *name;
	const char *value;
	const void *ptr;

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
	} else {
		sd_bus_message_skip(m, NULL);
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

	if (strcmp(iface, "xyz.openbmc_project.Common.UnixSocket") != 0) {
		sd_bus_message_skip(m, NULL);
		return 0;
	}

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	MCTP_ASSERT_RET(rc >= 0, -1,
			"sd_bus_message_enter_contain fail rc=%d\n", rc);

	/* Traverse dbus properities */
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
		sd_bus_message_skip(m, NULL);
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
 * Main function
 */
int main(int argc, char *const *argv)
{
	int rc = -1;
	int i = 0, len = 0;
	int fd = 0;
	int found = 0;
	char item[MCTP_VDM_COMMAND_NAME_SIZE] = { '\0' };
	char intf[16] = { 0 };
	char path[32] = { 0 };
	unsigned int max_len = 0;
	uint8_t teid = 0;
	uint8_t payload_required = 0;
	uint8_t payload[MCTP_CERTIFICATE_CHAIN_SIZE] = { '\0' };
	sd_bus *bus = NULL;

	for (;;) {
		rc = getopt_long(argc, argv, "vt:c:h", options, NULL);
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
			snprintf(item, sizeof(item), "%s", optarg);
			printf("Test command = %s\n", item);
			payload_required = (strcmp(item, "selftest") == 0);
			payload_required |=
				(strcmp(item, "debug_token_install") == 0);
			payload_required |=
				(strcmp(item, "program_certificate_chain") ==
				 0);
			if (strcmp(item, "selftest") == 0)
				max_len = 8;
			else if (strcmp(item, "debug_token_install") == 0)
				max_len = MCTP_DEBUG_TOKEN_SIZE;
			else if (strcmp(item, "program_certificate_chain") == 0)
				max_len = MCTP_CERTIFICATE_CHAIN_SIZE;
			else
				max_len = 0;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Invalid argument\n");
			return EXIT_FAILURE;
		}
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
	for (i = optind, len = 0; i < argc && len < max_len; i++, len++) {
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

	found = 0;
	for (i = 0; i < sizeof(dbus_services) / sizeof(dbus_services[0]); i++) {
		found = sock_name_helper(bus, dbus_services[i], teid);
		if (found == 1)
			break;
	}

	/* free dbus*/
	sd_bus_unref(bus);

	MCTP_ASSERT_RET(found == 1, EXIT_FAILURE, "can't find the interface\n");

	/* Establish the socket connection */
	rc = mctp_usr_socket_init(&fd, g_sock_name, MCTP_MESSAGE_TYPE_VDIANA);
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
		rc = query_boot_status(fd, teid, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query boot status: %d\n", rc);
	} else if (!strcmp(item, "download_log")) {
		rc = download_log(fd, teid, MCTP_VDM_RESP_OUTPUT_FILE,
				  ctx.verbose);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to download log: %d\n",
				    rc);
	} else if (!strcmp(item, "background_copy_disable")) {
		rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_DISABLE,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_enable")) {
		rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_ENABLE,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_disable_one")) {
		rc = background_copy(fd, teid,
				     MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to disable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_enable_one")) {
		rc = background_copy(fd, teid,
				     MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to enable one bg copy: %d\n", rc);
	} else if (!strcmp(item, "background_copy_init")) {
		rc = background_copy(fd, teid, MCTP_VDM_BACKGROUND_COPY_INIT,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to init bg: %d\n", rc);
	} else if (!strcmp(item, "background_copy_query_status")) {
		rc = background_copy(fd, teid,
				     MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit, "fail to query bg: %d\n",
				    rc);
	} else if (!strcmp(item, "background_copy_query_progress")) {
		rc = background_copy(fd, teid,
				     MCTP_VDM_BACKGROUND_COPY_PROGRESS,
				     VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "fail to query prog bg: %d\n", rc);
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
	} else if (!strcmp(item, "program_certificate_chain")) {
		rc = certificate_install(fd, teid, payload, len, VERBOSE_EN);
		VMD_CMD_ASSERT_GOTO(rc == 0, exit,
				    "failed to program certificate chain: %d\n",
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
