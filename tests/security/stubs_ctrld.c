/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/*
 * Minimal stub translation unit for the V16.1 / V17.1 security unit tests.
 *
 * mctp-discovery.c references a handful of symbols defined in heavier TUs
 * (mctp-ctrl.c, mctp-sdbus.c, dbus_log_event.c) that drag in sd-bus / socket
 * surface we do not want in a focused unit test. The two functions under test
 * (mctp_get_routing_table_get_response, mctp_get_endpoint_uuid_response) never
 * call any of these, so trivial stubs satisfy the link without changing the
 * tested code paths.
 */

#include <stdint.h>
#include <stddef.h>

/* Logging globals referenced by mctp-ctrl-log.h's inline logger.
 * command_line_mode is provided by Core-26.05 log.c. */
extern int command_line_mode;
uint8_t g_verbose_level = 0;

/* doLog() lives in dbus_log_event.c and pokes sd-bus; the no-medium-type path
 * of the routing handler can call it, but our entries use binding id 0
 * ("Unknown") which is filtered out *before* doLog, and our positive control
 * never reaches it. A no-op keeps the link clean and the test honest. */
void doLog(void *bus, char *arg0, char *arg1, char *severity, char *resolution)
{
	(void)bus;
	(void)arg0;
	(void)arg1;
	(void)severity;
	(void)resolution;
}

/* Defined in mctp-sdbus.c. Only reached on the "valid medium type" path; our
 * tests deliberately use an Unknown binding id so the real mapping is not
 * needed, but the symbol must resolve. Returning "Unknown" matches the id 0
 * entry in the positive control. */
const char *phy_transport_binding_to_string(uint8_t id)
{
	(void)id;
	return "Unknown";
}

/* Send/recv helpers from mctp-ctrl.c are only used by the request/discovery
 * driver functions, never by the two response parsers under test. Stub them
 * so mctp-discovery.c links. Return values are arbitrary failure codes. */
typedef uint8_t mctp_eid_t;

int mctp_client_with_binding_send(mctp_eid_t dest_eid, int mctp_fd,
				  const uint8_t *mctp_req_msg, size_t req_msg_len,
				  const void *bind_id, void *mctp_binding_info,
				  size_t mctp_binding_len)
{
	(void)dest_eid;
	(void)mctp_fd;
	(void)mctp_req_msg;
	(void)req_msg_len;
	(void)bind_id;
	(void)mctp_binding_info;
	(void)mctp_binding_len;
	return -7; /* MCTP_REQUESTER_SEND_FAIL */
}

int mctp_client_recv(mctp_eid_t eid, int mctp_fd, uint8_t **mctp_resp_msg,
		     size_t *resp_msg_len)
{
	(void)eid;
	(void)mctp_fd;
	(void)mctp_resp_msg;
	(void)resp_msg_len;
	return -8; /* MCTP_REQUESTER_RECV_FAIL */
}

uint16_t mctp_ctrl_get_target_bdf(const void *cmd)
{
	(void)cmd;
	return 0;
}
