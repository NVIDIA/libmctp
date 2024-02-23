/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>

#include "libmctp-astspi.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-astspi.h"
#include "libmctp-log.h"

#include "ctrld/mctp-ctrl.h"

#include "mctp-socket.h"
#include "mctp-ctrl-log.h"
#include "mctp-sdbus.h"
#include "dbus_log_event.h"

#include "vdm/nvidia/libmctp-vdm-cmds.h"
#include "vdm/nvidia/mctp-vdm-commands.h"

#define MCTP_NULL_ENDPOINT 0
#define MCTP_SPI_CMD_DELAY_USECS 10000
#define MCTP_SPI_HEARTBEAT_DELAY_SECS 30

#define MAX_HEARTBEAT_RETRY 10

extern int mctp_ctrl_running;

extern char *mctp_sock_path;

static int mctp_spi_set_endpoint_id(const mctp_cmdline_args_t *cmd)
{
	(void)cmd;
	return 0;
}

static int mctp_spi_get_endpoint_id(const mctp_cmdline_args_t *cmd)
{
	(void)cmd;
	return 0;
}

static int mctp_spi_get_endpoint_uuid(const mctp_cmdline_args_t *cmd)
{
	(void)cmd;
	return 0;
}

static int mctp_spi_get_version_support(const mctp_cmdline_args_t *cmd)
{
	(void)cmd;
	return 0;
}

static int mctp_spi_get_message_type(int sock, const mctp_cmdline_args_t *cmd)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	struct mctp_ctrl_cmd_get_msg_type_support req = { 0 };
	mctp_requester_rc_t rc = 0;

	(void)cmd;

	mctp_encode_ctrl_cmd_get_msg_type_support(&req);
	rc = mctp_client_send_recv(MCTP_NULL_ENDPOINT, sock,
				   MCTP_CTRL_HDR_MSG_TYPE, (uint8_t *)&req,
				   sizeof(req), &resp, &resp_len);

	if (rc != MCTP_REQUESTER_SUCCESS)
		fprintf(stderr, "%s: fail to recv [rc: %d] response\n",
			__func__, rc);

	free(resp);

	/* will implement it */
	return rc;
}

/* Nvidia IANA specific functions */
static int mctp_spi_set_endpoint_uuid(const mctp_cmdline_args_t *cmd)
{
	/* will implement it */
	(void)cmd;
	return 0;
}

static int64_t mctp_timediff_ms(struct timespec *tv1, struct timespec *tv2)
{
	int64_t diff_ms = 0;

	diff_ms = ((int64_t)tv2->tv_sec - tv1->tv_sec) * 1000;
	diff_ms += (tv2->tv_nsec - tv1->tv_nsec) / 1000000;

	return diff_ms;
}

static void mctp_ctrl_wait_and_discard(int socket, int signal_fd,
				       int timeout)
{
	int rc = -1;
	struct timespec target = { 0 };
	struct timespec curr = { 0 };
	struct pollfd pollfd[2] = { 0 };
	struct signalfd_siginfo si;
	ssize_t len = 0;

	rc = clock_gettime(CLOCK_MONOTONIC, &target);
	if (rc != 0) {
		warn("clock_gettime failed");
		return;
	}

	target.tv_sec += timeout / 1000;
	target.tv_nsec += (timeout % 1000000) * 1000000;

	pollfd[0].fd = socket;
	pollfd[0].events = POLLIN;
	pollfd[0].revents = 0;

	pollfd[1].fd = signal_fd;
	pollfd[1].events = POLLIN;
	pollfd[1].revents = 0;

	rc = clock_gettime(CLOCK_MONOTONIC, &curr);
	if (rc != 0) {
		warn("clock_gettime(2) failed");
		return;
	}

	timeout = (int)mctp_timediff_ms(&curr, &target);
	timeout = timeout > 0 ? timeout : 0;

	while (timeout > 0) {
		rc = poll(pollfd, 2, timeout);
		if (rc < 0) {
			warn("poll(2) failed");
			/* handle signal to exit blocking poll and exit loop immediately */
			if (errno == EINTR) {
				return;
			}
		}

		if (rc == 1 && pollfd[0].revents) {
			/* Discard message. */
			len = recv(pollfd[0].fd, NULL, 0, MSG_TRUNC);
			if (len < 0) {
				warn("recv(2) failed");
				return;
			}
		} else if (rc == 1 && pollfd[1].revents) {
			len = read(pollfd[1].fd, &si, sizeof(si));
			if (len < 0 || len != sizeof(si)) {
				MCTP_CTRL_ERR("[%s] Error read signal event: %s\n",
					      __func__, strerror(-len));
				return;
			}

			if (si.ssi_signo == SIGUSR2) {
				MCTP_CTRL_INFO(
					"[%s] The termination signal is captured by the keepalive thread\n",
					__func__);
				return;
			}
		}

		rc = clock_gettime(CLOCK_MONOTONIC, &curr);
		if (rc != 0) {
			warn("clock_gettime(2) failed");
			return;
		}

		timeout = (int)mctp_timediff_ms(&curr, &target);
		timeout = timeout > 0 ? timeout : 0;
	}
}

void *mctp_spi_keepalive_event(void *arg)
{
	int rc = 0;
	int signal_fd = -1;
	int socket_fd;
	sigset_t mask;
	int retries = MAX_HEARTBEAT_RETRY;
	mctp_ctrl_t *ctrl = (mctp_ctrl_t *)arg;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		MCTP_CTRL_ERR("[%s] Failed to signalmask\n", __func__);
		return 0;
	}

	/* Queue the signal and then do cleanup stuff */
	signal_fd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (signal_fd < 0) {
		MCTP_CTRL_ERR("[%s] Failed to signalfd\n", __func__);
		return 0;
	}

	/* Open the user socket file-descriptor */
	rc = mctp_usr_socket_init(&socket_fd, mctp_sock_path, MCTP_MESSAGE_TYPE_VDIANA,
    		MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("[%s] Failed to open socket, errno = %d\n", 
			  __func__, errno);
		return 0;
	}

	pthread_mutex_lock(&ctrl->worker_mtx);

	MCTP_CTRL_INFO("[%s] Send 'Boot complete v2' message\n", __func__);

	rc = boot_complete_v2(socket_fd, MCTP_NULL_ENDPOINT, 0, 0,
			      VERBOSE_DISABLE);
	if (rc != 0) {
		doLog(ctrl->bus, "ERoT SPI", "Boot Complete failed",
		      EVT_CRITICAL, "Reset the baseboard");

		MCTP_CTRL_ERR("[%s] Failed sending 'Boot complete v2' message\n",
			  __func__);

		goto exit_mctp_spi_keepalive_event;
	} else {
		MCTP_CTRL_INFO("[%s] Send 'Boot complete v2' message\n",
			  __func__);
	}

	/* Let the main thread continue to run and stop */
	ctrl->worker_is_ready = true;
	pthread_mutex_unlock(&ctrl->worker_mtx);
	pthread_cond_signal(&ctrl->worker_cv);

	/* Give some delay before sending next command */
	usleep(MCTP_SPI_CMD_DELAY_USECS);

	MCTP_CTRL_INFO("[%s] Send 'Enable Heartbeat' message\n", __func__);
	rc = set_heartbeat_enable(socket_fd, MCTP_NULL_ENDPOINT,
				  MCTP_SPI_HB_ENABLE_CMD, VERBOSE_DISABLE);
	if (rc != 0) {
		doLog(ctrl->bus, "ERoT SPI", "Enable HeartBeat failed",
		      EVT_CRITICAL, "Reset the baseboard");

		MCTP_CTRL_ERR("[%s] Failed MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);

		goto exit_mctp_spi_keepalive_event;
	}

	/* Give some delay before sending next command */
	usleep(MCTP_SPI_CMD_DELAY_USECS);

	while (mctp_ctrl_running) {
		MCTP_CTRL_DEBUG("[%s] Send 'Heartbeat' message\n", __func__);

		rc = heartbeat(socket_fd, MCTP_NULL_ENDPOINT, VERBOSE_DISABLE);
		if (rc != 0) {
			MCTP_CTRL_ERR("[%s] Heartbeat message failed.\n",
				      __func__);

			doLog(ctrl->bus, "ERoT SPI", "HeartBeat failed",
			      EVT_CRITICAL, "Reset the baseboard");
			if (retries == 0) {
				break;
			} else {
				retries--;
			}
		} else {
			retries = MAX_HEARTBEAT_RETRY;
		}
		
		/* Consume forwarding resposnses from other mctp client */
		mctp_ctrl_wait_and_discard(
			socket_fd, signal_fd, MCTP_SPI_HEARTBEAT_DELAY_SECS * 1000);
	}

exit_mctp_spi_keepalive_event:
	close(socket_fd);

	/* Terminate the main thread */
	mctp_ctrl_sdbus_stop();
	return NULL;
}

void mctp_spi_test_cmd(int socket, const mctp_cmdline_args_t *cmd)
{
	int rc = 0;
	mctp_spi_iana_vdm_ops_t ops = (mctp_spi_iana_vdm_ops_t)cmd->spi.vdm_ops;

	/* Check for Raw Read/write access */
	if (cmd->spi.cmd_mode) {
		MCTP_CTRL_INFO("%s: MCTP base command code: %d\n", __func__,
			       cmd->spi.cmd_mode);

		switch (cmd->spi.cmd_mode) {
		case MCTP_SPI_SET_ENDPOINT_ID:
			MCTP_CTRL_DEBUG("%s: MCTP_SPI_SET_ENDPOINT_ID\n",
					__func__);
			rc = mctp_spi_set_endpoint_id(cmd);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SPI_SET_ENDPOINT_ID\n",
					__func__);
			}

			break;

		case MCTP_SPI_GET_ENDPOINT_ID:
			MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_ID\n",
					__func__);
			rc = mctp_spi_get_endpoint_id(cmd);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SPI_GET_ENDPOINT_ID\n",
					__func__);
			}

			break;

		case MCTP_SPI_GET_ENDPOINT_UUID:
			MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_UUID\n",
					__func__);
			rc = mctp_spi_get_endpoint_uuid(cmd);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SPI_GET_ENDPOINT_UUID\n",
					__func__);
			}

			break;

		case MCTP_SPI_GET_VERSION:
			MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_VERSION\n", __func__);
			rc = mctp_spi_get_version_support(cmd);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SPI_GET_VERSION\n",
					__func__);
			}

			break;

		case MCTP_SPI_GET_MESSAGE_TYPE:
			MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_MESSAGE_TYPE\n",
					__func__);
			rc = mctp_spi_get_message_type(socket, cmd);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SPI_GET_MESSAGE_TYPE\n",
					__func__);
			}

			break;

		default:
			MCTP_CTRL_ERR("%s: Unsupported option\n", __func__);
			break;
		}

		return;
	}

	switch (ops) {
	case MCTP_SPI_SET_ENDPOINT_UUID:
		MCTP_CTRL_DEBUG("%s: MCTP_SPI_ENDPOINT_UUID\n", __func__);
		rc = mctp_spi_set_endpoint_uuid(cmd);
		if (rc != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed MCTP_SPI_ENDPOINT_UUID\n",
				      __func__);
		}

		break;

	case MCTP_SPI_BOOT_COMPLETE:

		MCTP_CTRL_DEBUG("%s: MCTP_SPI_BOOT_COMPLETE\n", __func__);
		rc = boot_complete_v1(socket, MCTP_NULL_ENDPOINT,
				      VERBOSE_EN);
		if (rc != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed MCTP_SPI_BOOT_COMPLETE\n",
				      __func__);
		}

		break;

	case MCTP_SPI_HEARTBEAT_SEND:
		MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_SEND\n", __func__);
		rc = heartbeat(socket, MCTP_NULL_ENDPOINT, VERBOSE_EN);
		if (rc != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_SEND\n",
				      __func__);
		}

		break;

	case MCTP_SPI_HEARTBEAT_ENABLE:
		MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
		rc = set_heartbeat_enable(socket, MCTP_NULL_ENDPOINT,
					  MCTP_SPI_HB_ENABLE_CMD, VERBOSE_EN);
		if (rc != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_ENABLE\n",
				      __func__);
		}

		break;

	case MCTP_SPI_QUERY_BOOT_STATUS:
		MCTP_CTRL_DEBUG("%s: MCTP_SPI_QUERY_BOOT_STATUS\n", __func__);
		rc = query_boot_status(socket, MCTP_NULL_ENDPOINT,
				       VERBOSE_EN, false);
		if (rc != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed MCTP_SPI_QUERY_BOOT_STATUS\n",
				      __func__);
		}

		break;

	default:
		MCTP_CTRL_DEBUG("%s: Invalid option\n", __func__);
		break;
	}

	return;
}
