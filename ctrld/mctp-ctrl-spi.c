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
#include <pthread.h>
#include <stdbool.h>

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"
#include "mctp-ctrl-log.h"
#include "mctp-ctrl.h"
#include "mctp-sdbus.h"
#include "mctp-socket.h"
#include "mctp-ctrl-spi.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-spi-cmds.h"
#include "mctp-discovery.h"

extern char *mctp_sock_path;

extern int g_socket_fd;

int exec_spi_test(const mctp_cmdline_args_t *cmdline, mctp_ctrl_t *mctp_ctrl)
{
	int rc, fd;

	MCTP_CTRL_DEBUG("%s: Setting up SPI socket\n", __func__);
	mctp_sock_path = MCTP_SOCK_PATH_SPI;

	/* Open the user socket file-descriptor */
	rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_MESSAGE_TYPE_VDIANA,
				  MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("[exec_spi_test] Failed to open mctp sock\n");

		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;
	/* Update global socket pointer */
	g_socket_fd = mctp_ctrl->sock;

	mctp_spi_test_cmd(fd, cmdline);

	return EXIT_SUCCESS;
}

