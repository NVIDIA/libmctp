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

static pthread_t g_keepalive_thread;

extern char *mctp_sock_path;

extern int g_socket_fd;
extern int g_signal_fd;

extern void *mctp_spi_keepalive_event(void *arg);

int exec_spi_test(const mctp_cmdline_args_t *cmdline, mctp_ctrl_t *mctp_ctrl)
{
	int rc, fd;

	MCTP_CTRL_DEBUG("%s: Setting up SPI socket\n", __func__);
	mctp_sock_path = MCTP_SOCK_PATH_SPI;

	/* Open the user socket file-descriptor */
	rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_MESSAGE_TYPE_VDIANA,
				  MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("Failed to open mctp sock\n");

		close(g_signal_fd);
		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;
	/* Update global socket pointer */
	g_socket_fd = mctp_ctrl->sock;

	mctp_spi_test_cmd(mctp_ctrl, cmdline);

	return EXIT_SUCCESS;
}

void cleanup_daemon_spi(void)
{
	pthread_join(g_keepalive_thread, NULL);
}
