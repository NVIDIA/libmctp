/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>

#ifdef MOCKUP_ENDPOINT
#include <time.h>
#endif

#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/aspeed-mctp.h>

#include "container_of.h"
#include "libmctp-alloc.h"
#include "libmctp-astpcie.h"
#include "libmctp-log.h"
#include "astpcie.h"

#undef pr_fmt
#define pr_fmt(fmt) "astpcie: " fmt

#define ASTPCIE_MIN_PACKET_SIZE 16

/*
 * PCIe header template in "network format" - Big Endian
 */
static const struct mctp_pcie_hdr mctp_pcie_hdr_template_be = {
	.fmt_type = MSG_4DW_HDR,
	.mbz_attr_length = MCTP_PCIE_VDM_ATTR,
	.code = MSG_CODE_VDM_TYPE_1,
	.vendor = VENDOR_ID_DMTF_VDM
};

static struct mctp_astpcie_pkt_private g_mctp_pkt_prv_default = {
	.routing = PCIE_ROUTE_BY_ID,
	.remote_id = 0
};

int mctp_astpcie_get_eid_info_ioctl(struct mctp_binding_astpcie *astpcie,
				    void *eid_info, uint16_t count,
				    uint8_t start_eid)
{
	struct aspeed_mctp_get_eid_info get_eid_info;
	int rc;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		return 0;
	}
#endif

	get_eid_info.count = count;
	get_eid_info.start_eid = start_eid;
	get_eid_info.ptr = (uint64_t)(uintptr_t)eid_info;

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_EID_INFO, &get_eid_info);
	if (!rc) {
		uintptr_t ptr = (uintptr_t)get_eid_info.ptr;
		memcpy(eid_info, (void *)ptr, get_eid_info.count);
	} else {
		mctp_prerr(
			"%s: Failed to get EID info (ioctl failed), error: %s",
			__func__, strerror(errno));
	}

	return rc;
}

int mctp_astpcie_set_eid_info_ioctl(struct mctp_binding_astpcie *astpcie,
				    void *eid_info, uint16_t count)
{
	struct aspeed_mctp_set_eid_info set_eid_info;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		return 0;
	}
#endif

	set_eid_info.count = count;
	set_eid_info.ptr = (uint64_t)(uintptr_t)eid_info;

	return ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_SET_EID_INFO,
		     &set_eid_info);
}

static int mctp_astpcie_get_bdf_ioctl(struct mctp_binding_astpcie *astpcie)
{
	struct aspeed_mctp_get_bdf bdf;
	int rc;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		astpcie->bdf = 0x0001;
		return 0;
	}
#endif

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_BDF, &bdf);
	if (!rc) {
		astpcie->bdf = bdf.bdf;
	} else {
		mctp_prerr(
			"%s: Failed to get EID info (ioctl failed), error: %s",
			__func__, strerror(errno));
	}
	/* Force set Requester ID */
	astpcie->bdf = 0x0001;

	return rc;
}

int mctp_astpcie_get_bdf(struct mctp_binding_astpcie *astpcie, uint16_t *bdf)
{
	int rc;

	rc = mctp_astpcie_get_bdf_ioctl(astpcie);
	if (!rc)
		*bdf = astpcie->bdf;

	return rc;
}

static int
mctp_astpcie_get_medium_id_ioctl(struct mctp_binding_astpcie *astpcie)
{
	struct aspeed_mctp_get_medium_id get_medium_id;
	int rc;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		astpcie->medium_id = 0;
		return 0;
	}
#endif

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_MEDIUM_ID,
		   &get_medium_id);
	if (!rc)
		astpcie->medium_id = get_medium_id.medium_id;

	return rc;
}

int mctp_astpcie_register_default_handler(struct mctp_binding_astpcie *astpcie)
{
#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		return 0;
	}
#endif

	return ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER);
}

uint8_t mctp_astpcie_get_medium_id(struct mctp_binding_astpcie *astpcie)
{
	return astpcie->medium_id;
}

static int mctp_astpcie_open(struct mctp_binding_astpcie *astpcie)
{
	int fd = open(AST_DRV_FILE, O_RDWR);

	if (fd < 0) {
		mctp_prerr("Cannot open: %s, errno = %d", AST_DRV_FILE, errno);

		return fd;
	}

	astpcie->fd = fd;
	return 0;
}

static void mctp_astpcie_close(struct mctp_binding_astpcie *astpcie)
{
#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		return;
	}
#endif
	close(astpcie->fd);
	astpcie->fd = -1;
}

/*
 * Start function. Opens driver, read bdf and medium_id
 */
static int mctp_astpcie_start(struct mctp_binding *b)
{
	struct mctp_binding_astpcie *astpcie = binding_to_astpcie(b);
	int rc;

	assert(astpcie);

	rc = mctp_astpcie_open(astpcie);

#ifdef MOCKUP_ENDPOINT
	if (rc && errno == ENOENT) {
		mctp_prerr("Unable to open %s is running in the debug mode",
			   AST_DRV_FILE);
		return 0;
	}
#endif

	if (rc)
		return -errno;

	rc = mctp_astpcie_get_bdf_ioctl(astpcie);
	if (rc) {
		mctp_prerr("%s: Failed to get BDF from ioctl (rc=%d)", __func__,
			   rc);
		goto out_close;
	}
	rc = mctp_astpcie_get_medium_id_ioctl(astpcie);
	if (rc) {
		mctp_prerr("%s: Failed to get Medium ID from ioctl (rc=%d)",
			   __func__, rc);
		goto out_close;
	}
	mctp_binding_set_tx_enabled(b, true);

	return 0;

out_close:
	mctp_astpcie_close(astpcie);
	return -errno;
}

static uint8_t mctp_astpcie_tx_get_pad_len(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) - sz;
}

static uint16_t mctp_astpcie_tx_get_payload_size_dw(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) / sizeof(uint32_t) - MCTP_HDR_SIZE_DW;
}

/*
 * Tx function which writes single packet to device driver
 */
static int mctp_astpcie_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_astpcie_pkt_private *pkt_prv =
		(struct mctp_astpcie_pkt_private *)pkt->msg_binding_private;
	struct mctp_binding_astpcie *astpcie = binding_to_astpcie(b);
	struct mctp_pcie_hdr hdr[PCIE_VDM_HDR_SIZE];
	uint16_t payload_len_dw = mctp_astpcie_tx_get_payload_size_dw(pkt);
	uint8_t pad = mctp_astpcie_tx_get_pad_len(pkt);
	uint8_t *pcie_mctp_hdr_data = pkt->data;
	ssize_t write_len, len;

	/* Do a sanity check before proceeding */
	if (payload_len_dw > 16) {
		mctp_prdebug("Invalid payload len: %d, pad: %d", payload_len_dw,
			     pad);
		return -1;
	}

	/* Update the Global BDF from pvt binding */
	if ((pkt_prv) && (g_mctp_pkt_prv_default.remote_id == 0))
		g_mctp_pkt_prv_default.remote_id = pkt_prv->remote_id;

	/* Copy PCIe header template */
	memcpy(hdr, &mctp_pcie_hdr_template_be, sizeof(*hdr));

	/* Update the private data if null */
	if (!pkt_prv) {
		pkt_prv = &g_mctp_pkt_prv_default;
	}

	PCIE_SET_ROUTING(hdr, pkt_prv->routing);
	PCIE_SET_DATA_LEN(hdr, payload_len_dw);
	PCIE_SET_REQ_ID(hdr, astpcie->bdf);
	PCIE_SET_TARGET_ID(hdr, pkt_prv->remote_id);
	PCIE_SET_PAD_LEN(hdr, pad);

	len = (payload_len_dw * sizeof(uint32_t)) +
	      ASPEED_MCTP_PCIE_VDM_HDR_SIZE;

	/* Copy PCIe header to original buffer */
	memcpy(pcie_mctp_hdr_data, hdr, sizeof(*hdr));

	mctp_trace_tx(pcie_mctp_hdr_data, len);

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		free(pcie_mctp_hdr_data);
		return -1;
	}
#endif

	write_len = write(astpcie->fd, pcie_mctp_hdr_data, len);
	if (write_len < 0) {
		mctp_prerr("TX error");
		return -1;
	}

	return 0;
}

static size_t mctp_astpcie_rx_get_payload_size(struct mctp_pcie_hdr *hdr)
{
	size_t len = PCIE_GET_DATA_LEN(hdr) * sizeof(uint32_t);
	uint8_t pad = PCIE_GET_PAD_LEN(hdr);

	return len - pad;
}

/*
 * Simple poll implementation for use
 */
int mctp_astpcie_poll(struct mctp_binding_astpcie *astpcie, int timeout)
{
	struct pollfd fds[1];
	int rc;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		struct timespec ts;
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		do {
			rc = nanosleep(&ts, &ts);
		} while (rc && errno == EINTR);
		return 0;
	}
#endif

	fds[0].fd = astpcie->fd;
	fds[0].events = POLLIN | POLLOUT;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	if (rc < 0) {
		mctp_prwarn("Poll returned error status (errno=%d)", errno);

		return -1;
	}

	return 0;
}

static bool mctp_astpcie_is_routing_supported(int routing)
{
	switch (routing) {
	case PCIE_ROUTE_TO_RC:
	case PCIE_ROUTE_BY_ID:
	case PCIE_BROADCAST_FROM_RC:
		return true;
	default:
		return false;
	}
}

int mctp_astpcie_rx(struct mctp_binding_astpcie *astpcie)
{
	uint32_t data[MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER];
	struct mctp_astpcie_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	struct mctp_pcie_hdr *hdr;
	size_t payload_len;
	int read_len;
	int rc;

#ifdef MOCKUP_ENDPOINT
	if (astpcie->fd <= 0) {
		return 0;
	}
#endif

	read_len = read(astpcie->fd, &data, sizeof(data));
	if (read_len < 0) {
		mctp_prerr("Reading RX data failed (errno = %d)", errno);
		return -1;
	}

	if (read_len < ASTPCIE_MIN_PACKET_SIZE) {
		mctp_prerr("Incorrect packet size: %d", read_len);
		return -1;
	}

	hdr = (struct mctp_pcie_hdr *)data;
	payload_len = mctp_astpcie_rx_get_payload_size(hdr);

	size_t len = (sizeof(struct mctp_pcie_hdr) + sizeof(struct mctp_hdr) +
		      payload_len);
	len = len > MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER ?
		      MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER :
		      len;
	mctp_trace_rx(&data, len);

	pkt_prv.routing = PCIE_GET_ROUTING(hdr);

	if (!mctp_astpcie_is_routing_supported(pkt_prv.routing)) {
		mctp_prerr("unsupported routing value: %d", pkt_prv.routing);
		return -1;
	}

	pkt_prv.remote_id = PCIE_GET_REQ_ID(hdr);

	pkt = mctp_pktbuf_alloc(&astpcie->binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");
		return -1;
	}

	rc = mctp_pktbuf_push(pkt, data + PCIE_HDR_SIZE_DW,
			      payload_len + sizeof(struct mctp_hdr));

	if (rc) {
		mctp_prerr("Cannot push to pktbuf");
		mctp_pktbuf_free(pkt);
		return -1;
	}

	memcpy(pkt->msg_binding_private, &pkt_prv, sizeof(pkt_prv));

	mctp_bus_rx(&astpcie->binding, pkt);

	return 0;
}

/*
 * Initializes PCIe binding structure
 */
struct mctp_binding_astpcie *mctp_astpcie_init_fileio(void)
{
	struct mctp_binding_astpcie *astpcie;

	astpcie = __mctp_alloc(sizeof(*astpcie));
	if (!astpcie)
		return NULL;

	memset(astpcie, 0, sizeof(*astpcie));

	astpcie->binding.name = "astpcie";
	astpcie->binding.version = 1;
	astpcie->binding.mctp_send_tx_queue = NULL;
	astpcie->binding.tx = mctp_astpcie_tx;
	astpcie->binding.start = mctp_astpcie_start;
	astpcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	astpcie->binding.pkt_header = PCIE_VDM_HDR_SIZE;
	astpcie->binding.pkt_trailer = PCIE_VDM_PAD_SIZE;
	astpcie->binding.pkt_priv_size =
		sizeof(struct mctp_astpcie_pkt_private);

	return astpcie;
}

/*
 * Closes file descriptor and releases binding memory
 */
void mctp_astpcie_free(struct mctp_binding_astpcie *astpcie)
{
	if (astpcie != NULL) {
		mctp_astpcie_close(astpcie);
		__mctp_free(astpcie);
	}
}

/*
 * Returns generic binder handler from PCIe binding handler
 */
struct mctp_binding *
mctp_binding_astpcie_core(struct mctp_binding_astpcie *astpcie)
{
	return &astpcie->binding;
}

int mctp_astpcie_init_pollfd(struct mctp_binding_astpcie *astpcie,
			     struct pollfd **pollfd)
{
	*pollfd = __mctp_alloc(1 * sizeof(struct pollfd));
	(*pollfd)->fd = astpcie->fd;
	(*pollfd)->events = POLLIN;

	return 1;
}
