#pragma once

struct mctp_spi_pkt_private {
	int fd;
	int gpio_lookup;
	uint8_t controller;
} __attribute__((packed));

int exec_spi_test(const mctp_cmdline_args_t *cmdline, mctp_ctrl_t *mctp_ctrl);
