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

#ifndef __GLACIER_SPB_AP_H__
#define __GLACIER_SPB_AP_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SPB_AP_OK,
	SPB_AP_MESSAGE_AVAILABLE,
	SPB_AP_ERROR_INVALID_ARGUMENT,
	SPB_AP_ERROR_TIMEOUT,
	SPB_AP_ERROR_UNKNOWN,
} SpbApStatus;

typedef enum {
	SPB_INFO = 0x01,
	SPB_MCTP = 0x02,
	//...
	SPB_ERROR = 0xFF
} SpbApMsgType;

/// Callback required for libspb
typedef struct {
	int debug_level;
	int msgs_available;
	int gpio_fd;
	uint32_t ec2spimb;
	int (*gpio_read_interrupt_pin)();
	int (*on_mode_change)(bool quad, uint8_t waitCycles);

	// required for both interrupt and no interrupt
	int (*spi_xfer)(int slen, uint8_t *send, int rlen, uint8_t *recv,
			bool deassert);
} SpbAp;

/// Initialisation, called once at startup.
SpbApStatus spb_ap_initialize(SpbAp *ap);

/// Change configuration
SpbApStatus spb_ap_set_cfg(SpbAp *ap, bool quad, uint8_t waitCycles);

/// Send message to glacier.
SpbApStatus spb_ap_send(SpbAp *ap, int len, void *buf);

/// Receive a message from glacier.
SpbApStatus spb_ap_recv(SpbAp *ap, int len, void *buf);

SpbApStatus spb_ap_wait_for_intr(SpbAp *ap, int timeout_ms, bool polling);

/// Called upon receiving GPIO interrupt.
SpbApStatus spb_ap_on_interrupt(SpbAp *ap);

/// Shutdown
SpbApStatus spb_ap_shutdown(SpbAp *ap);

/// Force a reset of SPB
SpbApStatus spb_ap_reset(SpbAp *ap);

int spb_ap_msgs_available(SpbAp *ap);

SpbApStatus posted_write(SpbAp *ap, uint16_t offset, int len, uint8_t *payload);
SpbApStatus posted_read(SpbAp *ap, int offset, int len, uint8_t *payload);
uint16_t mailbox_write(SpbAp *ap, uint32_t v);

const char *spb_ap_strstatus(SpbApStatus status);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __GLACIER_SPB_AP_H__
