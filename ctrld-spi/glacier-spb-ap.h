/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __GLACIER_SPB_AP_H__
#define __GLACIER_SPB_AP_H__
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    SPB_AP_OK,
    SPB_AP_MESSAGE_AVAILABLE,
    SPB_AP_ERROR_INVALID_ARGUMENT,
    SPB_AP_ERROR_TIMEOUT,
    SPB_AP_ERROR_UNKNOWN,
} SpbApStatus;

typedef enum
{
    SPB_INFO = 0x01,
    SPB_MCTP = 0x02,
    //...
    SPB_ERROR = 0xFF
} SpbApMsgType;

/// Callback required for libspb
typedef struct
{
    int debug_level;
    // no interrupt support
    int use_interrupt;
    volatile int* message_available;
    int (*gpio_read_interrupt_pin)();
    int (*on_mode_change)(bool quad, uint8_t waitCycles);

    // required for both interrupt and no interrupt
    int (*spi_xfer)(int slen, uint8_t* send, int rlen, uint8_t* recv, bool deassert);
} SpbAp;

/// Initialisation, called once at startup.
SpbApStatus spb_ap_initialize(SpbAp* ap);

/// Change configuration
SpbApStatus spb_ap_set_cfg(bool quad, uint8_t waitCycles);

/// Send message to glacier.
SpbApStatus spb_ap_send(int len, void* buf);

/// Receive a message from glacier.
SpbApStatus spb_ap_recv(int len, void* buf);

/// Called upon receiving GPIO interrupt.
SpbApStatus spb_ap_on_interrupt(int value);

/// Shutdown
SpbApStatus spb_ap_shutdown();

/// Force a reset of SPB
SpbApStatus spb_ap_reset();

SpbApStatus posted_write(uint16_t offset, int len, uint8_t* payload);
SpbApStatus posted_read(int offset, int len, uint8_t* payload);
uint16_t mailbox_write(uint32_t v);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // __GLACIER_SPB_AP_H__
