/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#include "glacier-spb-ap.h"

#include <time.h>
#define __USE_GNU
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libmctp.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-log.h"

#define POLL_SREG_TIMEOUT_MSECS 10000ULL
#define POLL_LOCK_TIMEOUT_MSECS 10000ULL
#define POLL_INT_TIMEOUT_MSECS  10000ULL
#define MAX_BYTES_PER_TRANSACTION 32
#define WAIT_CYCLES 0
#define TAR_CYCLES 1 // 1 in single, 4 in quad
#define TAR_WAIT_CYCLES (WAIT_CYCLES + TAR_CYCLES)

#define CHECK_FUNC_RET(func) {                  \
    SpbApStatus status = func;                         \
    if (status != SPB_AP_OK) { return status; } \
}

#define nullptr ((void*)0)

static SpbAp _spb;
static volatile uint32_t _ec2spimb = 0x00000000;
static pthread_mutex_t spi_mutex = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;

static inline uint64_t clock_msecs() 
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static inline SpbApStatus lock() 
{
    if (_spb.use_interrupt) {
        uint64_t start = clock_msecs();
        while (pthread_mutex_trylock(&spi_mutex) != 0) {
            if (clock_msecs() - start > POLL_LOCK_TIMEOUT_MSECS) {
                return SPB_AP_ERROR_TIMEOUT;
            }
        }
    }
    return SPB_AP_OK;
}
static inline SpbApStatus unlock()
{
    return (!_spb.use_interrupt || pthread_mutex_unlock(&spi_mutex) == 0)
               ? SPB_AP_OK
               : SPB_AP_ERROR_UNKNOWN;
    return SPB_AP_OK;
}

static const char* mailbox_str(uint32_t mb)
{
    static char str[128];
    str[0] = '\0';
    switch (mb & 0x0F000000) {
        case EC_ACK: strcat(str, "EC_ACK"); break;
        case AP_REQUEST_WRITE: strcat(str, "AP_REQUEST_WRITE"); break;
        case AP_READY_TO_READ: strcat(str, "AP_READY_TO_READ"); break;
        case AP_FINISHED_READ: strcat(str, "AP_FINISHED_READ"); break;
        case AP_REQUEST_RESET: strcat(str, "AP_REQUEST_RESET"); break;
        default: break;
    }
    if (mb & 0xFF) { sprintf(str + strlen(str), "LEN:%02x", mb & 0xFF); }
    if (mb & EC_MSG_AVAILABLE) {
        sprintf(str+strlen(str), " %x", mb);
        strcat(str, (strlen(str) > 0 ? "|EC_MSG_AVAILABLE" : "EC_MSG_AVAILABLE"));
    }

    if (strlen(str) == 0) {
        sprintf(str, "UNKNOWN MAILBOX: %08x", mb);
    }
    return str;
};

static inline uint32_t buf2dw(uint8_t* x)
{
    return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | (x[3] << 0);
}

static inline uint16_t buf2w(uint8_t* x) 
{ 
    return (x[0] << 8) | (x[1] << 0); 
}

static inline void dw2buf(uint32_t dw, uint8_t* buf)
{
    buf[0] = (uint8_t)((dw >> 24) & 0xff);
    buf[1] = (uint8_t)((dw >> 16) & 0xff);
    buf[2] = (uint8_t)((dw >> 8) & 0xff);
    buf[3] = (uint8_t)((dw >> 0) & 0xff);
}

static inline void w2buf(uint16_t w, uint8_t* buf)
{
    buf[0] = (uint8_t)((w >> 8) & 0xff);
    buf[1] = (uint8_t)((w >> 0) & 0xff);
}

static inline void spi_xfer(int sendLen, uint8_t* sbuf, int recvLen, uint8_t* rbuf, bool deassert)
{
    //MCTP_CTRL_DEBUG("%s: txlen: %d, rxlen: %d\n", __func__, sendLen, recvLen);
    _spb.spi_xfer(sendLen, sbuf, recvLen, rbuf, deassert);
}

uint16_t sreg_write_8(uint16_t addr, uint8_t value)
{
    uint8_t buf[1 + 2 + 1 + TAR_WAIT_CYCLES + 2] = {0};
    buf[0] = CMD_SREG_W8;
    w2buf(addr, buf + 1);
    buf[3] = value;
    spi_xfer(1+2+1, buf, TAR_WAIT_CYCLES+2, buf, true);
    // return lower 16 bits of status
    return buf2w(buf + TAR_WAIT_CYCLES);
}
uint16_t sreg_write_32(uint16_t addr, uint32_t value)
{
    uint8_t buf[1 + 2 + 4 + TAR_WAIT_CYCLES + 2] = {0};
    buf[0] = CMD_SREG_W32;
    w2buf(addr, buf + 1);
    dw2buf(value, buf + 3);
    spi_xfer(7, buf, TAR_WAIT_CYCLES+2, buf, true);
    // return lower 16 bits of status
    return buf2w(buf + TAR_WAIT_CYCLES);
}

uint16_t sreg_read_8(uint16_t addr, uint8_t *val)
{
    uint8_t buf[1 + 2 + TAR_WAIT_CYCLES + 2 + 1] = {0};
    buf[0] = CMD_SREG_R8;
    w2buf(addr, buf + 1);
    spi_xfer(3, buf, TAR_WAIT_CYCLES + 2 + 1, buf, true);
    *val = buf[TAR_WAIT_CYCLES + 2];
    // return lower 16 bits of status
    return buf2w(buf + TAR_WAIT_CYCLES);
}

uint16_t sreg_read_32(uint16_t addr, uint32_t *val)
{
    uint8_t buf[1 + 2 + TAR_WAIT_CYCLES + 2 + 4] = {0};
    buf[0] = CMD_SREG_R32;
    w2buf(addr, buf + 1);
    spi_xfer(3, buf, TAR_WAIT_CYCLES + 2 + 4, buf, true);
    *val = buf2dw(buf + TAR_WAIT_CYCLES + 2);
    // return lower 16 bits of status
    return buf2w(buf + TAR_WAIT_CYCLES);
}

uint32_t cmd_poll_all()
{
    uint8_t buf[1 + TAR_CYCLES + 4] = {0};
    buf[0] = CMD_POLL_ALL;
    spi_xfer(1, buf, TAR_CYCLES + 4, buf, true);

    return buf2dw(buf + TAR_CYCLES);
}

// Read RX_FIFO_EMPTY
static SpbApStatus wait_for_tx_fifo_not_empty() 
{ 
    uint64_t start = clock_msecs();
    while((cmd_poll_all() & 0x400) != 0) {
        if (clock_msecs() - start > POLL_SREG_TIMEOUT_MSECS) {
            return SPB_AP_ERROR_TIMEOUT;
        }
    }
    return SPB_AP_OK;
}

uint16_t mailbox_write(uint32_t v)
{
    uint16_t sts = sreg_write_32(SPI_SPIM2EC_MBX, v);
    if (_spb.debug_level > 0) {
        MCTP_CTRL_DEBUG("[SPIM2ECMB] %s\n", mailbox_str(v));
        
    }
    return sts;
}

static inline uint32_t clear_memory_write_done()
{
    return sreg_write_8(SPI_STS, 0b0001); // MemoryWriteDone bit 0, write to clear
}
static inline uint32_t clear_memory_read_done()
{
    return sreg_write_8(SPI_STS, 0b0010); // MemoryReadDone bit 1, write to clear
}
// Polling procedures with timeouts
SpbApStatus wait_for_memory_write_busy_and_rx_fifo_empty()
{ 
    uint64_t start = clock_msecs();
    // RxFifoEmpty Bit 8, MemoryWriteBusy Bit 3
    while ((cmd_poll_all() & 0x108) == 0) {
        if (clock_msecs() - start > POLL_SREG_TIMEOUT_MSECS)
            return SPB_AP_ERROR_TIMEOUT;
    }
    return SPB_AP_OK;
}

SpbApStatus wait_for_ack()
{
    SpbApStatus status = SPB_AP_OK;
    uint64_t start = clock_msecs();
    if (_spb.use_interrupt) {
        // simple implementation, could use signal/poll
        while (_ec2spimb != EC_ACK) {
            if (clock_msecs() - start > POLL_INT_TIMEOUT_MSECS)
                return SPB_AP_ERROR_TIMEOUT;
        }
    }
    else {
        // no interrupt support implementation
        do {
            // wait for interrupt pin
            while (_spb.gpio_read_interrupt_pin() == 0) {
                if (clock_msecs() - start > POLL_INT_TIMEOUT_MSECS) {
                    MCTP_CTRL_ERR("%s: Failed (Timeout)\n", __func__);
                    return SPB_AP_ERROR_TIMEOUT;
                }
            }
            status = spb_ap_on_interrupt(1);
            switch(status) {
                case SPB_AP_MESSAGE_AVAILABLE:
                    *_spb.message_available = 1;
                    status = SPB_AP_OK;
                    break;
                case SPB_AP_OK:
                    break;
                default:  // error
                    return status;
            }
        } while (_ec2spimb != EC_ACK);
    }
    _ec2spimb = 0;
    return status;
}

SpbApStatus wait_for_length(uint32_t *bytes)
{
    SpbApStatus status = SPB_AP_OK;
    uint64_t start = clock_msecs();

    if (_spb.use_interrupt) {
        while ((_ec2spimb & 0xFF) == 0) {
            if (clock_msecs() - start > POLL_INT_TIMEOUT_MSECS) {
                return SPB_AP_ERROR_TIMEOUT;
            }
        }
    }
    else {
        // no interrupt support
        do {
            // wait for interrupt pin
            while (_spb.gpio_read_interrupt_pin() == 0) {
                if (clock_msecs() - start > POLL_INT_TIMEOUT_MSECS) {
                    return SPB_AP_ERROR_TIMEOUT;
                }
            }
            status = spb_ap_on_interrupt(1);
            switch(status) {
                case SPB_AP_MESSAGE_AVAILABLE:
                    *_spb.message_available = 1;
                    status = SPB_AP_OK;
                    break;
                case SPB_AP_OK:
                    break;
                default:  // error
                    return status;
            }
        } while ((_ec2spimb & 0xFF) == 0);
    }

    *bytes     = _ec2spimb & 0xFF;
    _ec2spimb = 0;
    return status;
}


// Write payload with maxiumum of 32 bytes per transfer
SpbApStatus posted_write(uint16_t offset, int len, uint8_t* payload)
{
    uint8_t buf[128] = {0};
    int off          = 0;
    while (len > 0) {
        int bytes = len > MAX_BYTES_PER_TRANSACTION 
                  ? MAX_BYTES_PER_TRANSACTION : len;
        if (bytes >= 4) {
            bytes &= 0xFFFFFFFC;
            buf[0] = CMD_MEM_BLK_W1 + (bytes / 4 - 1);
            w2buf(offset + off, buf + 1);
            // byteswap for DWORD
            for (int i = 0; i < bytes; i += 4) {
                buf[i + 3 + 0] = payload[off + i + 3];
                buf[i + 3 + 1] = payload[off + i + 2];
                buf[i + 3 + 2] = payload[off + i + 1];
                buf[i + 3 + 3] = payload[off + i + 0];
            }
            CHECK_FUNC_RET(wait_for_memory_write_busy_and_rx_fifo_empty());
            spi_xfer(3 + bytes, buf, 0, buf, true);
            clear_memory_write_done();
        }
        else {
            for (int i = 0; i < bytes; i++) {
                buf[0] = CMD_MEM_W8;
                w2buf(offset + off + i, buf + 1);
                buf[3] = payload[off + i];
                CHECK_FUNC_RET(wait_for_memory_write_busy_and_rx_fifo_empty());
                spi_xfer(3 + 1, buf, 0, buf, true);
                clear_memory_write_done();
            }
        }
        off += bytes;
        len -= bytes;
    }

    return SPB_AP_OK;
}

static SpbApStatus posted_read_helper(uint8_t cmd, uint8_t cmd2, 
                                      uint16_t addr, 
                                      int bytes, uint8_t* buf)
{
    // Send the post read command
    buf[0] = cmd;
    w2buf(addr, buf + 1);
    spi_xfer(3, buf, 0, buf, true);

    // check ok to read
    CHECK_FUNC_RET(wait_for_tx_fifo_not_empty());

    // Initiate FIFO READ
    buf[0] = cmd2;
    spi_xfer(1, buf, TAR_CYCLES + 2, buf, false);

    // Check MemoryReadDone
    if ((buf[TAR_CYCLES+1] & 0x02) == 0) {
        // Poll status
        // TODO: this section is not tested
        uint64_t start = clock_msecs();
        do {
            // read status until MemoryReadDone is set
            buf[0] = 0, buf[1] = 0;
            spi_xfer(0, buf, 2, buf, false);
            if (clock_msecs() - start > POLL_INT_TIMEOUT_MSECS) {
                return SPB_AP_ERROR_TIMEOUT;
            }
        } while((buf[1] & 0x02) == 0);
    }

    // Read actual data
    spi_xfer(0, buf, bytes, buf, true);

    clear_memory_read_done();

    return SPB_AP_OK;
}

SpbApStatus posted_read(int offset, int len, uint8_t* payload)
{
    uint8_t buf[128] = {0};
    int off          = 0;
    while (len > 0) {
        int bytes = len > MAX_BYTES_PER_TRANSACTION 
                  ? MAX_BYTES_PER_TRANSACTION : len;
        if (bytes >= 4) {
            bytes &= 0xFFFFFFFC;
            CHECK_FUNC_RET(posted_read_helper(CMD_MEM_BLK_R1 + (bytes / 4 - 1),
                                              CMD_BLK_RD_FIFO_FSR + (bytes / 4 - 1),
                                              offset + off, bytes, buf));

            for (int i = 0; i < bytes; i += 4) {
                payload[off + i + 3] = buf[i + 0];
                payload[off + i + 2] = buf[i + 1];
                payload[off + i + 1] = buf[i + 2];
                payload[off + i + 0] = buf[i + 3];
            }
        }
        else {
            for (int i = 0; i < bytes; i++) {
                CHECK_FUNC_RET(posted_read_helper(CMD_MEM_R8, CMD_RD_SNGL_FIFO8_FSR,
                                                  offset + off + i,
                                                  4,  // TODO: why is this 4 ?
                                                  buf));
                // TODO: offset 3 because we have to read 4 bytes
                payload[off + i] = buf[3];
            }
        }
        off += bytes;
        len -= bytes;
    }

    return SPB_AP_OK;
}

// --- public

SpbApStatus spb_ap_initialize(SpbAp* ap)
{
    if (!ap || ap->spi_xfer == nullptr || ap->on_mode_change == nullptr) {
        return SPB_AP_ERROR_INVALID_ARGUMENT;
    }

    // ensure no interrupt has additional requirements
    if ((ap->use_interrupt == 0)
        && (ap->gpio_read_interrupt_pin == NULL || ap->message_available == NULL)) {
        return SPB_AP_ERROR_INVALID_ARGUMENT;
    }

    _spb = *ap;

    return spb_ap_reset();
}

SpbApStatus spb_ap_shutdown()
{
    // leave Glacier in single spi mode
    return spb_ap_set_cfg(false, 0);
}

SpbApStatus spb_ap_set_cfg(bool quad, uint8_t waitCycles)
{

    uint8_t cmd[] = {
        0x03,
        0x00,
        waitCycles,
        (uint8_t)(quad ? 0b0001 : 0x00)
    };

    // send set cfg
    CHECK_FUNC_RET(lock());
    mailbox_write(AP_REQUEST_WRITE);
    CHECK_FUNC_RET(unlock());
    CHECK_FUNC_RET(wait_for_ack());
    CHECK_FUNC_RET(lock());
    CHECK_FUNC_RET(posted_write(0, sizeof(cmd), cmd));
    mailbox_write(sizeof(cmd));
    CHECK_FUNC_RET(unlock());

    // mode has changed
    if (_spb.on_mode_change(quad, waitCycles)) {
        CHECK_FUNC_RET(wait_for_ack());
        return SPB_AP_OK;
    }
    return SPB_AP_ERROR_UNKNOWN;
}

SpbApStatus spb_ap_on_interrupt(int value)
{
    CHECK_FUNC_RET(lock());
    // rising edge
    SpbApStatus ret = SPB_AP_OK;
    if (value) {
        uint32_t sts;
        // check mailbox and reset interrupt
        uint32_t mb;
        sts = sreg_read_32(SPI_EC2SPIM_MBX, &mb);
        if (_spb.debug_level > 0) {
            MCTP_CTRL_DEBUG("[EC2SPIMMB] %s %04x\n", mailbox_str(mb), sts);
        }
        if (mb & EC_MSG_AVAILABLE) { ret = SPB_AP_MESSAGE_AVAILABLE; }
        _ec2spimb = mb & ~EC_MSG_AVAILABLE;
    }
    CHECK_FUNC_RET(unlock());
    return ret;
}

SpbApStatus spb_ap_send(int len, void* buf)
{
    CHECK_FUNC_RET(lock());
    //MCTP_CTRL_DEBUG("%s: AP_REQUEST_WRITE\n", __func__);
    mailbox_write(AP_REQUEST_WRITE);
    CHECK_FUNC_RET(unlock());
    //MCTP_CTRL_DEBUG("%s: wait_for_ack\n", __func__);
    CHECK_FUNC_RET(wait_for_ack());
    CHECK_FUNC_RET(lock());
    //MCTP_CTRL_DEBUG("%s: posted_write\n", __func__);
    CHECK_FUNC_RET(posted_write(0, len, (uint8_t *)(buf)));
    //MCTP_CTRL_DEBUG("%s: mailbox_write\n", __func__);
    mailbox_write(len);
    CHECK_FUNC_RET(unlock());
    //MCTP_CTRL_DEBUG("%s: wait_for_ack\n", __func__);
    CHECK_FUNC_RET(wait_for_ack());
    //MCTP_CTRL_DEBUG("%s: Success\n", __func__);
    return SPB_AP_OK;
}

SpbApStatus spb_ap_recv(int len, void* buf)
{
    CHECK_FUNC_RET(lock());
    //MCTP_CTRL_DEBUG("%s: AP_REQUEST_READ\n", __func__);
    mailbox_write(AP_READY_TO_READ);
    CHECK_FUNC_RET(unlock());
    uint32_t bytes;
    //MCTP_CTRL_DEBUG("%s: wait_for_length\n", __func__);
    CHECK_FUNC_RET(wait_for_length(&bytes));
    CHECK_FUNC_RET(lock());
    //MCTP_CTRL_DEBUG("%s: posted_read: bytes: %d\n", __func__, bytes);
    CHECK_FUNC_RET(posted_read(0x8000, bytes, (uint8_t *)(buf)));
    //MCTP_CTRL_DEBUG("%s: mailbox_write\n", __func__);
    mailbox_write(AP_FINISHED_READ);
    CHECK_FUNC_RET(unlock());
    //MCTP_CTRL_DEBUG("%s: wait_for_ack\n", __func__);
    CHECK_FUNC_RET(wait_for_ack());
    //MCTP_CTRL_DEBUG("%s: Success\n", __func__);
    return SPB_AP_OK;
}

SpbApStatus spb_ap_reset()
{
    // reset locals
    _ec2spimb = 0;
    if (_spb.message_available) {
        *_spb.message_available = 0;
    }
    // initiate reset
    mailbox_write(AP_REQUEST_RESET);

    // wait for ack
    CHECK_FUNC_RET(wait_for_ack());
    return SPB_AP_OK;
}

