#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <systemd/sd-bus.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>


#include "libmctp-cmds.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-ctrl-log.h"
#include "mctp-sdbus.h"
#include "mctp-discovery.h"

extern mctp_uuid_table_t        *g_uuid_entries;
extern int g_uuid_table_len;

extern mctp_msg_type_table_t    *g_msg_type_entries;
extern int                      g_msg_type_table_len;

static int                      mctp_ctrl_running = 1;

/* String map for supported bus type */
char g_mctp_ctrl_supported_buses[MCTP_CTRL_MAX_BUS_TYPES][10] = {
    "PCIe Bus ",
    "SPI Bus ",
    "I2C Bus "
};

static int mctp_ctrl_supported_bus_types(sd_bus *bus,
                                         const char *path,
                                         const char *interface,
                                         const char *property,
                                         sd_bus_message *reply,
                                         void *userdata,
                                         sd_bus_error *error)
{
    int     r, i=0;

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    for (i = 0; i < MCTP_CTRL_MAX_BUS_TYPES; i++) {
        r = sd_bus_message_append(reply, "s", g_mctp_ctrl_supported_buses[i]);
        if (r < 0) {
            MCTP_CTRL_ERR("Failed to build the list of failed boot modes: %s", strerror(-r));
            return r;
        }
    }

    return sd_bus_message_close_container(reply);
}

static int mctp_ctrl_get_uuids(sd_bus *bus,
                               const char *path,
                               const char *interface,
                               const char *property,
                               sd_bus_message *reply,
                               void *userdata,
                               sd_bus_error *error)
{
    int                     r, i=0;
    char                    uuid_data[MCTP_CTRL_SDBUS_MAX_MSG_SIZE];
    mctp_uuid_table_t       *uuid_entries = g_uuid_entries;

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    while (uuid_entries != NULL) {
        /* Reset the message buffer */
        memset(uuid_data, 0, MCTP_CTRL_SDBUS_MAX_MSG_SIZE);

        /* Frame the message */
        snprintf(uuid_data, MCTP_CTRL_SDBUS_MAX_MSG_SIZE,
                            "EID: 0x%x, UUID: 0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x",
                            uuid_entries->eid,
                            uuid_entries->uuid.canonical.data0,
                            uuid_entries->uuid.canonical.data1,
                            uuid_entries->uuid.canonical.data2,
                            uuid_entries->uuid.canonical.data3,
                            uuid_entries->uuid.canonical.data4[0],
                            uuid_entries->uuid.canonical.data4[1],
                            uuid_entries->uuid.canonical.data4[2],
                            uuid_entries->uuid.canonical.data4[3],
                            uuid_entries->uuid.canonical.data4[4],
                            uuid_entries->uuid.canonical.data4[5]);

        r = sd_bus_message_append(reply, "s", uuid_data);
        if (r < 0) {
            MCTP_CTRL_ERR("Failed to build the list of failed boot modes: %s", strerror(-r));
            return r;
        }

        /* Increment for next entry */
        uuid_entries = uuid_entries->next;
    }

    return sd_bus_message_close_container(reply);
}

static int mctp_ctrl_get_msg_type(sd_bus *bus,
                               const char *path,
                               const char *interface,
                               const char *property,
                               sd_bus_message *reply,
                               void *userdata,
                               sd_bus_error *error)
{
    int                     r, i=0;
    char                    msg_type_data[MCTP_CTRL_SDBUS_MAX_MSG_SIZE];
    mctp_msg_type_table_t   *msg_type_entries = g_msg_type_entries;

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    while (msg_type_entries != NULL) {

        /* Reset the message buffer */
        memset(msg_type_data, 0, MCTP_CTRL_SDBUS_MAX_MSG_SIZE);

        MCTP_CTRL_DEBUG("MCTP-CTRL: Msg Type length: %d\n", msg_type_entries->data_len);

        /* Frame the message */
        snprintf(msg_type_data, MCTP_CTRL_SDBUS_MAX_MSG_SIZE,
                            "EID: 0x%x, supported types: 0x%x-0x%x",
                            msg_type_entries->eid,
                            msg_type_entries->data[0],
                            msg_type_entries->data[1]);

        r = sd_bus_message_append(reply, "s", msg_type_data);
        if (r < 0) {
            MCTP_CTRL_ERR("Failed to build the list of failed boot modes: %s", strerror(-r));
            return r;
        }

        /* Increment for next entry */
        msg_type_entries = msg_type_entries->next;
    }

    return sd_bus_message_close_container(reply);
}

static int mctp_ctrl_dispatch_sd_bus(mctp_sdbus_context_t *context)
{
    int r = 0;
    if (context->fds[MCTP_CTRL_SD_BUS_FD].revents) {
        r = sd_bus_process(context->bus, NULL);
        if (r > 0)
            MCTP_CTRL_TRACE("Processed %d dbus events\n", r);
    }

    return r;
}

static const sd_bus_vtable mctp_ctrl_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("mctp_supported_bus",   "as", mctp_ctrl_supported_bus_types,    0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("mctp_get_uuid",        "as", mctp_ctrl_get_uuids,              0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("mctp_get_msg_type",    "as", mctp_ctrl_get_msg_type,           0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};


/* MCTP ctrl sdbus initialization */
int mctp_ctrl_sdbus_init (void)
{
    mctp_sdbus_context_t *context;
    const char *name = "mctp-ctrl";
    int opt, polled, r;

    context = calloc(1, sizeof(*context));

    MCTP_CTRL_TRACE("Starting\n");
    r = sd_bus_default_system(&context->bus);
    if (r < 0) {
        MCTP_CTRL_ERR("Failed to connect to system bus: %s\n", strerror(-r));
        goto finish;
    }

    MCTP_CTRL_TRACE("Registering dbus methods/signals\n");
    r = sd_bus_add_object_vtable(context->bus,
                                 NULL,
                                 MCTP_CTRL_OBJ_NAME,
                                 MCTP_CTRL_DBUS_NAME,
                                 mctp_ctrl_vtable,
                                 context);
    if (r < 0) {
        MCTP_CTRL_ERR("Failed to issue method call: %s\n", strerror(-r));
        goto finish;
    }

    MCTP_CTRL_TRACE("Requesting dbus name: %s\n", MCTP_CTRL_DBUS_NAME);
    r = sd_bus_request_name(context->bus, MCTP_CTRL_DBUS_NAME,
                SD_BUS_NAME_ALLOW_REPLACEMENT|SD_BUS_NAME_REPLACE_EXISTING);
    if (r < 0) {
        MCTP_CTRL_ERR("Failed to acquire service name: %s\n", strerror(-r));
        goto finish;
    }

    MCTP_CTRL_TRACE("Getting dbus file descriptors\n");
    context->fds[MCTP_CTRL_SD_BUS_FD].fd = sd_bus_get_fd(context->bus);
    if (context->fds[MCTP_CTRL_SD_BUS_FD].fd < 0) {
        r = -errno;
        MCTP_CTRL_TRACE("Couldn't get the bus file descriptor: %s\n", strerror(errno));
        goto finish;
    }

    context->fds[MCTP_CTRL_SD_BUS_FD].events = POLLIN;

    MCTP_CTRL_DEBUG("%s: Entering polling loop\n", __func__);

    while (mctp_ctrl_running) {
        polled = poll(context->fds, MCTP_CTRL_TOTAL_FDS, MCTP_CTRL_POLL_TIMEOUT);
        if (polled == 0)
            continue;
        if (polled < 0) {
            r = -errno;
            MCTP_CTRL_ERR("Error from poll(): %s\n", strerror(errno));
            goto finish;
        }
        r = mctp_ctrl_dispatch_sd_bus(context);
        if (r < 0) {
            MCTP_CTRL_ERR("Error handling dbus event: %s\n", strerror(-r));
            goto finish;
        }
    }

finish:
    sd_bus_unref(context->bus);
    free(context);

    return r;

}
