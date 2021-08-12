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

extern int g_uuid_table_len;

static int mctp_ctrl_running = 1;

char g_mctp_ctrl_supported_buses[MCTP_CTRL_MAX_BUS_TYPES][10] = {
    "PCIe Bus ",
    "I2C Bus ",
    "SPI Bus "
};

static int mctp_ctrl_supported_bus_types(sd_bus *bus,
                                         const char *path,
                                         const char *interface,
                                         const char *property,
                                         sd_bus_message *reply,
                                         void *userdata,
                                         sd_bus_error *error)
{
    int r, i=0;

    printf("MCTP-CTRL: Total Supported bus types: %d\n", MCTP_CTRL_MAX_BUS_TYPES);

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    for (i = 0; i < MCTP_CTRL_MAX_BUS_TYPES; i++) {
        r = sd_bus_message_append(reply, "s", g_mctp_ctrl_supported_buses[i]);
        if (r < 0) {
            fprintf(stderr, "Failed to build the list of failed boot modes: %s", strerror(-r));
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
    int r, i=0;
    char uuid[64];

    printf("MCTP-CTRL: Total UUID's: %d\n", g_uuid_table_len);

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    for (i = 0; i < g_uuid_table_len; i++) {
        snprintf(uuid, 64, "EID: %d, UUID: %s", i, (char *)"112233445566");
        r = sd_bus_message_append(reply, "s", uuid);
        if (r < 0) {
            fprintf(stderr, "Failed to build the list of failed boot modes: %s", strerror(-r));
            return r;
        }
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

/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable mctp_ctrl_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("mctp_supported_bus", "as", mctp_ctrl_supported_bus_types, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("mctp_get_uuid", "as", mctp_ctrl_get_uuids, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};


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
    r = sd_bus_request_name(context->bus, MCTP_CTRL_DBUS_NAME, SD_BUS_NAME_ALLOW_REPLACEMENT|SD_BUS_NAME_REPLACE_EXISTING);
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

    MCTP_CTRL_TRACE("Entering polling loop\n");

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
