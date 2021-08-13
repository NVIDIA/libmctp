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

static uint8_t mctp_ctrl_get_eid_from_sdbus_path(const char *path)
{
    char *output = NULL;

    output = strrchr(path, '/');
    if(output != NULL) {
        output++;
        return atoi(output);
    }

    return 0;
}

static int mctp_ctrl_sdbus_get_nw_id(sd_bus *bus,
                                     const char *path,
                                     const char *interface,
                                     const char *property,
                                     sd_bus_message *reply,
                                     void *userdata,
                                     sd_bus_error *error)
{
    int                     r, i=0;
    uint32_t                mctp_nw_id;
    uint8_t                 eid_req = 0;
    mctp_msg_type_table_t   *entry = g_msg_type_entries;

    eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

    while (entry != NULL) {

       if (entry->eid == eid_req) {
           mctp_nw_id = MCTP_CTRL_SDBUS_NETWORK_ID;
           break;
       }

        /* Increment for next entry */
        entry = entry->next;
    }

    /* append the message */
    return sd_bus_message_append(reply, "u", mctp_nw_id);
}

static int mctp_ctrl_sdbus_get_endpoint(sd_bus *bus,
                                     const char *path,
                                     const char *interface,
                                     const char *property,
                                     sd_bus_message *reply,
                                     void *userdata,
                                     sd_bus_error *error)
{
    int                     r, i=0;
    uint8_t                 eid_req = 0;
    mctp_msg_type_table_t   *entry = g_msg_type_entries;
    uint32_t                get_eid;

    eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

    while (entry != NULL) {

        if (entry->eid == eid_req) {
            get_eid = entry->eid;
            break;
        }

        /* Increment for next entry */
        entry = entry->next;
    }

    /* append the message */
    return sd_bus_message_append(reply, "u", get_eid);
}

static int mctp_ctrl_sdbus_get_msg_type(sd_bus *bus,
                                  const char *path,
                                  const char *interface,
                                  const char *property,
                                  sd_bus_message *reply,
                                  void *userdata,
                                  sd_bus_error *error)
{
    int                     r, i=0;
    uint8_t                 eid_req = 0;
    mctp_msg_type_table_t   *entry = g_msg_type_entries;

    eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

    r = sd_bus_message_open_container(reply, 'a', "y");
    if (r < 0)
        return r;

    while (entry != NULL) {

        if (entry->eid == eid_req) {

            /* Traverse supported message type one by one */
            while (i < entry->data_len) {
                /* append the message */
                r = sd_bus_message_append(reply, "y", entry->data[i]);
                if (r < 0) {
                   MCTP_CTRL_ERR("Failed sdbus message append: %s", strerror(-r));
                   return r;
                }

                i++;
            }

            break;
       }

        /* Increment for next entry */
        entry = entry->next;
    }

    return sd_bus_message_close_container(reply);
}



static int mctp_ctrl_sdbus_get_uuid(sd_bus *bus,
                                     const char *path,
                                     const char *interface,
                                     const char *property,
                                     sd_bus_message *reply,
                                     void *userdata,
                                     sd_bus_error *error)
{
    int                     r, i=0;
    uint8_t                 eid_req = 0;
    mctp_uuid_table_t       *entry = g_uuid_entries;
    char                    uuid_data[MCTP_CTRL_SDBUS_MAX_MSG_SIZE];

    eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

    /* Reset the message buffer */
    memset(uuid_data, 0, MCTP_CTRL_SDBUS_MAX_MSG_SIZE);

    while (entry != NULL) {

        if (entry->eid == eid_req) {
            /* Frame the message */
            snprintf(uuid_data, MCTP_CTRL_SDBUS_MAX_MSG_SIZE,
                            "%x-%x-%x-%x-%x%x%x%x%x%x",
                            entry->uuid.canonical.data0,
                            entry->uuid.canonical.data1,
                            entry->uuid.canonical.data2,
                            entry->uuid.canonical.data3,
                            entry->uuid.canonical.data4[0],
                            entry->uuid.canonical.data4[1],
                            entry->uuid.canonical.data4[2],
                            entry->uuid.canonical.data4[3],
                            entry->uuid.canonical.data4[4],
                            entry->uuid.canonical.data4[5]);
            break;
       }

        /* Increment for next entry */
        entry = entry->next;
    }

    /* append the message */
    return sd_bus_message_append(reply, "s", uuid_data);

}



static int mctp_ctrl_dispatch_sd_bus(mctp_sdbus_context_t *context)
{
    int r = 0;
    if (context->fds[MCTP_CTRL_SD_BUS_FD].revents) {
        r = sd_bus_process(context->bus, NULL);
    }

    return r;
}

/* Properties for xyz.openbmc_project.MCTP.Endpoint */
static const sd_bus_vtable mctp_ctrl_endpoint_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("NetworkId",                "u",    mctp_ctrl_sdbus_get_nw_id,        0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("EID",                      "u",    mctp_ctrl_sdbus_get_endpoint,     0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("SupportedMessageTypes",    "ay",   mctp_ctrl_sdbus_get_msg_type,     0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

/* Properties for xyz.openbmc_project.Common.UUID */
static const sd_bus_vtable mctp_ctrl_common_uuid_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("UUID",                     "s",    mctp_ctrl_sdbus_get_uuid,         0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};


/* MCTP ctrl sdbus initialization */
int mctp_ctrl_sdbus_init (void)
{
    mctp_sdbus_context_t    *context;
    int                     opt, polled, r;
    char                    mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
    mctp_msg_type_table_t   *entry = g_msg_type_entries;

    context = calloc(1, sizeof(*context));

    r = sd_bus_default_system(&context->bus);
    if (r < 0) {
        MCTP_CTRL_ERR("Failed to connect to system bus: %s\n", strerror(-r));
        goto finish;
    }


    while (entry != NULL) {

        /* Reset the message buffer */
        memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);

        /* Frame the message */
        snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
                            "%s%d",
                            MCTP_CTRL_NW_OBJ_PATH,
                            entry->eid);

        MCTP_CTRL_TRACE("Registering object '%s' for Endpoint: %d\n",
                                            mctp_ctrl_objpath, entry->eid);
        r = sd_bus_add_object_vtable(context->bus,
                                 NULL,
                                 mctp_ctrl_objpath,
                                 MCTP_CTRL_DBUS_EP_INTERFACE,
                                 mctp_ctrl_endpoint_vtable,
                                 context);

        MCTP_CTRL_TRACE("Registering object '%s' for UUID: %d\n",
                                            mctp_ctrl_objpath, entry->eid);
        r = sd_bus_add_object_vtable(context->bus,
                                 NULL,
                                 mctp_ctrl_objpath,
                                 MCTP_CTRL_DBUS_UUID_INTERFACE,
                                 mctp_ctrl_common_uuid_vtable,
                                 context);
        if (r < 0) {
            MCTP_CTRL_ERR("Failed to issue method call: %s\n", strerror(-r));
            goto finish;
        }

        /* Increment for next entry */
        entry = entry->next;
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