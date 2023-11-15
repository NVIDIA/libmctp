#pragma once

#include <stdio.h>
#include <stdbool.h>
#include "mctp-ctrl-cmds.h"

//! Dynamic EP config
typedef struct fsdyn_ep_config {
	unsigned char eid;
	unsigned char data[MCTP_MSG_TYPE_MAX_SIZE];
	int data_size;
	guid_t uuid;
	bool has_uuid;
} fsdyn_ep_config_t;

//! Event operation on file monitoring
typedef struct fsdyn_ep_ops {
	void (*add)(const fsdyn_ep_config_t *cfg);
	void (*remove)(const fsdyn_ep_config_t *cfg);
} fsdyn_ep_ops_t;

// Private dynamic context
struct fsdyn_ep_context;
typedef struct fsdyn_ep_context *fsdyn_ep_context_ptr;

enum fsdyn_status {
	fsdyn_status_unmodified = 0, // Content not changed
	fsdyn_status_success = 0, // Sucess
	fsdyn_status_modified = 1, // Content modified
	fsdyn_status_system_error = -1, // Content error
	fsdyn_status_error_args = -2, // Argument parse error
	fsdyn_status_error_parse = -3, // Parse error
	fsdyn_status_error_array_size = -4, // Array size error
};

/**
 * @brief Start filesystem monitoring for dynamic ep configuration
 *
 * @param directory Directory to be monitored
 * @param file  File to be monitored
 * @param json_root_node Root node name with data
 * @param dyn_ops Dynamic operation on add or remove
 * @return fsdyn_ep_context_ptr Module context
 */
fsdyn_ep_context_ptr fsdyn_ep_mon_start(const char *directory, const char *file,
					const char *json_root_node,
					const fsdyn_ep_ops_t *dyn_ops);

/**
 * @brief Handle library data on the monitor event
 *
 * @param ctx Fsdyn context
 * @return int see @fsdyn_status
 */
int fsdyn_ep_poll_handler(fsdyn_ep_context_ptr ctx);

/**
 * @brief  Get the FD for montoring
 *
 * @param ctx Fsdyn context
 * @return int File descriptor or error code
 */
int fsdyn_ep_get_fd(const fsdyn_ep_context_ptr ctx);

/**
 * @brief Stop monitoring deallocate resources
 *
 * @param ctx Fsdyn context
 * @return int Error code
 */
int fsdyn_ep_mon_stop(fsdyn_ep_context_ptr ctx);
