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
#include "fsdyn-endpoint.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <string.h>
#include <limits.h>
#include <json-c/json_util.h>
#include <ctype.h>

// Item entry
typedef struct items_list {
	fsdyn_ep_config_t *ptr;
	size_t size;
} items_list_t;

// Internal fsdyn context
struct fsdyn_ep_context {
	int inotify_fd;
	int watched_fd;
	const char *filename;
	const char *path;
	const char *root_node;
	char inotify_buf[4096]
		__attribute__((aligned(__alignof__(struct inotify_event))));
	fsdyn_ep_ops_t fops;
	items_list_t prev;
};

static int uuid_from_str(const char *input, guid_t *uuid)
{
	int i;
	const char *cp;
	char buf[3];

	const int uuid_len = 36;
	const int uuid_sep_low_pos = 8;
	const int uuid_sep_mid_pos = 13;
	const int uuid_sep_seq_pos = 18;
	const int uuid_sep_node_pos = 23;
	const int uuid_node_num_parts = 6;

	if (strlen(input) != (size_t)uuid_len)
		return -1;
	for (i = 0, cp = input; i <= uuid_len; i++, cp++) {
		if ((i == uuid_sep_low_pos) || (i == uuid_sep_mid_pos) ||
		    (i == uuid_sep_seq_pos) || (i == uuid_sep_node_pos)) {
			if (*cp == '-')
				continue;
			else
				return -1;
		}
		if (i == uuid_len)
			if (*cp == '\0')
				continue;
		if (!isxdigit(*cp))
			return -1;
	}
	uuid->canonical.data0 = htobe32(strtoul(input, NULL, 16));
	uuid->canonical.data1 =
		htobe16(strtoul(input + uuid_sep_low_pos + 1, NULL, 16));
	uuid->canonical.data2 =
		htobe16(strtoul(input + uuid_sep_mid_pos + 1, NULL, 16));
	uuid->canonical.data3 =
		htobe16(strtoul(input + uuid_sep_seq_pos + 1, NULL, 16));
	cp = input + uuid_sep_node_pos + 1;
	buf[2] = 0;
	for (i = 0; i < uuid_node_num_parts; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		uuid->canonical.data4[i] = strtoul(buf, NULL, 16);
	}
	return 0;
}

// Key comparator for sort by EUID
static int key_compare_by_euid(const void *obj1, const void *obj2)
{
	const int result_lower_than = -1;
	const int result_equal = 0;
	const int result_greater_than = 1;
	if (!obj1) {
		return result_lower_than;
	}
	if (!obj2) {
		return result_greater_than;
	}
	json_object *const *j1 = (json_object *const *)obj1;
	json_object *const *j2 = (json_object *const *)obj2;
	if (!*j1 && !*j2) {
		return result_equal;
	}
	if (!*j1) {
		return result_lower_than;
	}
	if (!*j2) {
		return result_greater_than;
	}
	json_object *eid1, *eid2;
	int i1, i2;
	if (json_object_object_get_ex(*j1, "eid", &eid1)) {
		i1 = json_object_get_int(eid1);
	} else {
		return result_lower_than;
	}
	if (json_object_object_get_ex(*j2, "eid", &eid2)) {
		i2 = json_object_get_int(eid2);
	} else {
		return result_greater_than;
	}
	return i1 - i2;
}

// Parse json and generate file
static int create_ep_list_from_json(items_list_t *entry, const char *filename,
				    const char *root_node)
{
	if (!entry)
		return fsdyn_status_error_args;
	// Try to open the files
	const json_object *jdoc = json_object_from_file(filename);
	if (!jdoc) {
		return fsdyn_status_error_parse;
	}
	json_object *jroot, *jendps;
	if (!json_object_object_get_ex(jdoc, root_node, &jroot))
		return fsdyn_status_error_parse;
	if (!json_object_object_get_ex(jroot, "endpoints", &jendps))
		return fsdyn_status_error_parse;
	json_object_array_sort(jendps, key_compare_by_euid);
	const int eps_count = json_object_array_length(jendps);
	if (eps_count <= 0)
		return fsdyn_status_error_array_size;
	entry->ptr = calloc(eps_count, sizeof(fsdyn_ep_config_t));
	if (!entry->ptr)
		return fsdyn_status_system_error;
	int itr = 0;
	for (int c = 0; c < eps_count; ++c) {
		json_object *it;
		fsdyn_ep_config_t item;
		const json_object *ep = json_object_array_get_idx(jendps, c);
		if (json_object_object_get_ex(ep, "eid", &it)) {
			item.eid = json_object_get_int(it);
		} else {
			return fsdyn_status_error_parse;
		}
		if (json_object_object_get_ex(ep, "mctp_type", &it)) {
			memset(item.data, 0, sizeof item.data);
			if (json_object_is_type(it, json_type_int)) {
				item.data[0] = json_object_get_int(it);
				item.data_size = 1;
			} else if (json_object_is_type(it, json_type_array)) {
				item.data_size = json_object_array_length(it);
				if (item.data_size < 0 ||
				    item.data_size > MCTP_MSG_TYPE_MAX_SIZE) {
					continue;
				}
				for (int dc = 0; dc < item.data_size; ++dc) {
					json_object *arr_it =
						json_object_array_get_idx(it,
									  dc);
					if (!arr_it) {
						memset(item.data, 0,
						       sizeof item.data);
						item.data_size = 0;
						break;
					}
					item.data[dc] =
						json_object_get_int(arr_it);
				}
			}
		} else {
			return fsdyn_status_error_parse;
		}
		if (json_object_object_get_ex(ep, "uuid", &it)) {
			const char *uuids = json_object_get_string(it);
			item.has_uuid = (uuid_from_str(uuids, &item.uuid) == 0);
		}
		entry->ptr[itr++] = item;
	}
	entry->size = itr;
	return fsdyn_status_success;
}

// Destroy Ep list
static void destroy_ep_list_from_json(items_list_t *entry)
{
	free(entry->ptr);
	entry->size = 0;
	entry->ptr = NULL;
}

// Compare with previous sorted list and trigger change if needed
static int compare_with_previous_list(const items_list_t *prev,
				      const items_list_t *curr,
				      const fsdyn_ep_ops_t *fops)
{
	int ret = fsdyn_status_unmodified;
	size_t i = 0, j = 0;
	while (i < prev->size && j < curr->size) {
		const int a1 = prev->ptr[i].eid;
		const int a2 = curr->ptr[j].eid;
		if (a1 < a2) {
			const fsdyn_ep_config_t *it1 = &prev->ptr[i];
			fops->remove(it1);
			i++;
			ret = fsdyn_status_modified;
		} else if (a2 < a1) {
			const fsdyn_ep_config_t *it2 = &curr->ptr[j];
			fops->add(it2);
			j++;
			ret = fsdyn_status_modified;
		} else {
			// Compare struct if same key
			const fsdyn_ep_config_t *it1 = &prev->ptr[i];
			const fsdyn_ep_config_t *it2 = &curr->ptr[j];
			if (memcmp(it1, it2, sizeof(fsdyn_ep_config_t))) {
				fops->remove(it1);
				fops->add(it2);
				ret = fsdyn_status_modified;
			}
			i++;
			j++;
		}
	}
	while (i < prev->size) {
		const fsdyn_ep_config_t *it1 = &prev->ptr[i];
		fops->remove(it1);
		ret = fsdyn_status_modified;
		i++;
	}
	while (j < curr->size) {
		const fsdyn_ep_config_t *it2 = &curr->ptr[j];
		fops->add(it2);
		ret = fsdyn_status_modified;
		j++;
	}
	return ret;
}

// File is modified modify ep list
static int modify_endpoints(fsdyn_ep_context_ptr ctx)
{
	items_list_t entry;
	int ret = fsdyn_status_unmodified;
	if (create_ep_list_from_json(&entry, ctx->path, ctx->root_node) ==
	    fsdyn_status_success) {
		if (ctx->prev.size > 0) {
			ret = compare_with_previous_list(&ctx->prev, &entry,
							 &ctx->fops);
			destroy_ep_list_from_json(&ctx->prev);
			ctx->prev = entry;
		} else {
			for (size_t i = 0; i < entry.size; ++i) {
				ctx->fops.add(&entry.ptr[i]);
			}
			ctx->prev = entry;
			ret = fsdyn_status_modified;
		}
	}
	return ret;
}

// File is deleted delete all endpoints
static void delete_endpoints(fsdyn_ep_context_ptr ctx)
{
	for (size_t i = 0; i < ctx->prev.size; ++i) {
		ctx->fops.remove(&ctx->prev.ptr[i]);
	}
	destroy_ep_list_from_json(&ctx->prev);
}

// Notify for all edpoints for ex newlist
static void notify_all_endpoints(fsdyn_ep_context_ptr ctx)
{
	for (size_t i = 0; i < ctx->prev.size; ++i) {
		ctx->fops.add(&ctx->prev.ptr[i]);
	}
}

// Start monitoring
fsdyn_ep_context_ptr fsdyn_ep_mon_start(const char *directory, const char *file,
					const char *json_root_node,
					const fsdyn_ep_ops_t *dyn_ops)

{
	if (!directory || !file || !dyn_ops || !dyn_ops->add ||
	    !dyn_ops->remove) {
		errno = EINVAL;
		return NULL;
	}
	fsdyn_ep_context_ptr ctx = NULL;
	bool cleanup = true;
	do {
		ctx = calloc(1, sizeof(struct fsdyn_ep_context));
		if (!ctx)
			break;
		ctx->filename = strndup(file, PATH_MAX);
		if (!ctx->filename)
			break;
		ctx->path = calloc(1, PATH_MAX + 2);
		ctx->root_node = strndup(json_root_node, PATH_MAX);
		strncpy((char *)ctx->path, directory, PATH_MAX + 1);
		strncat((char *)ctx->path, "/", PATH_MAX + 1);
		strncat((char *)ctx->path, ctx->filename, PATH_MAX + 1);
		ctx->inotify_fd = inotify_init();
		if (!ctx->inotify_fd)
			break;
		ctx->watched_fd = inotify_add_watch(ctx->inotify_fd, directory,
						    IN_CLOSE_WRITE | IN_DELETE);
		if (!ctx->watched_fd)
			break;
		ctx->fops = *dyn_ops;
		if (create_ep_list_from_json(&ctx->prev, ctx->path,
					     ctx->root_node) ==
		    fsdyn_status_success)
			notify_all_endpoints(ctx);
		cleanup = false;

	} while (0);
	if (cleanup) {
		if (ctx->filename)
			free((void *)ctx->filename);
		if (ctx->path)
			free((void *)ctx->path);
		if (ctx->root_node)
			free((void *)ctx->root_node);
		if (ctx->watched_fd)
			close(ctx->watched_fd);
		if (ctx->inotify_fd)
			close(ctx->inotify_fd);
		free(ctx);
		ctx = NULL;
	}

	return ctx;
}

// Get monitoring fd
int fsdyn_ep_get_fd(const fsdyn_ep_context_ptr ctx)
{
	return ctx ? ctx->inotify_fd : -EINVAL;
}

// Stop monitoring deinitalizing all structures
int fsdyn_ep_mon_stop(fsdyn_ep_context_ptr ctx)
{
	if (!ctx)
		return -EINVAL;
	close(ctx->inotify_fd);
	free((void *)ctx->filename);
	free((void *)ctx->path);
	free((void *)ctx->root_node);
	destroy_ep_list_from_json(&ctx->prev);
	free(ctx);
	ctx = NULL;
	return 0;
}

// Read events on the poll ev
int fsdyn_ep_poll_handler(fsdyn_ep_context_ptr ctx)
{
	if (!ctx)
		return -EINVAL;
	ssize_t len = read(ctx->inotify_fd, ctx->inotify_buf,
			   sizeof(ctx->inotify_buf));
	if (len <= 0)
		return len;
	const struct inotify_event *ev;
	int ret = fsdyn_status_unmodified;
	for (char *ptr = ctx->inotify_buf; ptr < ctx->inotify_buf + len;
	     ptr += sizeof(struct inotify_event) + ev->len) {
		ev = (const struct inotify_event *)ptr;
		if (!strcmp(ev->name, ctx->filename) &&
		    !(ev->mask & IN_ISDIR)) {
			if (ev->mask & IN_CLOSE_WRITE) {
				ret = modify_endpoints(ctx);
			}
			if (ev->mask & IN_DELETE) {
				delete_endpoints(ctx);
				ret = fsdyn_status_modified;
			}
		}
	}
	return ret;
}
