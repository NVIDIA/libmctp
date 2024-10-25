/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"

#ifdef MCTP_HAVE_CONFIG_H
#include "config.h"
#endif
/* 65 (4101 bytes / 64 = 64.07, rounded to 65) packets are enqueued to be send */
#define MCTP_POOL_SIZE 65
/* Taking PCIE since it has the maximum medium_header_size
mctp_pktbuf->size = 24 + mctp_pktbuf->data[] = 83
mctp_pktbuf->data[] = medium_header+ mctp_header+ mctp_payload+ mctp_trailer 
medium_header = 12(taking max for pcie) + mctp_header = 4 + mctp_payload = 64
+ mctp_trailer = 3 (taking max for pcie) == 83 */
#define MCTP_PACKET_BUFFER_SIZE 107

struct mctp_memory_pool {
	void *buffers[MCTP_POOL_SIZE];
	bool used[MCTP_POOL_SIZE];
};

static struct mctp_memory_pool *pool = NULL;

void cleanup_mctp_memory_pool(void)
{
	if (pool == NULL) {
		return;
	}
	for (int i = 0; i < MCTP_POOL_SIZE; i++) {
		free(pool->buffers[i]);
	}

	free(pool);
	pool = NULL;
}

bool init_mctp_memory_pool(void)
{
	pool = malloc(sizeof(struct mctp_memory_pool));
	if (pool == NULL) {
		mctp_prerr("Failed to init memory pool");
		return false;
	}

	memset(pool, 0, sizeof(struct mctp_memory_pool));

	for (int i = 0; i < MCTP_POOL_SIZE; i++) {
		pool->buffers[i] = malloc(MCTP_PACKET_BUFFER_SIZE);
		if (pool->buffers[i] == NULL) {
			mctp_prerr(
				"Failed to alloc pool buffers, cleaning up allocated resources");
			//Prevent memory leak, freeing all allocated resources upon failure
			cleanup_mctp_memory_pool();
			return false;
		}
	}
	return true;
}

void *__mctp_alloc_pool(size_t size)
{
	if (pool == NULL) {
		if (!init_mctp_memory_pool()) {
			return NULL;
		}
	}

	if (size > MCTP_PACKET_BUFFER_SIZE) {
		mctp_prerr(
			"Size requested greated than maximum pool buffer size");
		return malloc(size);
	}

	for (int i = 0; i < MCTP_POOL_SIZE; i++) {
		if (!pool->used[i]) {
			pool->used[i] = true;
			return pool->buffers[i];
		}
	}
	//Defaulting to backup malloc
	mctp_prinfo("Defaulting to backup malloc");
	return malloc(size);
}

void __mctp_free_pool(void *ptr)
{
	if (ptr == NULL) {
		return;
	}
	if (pool == NULL) {
		free(ptr);
		return;
	}

	for (int i = 0; i < MCTP_POOL_SIZE; i++) {
		if (ptr == pool->buffers[i]) {
			if (pool->used[i]) {
				pool->used[i] = false;
			} else {
				mctp_prerr(
					"Attempt to pool free an unallocated pointer");
			}
			return;
		}
	}
	//Defaulting to backup free
	mctp_prinfo("Defaulting to backup free");
	free(ptr);
}

struct {
	void *(*m_alloc)(size_t);
	void (*m_free)(void *);
	void *(*m_realloc)(void *, size_t);
} alloc_ops = {
	malloc,
	free,
	realloc,
};

/* internal-only allocation functions */
void *__mctp_alloc(size_t size)
{
	if (alloc_ops.m_alloc)
		return alloc_ops.m_alloc(size);
	if (alloc_ops.m_realloc)
		return alloc_ops.m_realloc(NULL, size);
	assert(0);
	return NULL;
}

void __mctp_free(void *ptr)
{
	if (alloc_ops.m_free)
		alloc_ops.m_free(ptr);
	else if (alloc_ops.m_realloc)
		alloc_ops.m_realloc(ptr, 0);
	else
		assert(0);
}

void *__mctp_realloc(void *ptr, size_t size)
{
	if (alloc_ops.m_realloc)
		return alloc_ops.m_realloc(ptr, size);
	assert(0);
	return NULL;
}

void mctp_set_alloc_ops(void *(*m_alloc)(size_t), void (*m_free)(void *),
			void *(m_realloc)(void *, size_t))
{
	alloc_ops.m_alloc = m_alloc;
	alloc_ops.m_free = m_free;
	alloc_ops.m_realloc = m_realloc;
}
