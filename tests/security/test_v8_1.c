/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * V8.1 (NVBug 6295077, CWE-824) security regression test  --  usb.c
 *
 * Core-26.05 port note: this branch's mctp_usb_init() also assigns a zero-
 * initialized compound literal before registering the hotplug callback. That
 * refactor already preserves the invariant tested here even if the explicit
 * memset is removed. On this base the fixed-leg test is therefore an API and
 * invariant smoke test, not a load-bearing regression test. It links the
 * recipe's real libusb and does not force or instrument a hotplug callback.
 * The original A/B fault evidence below applies only to the Core-24.09
 * implementation, where the compound-literal assignment was not present.
 *
 * Finding
 * -------
 * mctp_usb_init() allocated `struct mctp_binding_usb` with __mctp_alloc()
 * (plain malloc) and never zeroed it, so binding.bus / binding.mctp held
 * uninitialised heap until mctp_register_bus() ran later. The hotplug callback
 * is registered with LIBUSB_HOTPLUG_ENUMERATE, which makes libusb invoke
 * mctp_usb_hotplug_callback() for an already-attached matching device *during
 * registration* -- i.e. before the bus is registered. That callback reads
 * base_usb->bus (`if (base_usb->bus) bus_reg = true;`) and, on DEVICE_ARRIVED,
 * calls mctp_binding_set_tx_enabled(base_usb, true) when bus_reg is set;
 * mctp_binding_set_tx_enabled() begins with
 *     struct mctp_bus *bus = binding->bus; switch (bus->state) ...
 * -- a read through (and potential write to) the garbage pointer (CWE-824).
 *
 * Fix
 * ---
 * NULL-check the allocation and memset(usb, 0, sizeof(*usb)) immediately after
 * it, so binding.bus / binding.mctp are deterministically NULL until
 * mctp_register_bus() sets them; the ENUMERATE callback then takes the
 * `if (base_usb->bus)` false branch and never dereferences a wild pointer.
 *
 * Original Core-24.09 A/B method (provenance)
 * -------------------------------------------
 * The original validation used a scratch libusb stub that synchronously
 * injected the ENUMERATE callback and a poisoning allocator that filled fresh
 * allocations with 0xAA. With the fix, initialization made binding.bus and
 * binding.mctp NULL; with only the memset reverted, the callback dereferenced
 * poisoned state and AddressSanitizer faulted. Those scratch `.sec-v8_1`
 * fixtures are not carried in this branch; the embedded A/B output in
 * UNIT-TESTING-AB-REGRESSIONS.md is retained as Core-24.09 evidence.
 *
 * The Core-26.05 fixed leg below drives the real mctp_usb_init() through its
 * config-pointer API with the recipe's libusb, poisons the allocation, and
 * checks the resulting binding invariant. No matching-device or callback
 * occurrence is asserted, and reverting only the explicit memset is not
 * expected to fail on this base because the later whole-struct assignment
 * independently zeroes omitted members.
 */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libmctp.h>
#include <libmctp-alloc.h>
#include <libmctp-log.h>
#include <libmctp-usb.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* ------------------------------------------------------------------ */
/* Poisoning allocator: model uninitialised heap deterministically.   */
/* Fresh allocations come back filled with 0xAA so an un-zeroed struct */
/* has a garbage (non-NULL) binding.bus, exactly the pre-fix hazard.   */
/* ------------------------------------------------------------------ */

static void *poison_alloc(size_t n)
{
	void *p = malloc(n);
	if (p)
		memset(p, 0xAA, n);
	return p;
}

static void poison_free(void *p)
{
	free(p);
}

static void *poison_realloc(void *p, size_t n)
{
	/* Not exercised by this path, but keep it consistent: a *growth*
	 * leaves the tail uninitialised, which we approximate with poison. */
	return realloc(p, n);
}

/* ------------------------------------------------------------------ */
/* V8.1: mctp_usb_init() must zero the binding before the ENUMERATE    */
/* hotplug callback can fire.                                          */
/* ------------------------------------------------------------------ */

static void test_v8_1_usb_init_zeroes_binding(void)
{
	struct mctp_binding_usb *usb;
	struct mctp_binding *base;
	mctp_usb_dev_cfg_t cfg = {
		.mode = MCTP_USB_BATCH_NONE,
		.bus_id = 1,
		.port_path = "1",
	};

	/* Route libmctp's internal allocator through the poisoning ops so this
	 * verifies that initialization, rather than allocator contents, establishes
	 * the NULL binding pointers. */
	mctp_set_alloc_ops(poison_alloc, poison_free, poison_realloc);

	/* Core-26.05 selects a USB device by bus/port configuration rather than
	 * the older vendor/product/class tuple. */
	usb = mctp_usb_init(&cfg);

	/* This smoke check asserts the post-initialization invariant only; it does
	 * not claim that libusb invoked the hotplug callback during this run. */
	assert(usb != NULL);

	base = mctp_binding_usb_core(usb);
	assert(base != NULL);
	assert(base->bus == NULL);  /* deterministically NULL post-fix */
	assert(base->mctp == NULL); /* same invariant for binding.mctp  */

	printf("  binding.bus = %p (expected NULL), binding.mctp = %p\n",
	       (void *)base->bus, (void *)base->mctp);

	/* Note: we intentionally do not mctp_destroy()/free here -- there is no
	 * public teardown for a usb binding that was never registered, and the
	 * process exits immediately after the suite. Leaks are irrelevant to
	 * the UB being tested (run with ASAN_OPTIONS=detect_leaks=0). */
	mctp_set_alloc_ops(malloc, free, realloc); /* restore default ops */
}

/* ------------------------------------------------------------------ */

/* clang-format off */
#define TEST_CASE(t) { #t, t }
static const struct {
	const char *name;
	void (*test)(void);
} security_tests[] = {
	TEST_CASE(test_v8_1_usb_init_zeroes_binding),
};
/* clang-format on */

int main(void)
{
	size_t i;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	for (i = 0; i < ARRAY_SIZE(security_tests); i++) {
		printf("test: %s\n", security_tests[i].name);
		security_tests[i].test();
	}

	printf("All %zu security regression tests passed\n",
	       ARRAY_SIZE(security_tests));
	return EXIT_SUCCESS;
}
