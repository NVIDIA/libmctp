# Unit-Testing — A/B Security Regressions

A/B (before/after) unit tests for the 10 retained Glasswing security findings.
Each test drives the **real** fixed function with the exact
malformed/adversarial input from the finding, and is two-sided:

> **Core-26.05 port note (2026-07-01):** all fixed legs were cross-compiled
> with the hgxb300 ARM toolchain and run successfully under the Yocto QEMU
> wrapper. All embedded per-finding PASS/FAIL output below was produced on the
> original Core-24.09 branch and was not regenerated for this port. V8.1 is a
> special case: Core-26.05's later compound-literal initialization already
> zeroes the USB binding before callback registration, so its fixed-leg test is
> only an invariant/config-pointer API smoke test; the original load-bearing
> A/B fault is specific to the Core-24.09 implementation and its stubbed
> callback run.

- **A — fixed tree:** the test **passes** (`EXIT=0`) — the guard/fix rejects the input.
- **B — fix reverted:** the same test **faults** — AddressSanitizer abort (`EXIT=1`)
  or an assertion abort (`EXIT=134`). This half is the proof: it shows the test
  reaches the real defect and the fix is load-bearing, not merely that the code
  compiles.

The original Core-24.09 PASS and FAIL output for every finding is embedded
per-ID in [A/B evidence](#ab-evidence). (Memory-pool debug spam — `Size
requested greated than maximum pool buffer size` / `Defaulting to backup free`
— is elided for readability.)

## How to run / reproduce

All commands run from the repo root (`sources/libmctp`); a `config.h` is needed
(meson generates one — for a direct gcc build use a 2-line shim), then:

```sh
printf '#ifndef _CONFIG_H\n#define _CONFIG_H\n#endif\n' > config.h   # if not building via meson
export ASAN_OPTIONS=detect_leaks=0
```

- **V1.1, V13.2** are also a meson unit test (`test_security` in `tests/meson.build`):
  `meson setup build -Dtests=enabled -Db_sanitize=address && meson test -C build test_security`.
- The other eight are **standalone** source-compile tests (they reach `static`
  functions / private structs / symbols in the ctrld, vdm-util, mctp-socket and
  demux binaries, or the build-disabled mctp-tun module, so they can't link
  `libmctp` like the meson suite). Their exact compiler/linker inputs depend on
  the branch and sysroot; some header comments retain historical Core-24.09
  commands, but they are not a complete Core-26.05 runner. Dependencies include
  `systemd`, `json-c`, and `libusb`; `stubs_{ctrld,demux}.c` are inert link
  scaffolding.

To reproduce the **B (reverted)** leg, reverse-apply only that finding's fix hunk
into a scratch copy and rebuild the same test against it (never modify the real
source); the fix commit is `git log --grep <nvbug-id>`. Example for V1.1:

```sh
sed '/ctx->buf = NULL;/d; /ctx->buf_alloc_size = 0;/d' core.c > /tmp/core_prefix.c
gcc -g -O1 -fsanitize=address -I. -Itests tests/test_security.c /tmp/core_prefix.c alloc.c log.c -o /tmp/t
ASAN_OPTIONS=detect_leaks=0 /tmp/t      # -> heap-use-after-free, abort
```

## A/B evidence

### V1.1 — NVBug 6294880 — CWE-416 — reassembly realloc-fail → use-after-free
**Fixed (PASS):**
```
test: test_v1_1_reassembly_realloc_uaf
test: test_v13_2_bridge_source_filter
All 2 security regression tests passed
EXIT=0
```
**Reverted (FAIL):**
```
==ERROR: AddressSanitizer: heap-use-after-free ... WRITE of size 100
    #2 in mctp_msg_ctx_add_pkt core.c   (reassembly slot-reuse memcpy into freed buf)
0x... is located 0 bytes inside of 4096-byte region [freed]
EXIT=1
```

### V3.1 — NVBug 6294887 — CWE-191 — SMBus len−hdr−PEC size_t underflow → unbounded memcpy
**Fixed (PASS):**
```
smbus: SMBus frame too short: len=4
V3.1 security regression test passed
EXIT=0
```
**Reverted (FAIL):**  (`4 - 4 - 1` = SIZE_MAX)
```
==ERROR: AddressSanitizer: negative-size-param: (size=-1)
    in __interceptor_memcpy <- mctp_pktbuf_push <- mctp_smbus_read
EXIT=1
```

### V8.1 — NVBug 6295077 — CWE-824 — unzeroed USB binding; ENUMERATE hotplug derefs uninit bus ptr
**Fixed (PASS):**  (ENUMERATE callback fires during init; memset made the pointers NULL)
```
usb: Device attached: 1234:5678
binding.bus = (nil)
All 1 security regression tests passed
EXIT=0
```
**Reverted (FAIL):**  (0xAA-poisoning allocator; struct left un-zeroed)
```
==ERROR: AddressSanitizer: SEGV on unknown address (high/non-canonical, READ)
    in mctp_usb_hotplug_callback <- mctp_usb_init   (deref of un-zeroed struct field)
EXIT=1
```

### V9.1 — NVBug 6295083 — CWE-191 — demux USB tx_pvt_message off-by-one → SIZE_MAX msg_len → OOB read
**Fixed (PASS):**
```
Packet too short for USB.            (34-byte USB-bind datagram rejected; tx_count == 0)
V9.1 security regression test passed
EXIT=0
```
**Reverted (FAIL):**
```
mctp_message_tx_on_bus: Generating packets for transmission of 18446744073709551615 byte message
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 64
0x... is located 0 bytes to the right of 34-byte region
EXIT=1
```

### V13.2 — NVBug 6295088 — CWE-862 — bridge forwards cross-bus with no source filter
**Fixed (PASS):**  (same binary as V1.1; filter drops the blocked source, forwards the allowed one)
```
test: test_v1_1_reassembly_realloc_uaf
test: test_v13_2_bridge_source_filter
All 2 security regression tests passed
EXIT=0
```
**Reverted (FAIL):**  (filter gate removed — blocked source is forwarded)
```
test_security.c:285: test_v13_2_bridge_source_filter: Assertion `g_filter_calls >= 1' failed.
EXIT=134
```

### V16.1 — NVBug 6295093 — CWE-125 — Get-Routing-Table short response → entry OOB read
**Fixed (PASS):**
```
V16.1 get-routing-table short-response guard: OK
All security regression tests passed (V16.1)
EXIT=0
```
**Reverted (FAIL):**  (length guard removed)
```
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 0 bytes to the right of 3-byte region
EXIT=1
```

### V17.1 — NVBug 6295094 — CWE-125 — Get-UUID short response → 16-byte OOB read
**Fixed (PASS):**
```
V17.1 get-uuid short-response guard: OK
All security regression tests passed (V17.1)
EXIT=0
```
**Reverted (FAIL):**  (length guard removed; UUID copy reads past the buffer)
```
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 0 bytes to the right of 3-byte region
EXIT=1
```

### V20.1 — NVBug 6295098 — CWE-125 — vendor-header parse on short response → command_code OOB read
**Fixed (PASS):**
```
V20.1 security regression test passed (mctp_client_recv_from_eid rejects short vendor responses)
EXIT=0
```
**Reverted (FAIL):**  (command_code read at buffer offset 7)
```
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 3 bytes to the right of 4-byte region
EXIT=1
```

### V21.1 — NVBug 6295100 — CWE-125 — query_boot_status negative tail index on short response → OOB read
**Fixed (PASS):**
```
query_boot_status: short boot-status response (3 bytes)   (3-/7-byte rejected, 8-byte accepted)
V21.1 query_boot_status_json short-response guard: OK
All security regression tests passed (V21.1)
EXIT=0
```
**Reverted (FAIL):**  (is_booted_OK reads resp[resp_len-4] = resp[-1])
```
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 1 bytes to the left of 3-byte region
EXIT=1
```

### V24.1 — NVBug 6295108 — CWE-787 — unclamped TUN frame → heap OOB write
**Fixed (PASS):**
```
V24.1 security regression test passed (tun_read clamps oversized frames)
EXIT=0
```
**Reverted (FAIL):**  (40000-byte payload memcpy'd into the fixed 32828-byte pktbuf)
```
==ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 40000
0x... is located 0 bytes to the right of 32828-byte region
EXIT=1
```

## Verification status

On the Core-26.05 port, the Meson suite (including V1.1/V13.2) passed all eight
tests, and all eight retained standalone fixed-leg binaries (V3.1, V8.1, V9.1,
V16.1, V17.1, V20.1, V21.1, V24.1) were cross-built and passed under the Yocto
QEMU wrapper. The standalone builds used the recipe sysroot's real `json-c`,
`libusb`, and `systemd` dependencies. Original ASan B-leg nuances:
V3.1 reports `negative-size-param` (memcpy rejects the `SIZE_MAX` length);
V8.1 on Core-24.09 prints `SEGV on unknown address` for the high 0xAA poison
pointer; V16.1/V17.1/V21.1 abort at the first below/over-read index, which is
shallower than the deepest one the finding names. Production source is not
modified by any test.

## Files

- `test_v*.c` — one focused test source per standalone finding.
- `stubs_ctrld.c` / `stubs_demux.c` — inert externs so the ctrld / demux TUs link
  in isolation (never executed by the tested paths).

### RS2-25 — NVBug 6519382 — CWE-787 — overlong socket name overflows sun_path (mctp-socket.c / demux)
Test: `tests/security/test_rs2_25.c` drives the real `mctp_usr_socket_init()` (TU include) with a
201-byte abstract socket name (sun_path is 108). Build without `-DMCTP_IN_KERNEL`:
```
gcc -g -O1 -fsanitize=address -I. -Itests tests/security/test_rs2_25.c log.c -lsystemd -o /tmp/t_rs2_25
ASAN_OPTIONS=detect_leaks=0 /tmp/t_rs2_25
```
**Fixed (PASS):**
```
mctp_usr_socket_init() rejected overlong socket name (rc=-1) - no overflow
RS2-25 security regression test passed (mctp_usr_socket_init rejects overlong socket names)
EXIT=0
```
**Reverted (FAIL):** (memcpy of 201 bytes into 108-byte sun_path)
```
*** buffer overflow detected ***: terminated   (SIGABRT, EXIT=134)
```
The identical guard is applied at the demux bind site (`utils/mctp-demux-daemon.c`); same fix, same class.
