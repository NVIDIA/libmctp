ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmctp.la
libmctp_la_SOURCES = core.c alloc.c log.c \
		     libmctp-alloc.h libmctp-log.h \
		     libmctp-cmds.h
include_HEADERS = libmctp.h

if LIBMCTP_BINDING_serial
libmctp_la_SOURCES += serial.c
include_HEADERS += libmctp-serial.h
endif

if LIBMCTP_BINDING_astlpc
libmctp_la_SOURCES += astlpc.c crc32.c
include_HEADERS += libmctp-astlpc.h
endif

if LIBMCTP_BINDING_astpcie
libmctp_la_SOURCES += astpcie.c
include_HEADERS += libmctp-astpcie.h
endif

if LIBMCTP_BINDING_astspi
libmctp_la_SOURCES += astspi.c
libmctp_la_SOURCES += glacier-spb-ap.c
include_HEADERS += libmctp-astspi.h
include_HEADERS += glacier-spb-ap.h
endif

if LIBMCTP_BINDING_smbus
libmctp_la_SOURCES += smbus.c
include_HEADERS += libmctp-smbus.h
endif

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	systemd/system/mctp-pcie-demux.service \
	systemd/system/mctp-pcie-demux.socket \
	systemd/system/mctp-spi-demux.service \
	systemd/system/mctp-spi-demux.socket \
	systemd/system/mctp-i2c-demux.service \
	systemd/system/mctp-i2c-demux.socket \
	systemd/system/mctp-pcie-ctrl.service \
	systemd/system/mctp-spi-ctrl.service \
	systemd/system/mctp-i2c-ctrl.service
endif

bin_PROGRAMS = utils/mctp-demux-daemon ctrld/mctp-ctrl vdm/nvidia/mctp-vdm-util
noinst_PROGRAMS = utils/mctp-in utils/mctp-pipe

utils_mctp_demux_daemon_LDFLAGS = "-ljson-c"
utils_mctp_demux_daemon_SOURCES = utils/mctp-demux-daemon.c \
                    mctp-json.c
if HAVE_PCAP
utils_mctp_demux_daemon_SOURCES += utils/mctp-capture.c
endif
utils_mctp_demux_daemon_LDADD = libmctp.la $(pcap_LIBS)
utils_mctp_demux_daemon_CFLAGS = $(pcap_CFLAGS)

ctrld_mctp_ctrl_LDFLAGS = "-lsystemd -lpthread -ljson-c"

ctrld_mctp_ctrl_SOURCES = ctrld/mctp-ctrl.c \
                    ctrld/mctp-discovery-common.c \
                    ctrld/mctp-discovery.c \
                    mctp-socket.c \
                    mctp-json.c \
                    dbus_log_event.c \
                    ctrld/mctp-encode.c \
                    ctrld/mctp-sdbus.c \
                    ctrld/mctp-spi-cmds.c \
                    ctrld/mctp-ctrl-spi.c \
                    ctrld/mctp-discovery-i2c.c \
                    vdm/nvidia/mctp-vdm-commands.c \
                    vdm/nvidia/mctp-vdm-encode.c

vdm_nvidia_mctp_vdm_util_LDFLAGS = "-lsystemd"

vdm_nvidia_mctp_vdm_util_SOURCES = vdm/nvidia/mctp-vdm-nvda.c \
                    mctp-socket.c \
                    vdm/nvidia/mctp-vdm-commands.c \
                    vdm/nvidia/mctp-vdm-encode.c

pkgconfig_DATA = libmctp.pc

if LIBMCTP_UDEV_RAW_KCS
udevrules_DATA = udev/rules.d/mctp0-raw-kcs3.rules \
		 udev/rules.d/mctp0-raw-kcs4.rules
endif

dist_bin_SCRIPTS = mctp-pcie-ctrl mctp-spi-ctrl mctp-i2c-ctrl

if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = -Wall $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

TESTS = $(check_PROGRAMS)

check_PROGRAMS = tests/test_eid tests/test_seq tests/test_bridge \
		 tests/test_astlpc tests/test_serial tests/test_cmds \
		 tests/test_core
# We set a global LDADD here, as there's no way to specify it for all
# tests. This means other targets' LDADDs need to be overridden.
LDADD = tests/libtest-utils.a libmctp.la

noinst_LIBRARIES = tests/libtest-utils.a

tests_libtest_utils_a_SOURCES = tests/test-utils.c tests/test-utils.h

@VALGRIND_CHECK_RULES@
