BUILD_COMMAND="meson builddir --wrap-mode nodownload -Dtests=disabled -Denable-fuzzctrl=enabled -Dprefix=/usr/local && ninja -C builddir"

WORK_DIR="builddir/ctrld"
FUZZ_EXEC="mctp-ctrl"

HOST_PREPARATION_COMMAND=""
DOCKER_PREPARATION_COMMAND=""
