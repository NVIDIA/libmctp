# Demux demon Fuzz tests and UT require mocked drivers being insmod in the system.
# Compilation and insmod operation are performed by meson during configuration phase,
#  in this case ninja is not required.
BUILD_COMMAND="rm -rf builddir-drivers && meson builddir-drivers --wrap-mode nodownload -Dmocked-drivers=enabled"

IMAGE=afl:mctp-drivers
CONTAINER=afl-mctp-drivers-container

PROJECT_NAME="libmctp"
