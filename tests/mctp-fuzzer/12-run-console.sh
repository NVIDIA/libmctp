#!/bin/bash

# Use this script to run docker console in user normal mode or privileged
# Priviliged mode is required to test any sdbus functionality
# It is usefull for debug purposes or to prepare code coverage report

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")
PROJ_PATH=$(dirname "${SCRIPT_PATH}")

echo "Project path: ${PROJ_PATH}"

pushd ${SCRIPT_PATH} &> /dev/null

source 00-projdefs.sh
source 01-common.sh

cleanup_containers

docker run \
    --interactive --net=host --tty --rm --privileged \
    --volume "${PROJ_PATH}:${PROJ_PATH}" \
    --volume "/dev:/dev" \
    --workdir ${PROJ_PATH}/${WORK_DIR}/ \
    --user="${USER}" \
    --volume /run/user/$(id -u)/bus:/run/user/$(id -u)/bus \
    --env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus" \
    ${IMAGE} \
    /bin/bash

popd &> /dev/null

# Settings to support sdbus
#    --privileged \
#    --user="${USER}" \
#    -v /run/user/$(id -u)/bus:/run/user/$(id -u)/bus \
#    -e DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus" \
#
#    User mode also requires using sd_bus_open_user function
#
# Similar settings are required for root user.
#    --privileged \
#    --user="root" \
#    -v /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket \
#    -e DBUS_SYSTEM_BUS_ADDRESS="unix:path=/var/run/dbus/system_bus_socket" \
#
#    Root mode requires sd_bus_default_system function
# However, it is for some reason not working properly, as still,
#  there is some issue with access denied while requesting dbus name