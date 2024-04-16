#!/bin/bash

# Use this script to run docker console in full privileged mode
# It is usefull to work with kernel modules from inside a docker
# To work with insmod it is mandatory to add to docker run:
#    --security-opt seccomp=unconfined \
#    --privileged \
#    --cap-add=CAP_SYS_MODULE \
# The above security opts allows to init kernel modules inside docker
# Also root user is mandatory

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")
PROJ_PATH=$(dirname "${SCRIPT_PATH}")

echo "Project path: ${PROJ_PATH}"

pushd ${SCRIPT_PATH} &> /dev/null

source 01-common.sh
source 04-projdefs-drivers.sh

cleanup_containers

docker run \
    --interactive --net=host --tty --rm --privileged \
    --security-opt seccomp=unconfined \
    --user="root" \
    --volume "${PROJ_PATH}:${PROJ_PATH}" \
    --volume "/dev:/dev" \
    --workdir ${PROJ_PATH}/${WORK_DIR}/ \
    ${IMAGE} \
    /bin/bash

popd &> /dev/null
