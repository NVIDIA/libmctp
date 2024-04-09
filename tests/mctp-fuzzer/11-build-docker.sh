#!/bin/bash

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")

pushd ${SCRIPT_PATH} &> /dev/null

source 00-projdefs.sh
source 01-common.sh

cleanup_containers

BUILD_ARGS=" \
    --build-arg UNAME=${USER} \
    --build-arg UID=$(id -u) \
    --build-arg GID=$(id -g)"

unset DELETE_IMAGE
unset REBUILD_IMAGE

for ARG in "$@"; do
    if [[ "${ARG}" == "-d" ]]; then
        DELETE_IMAGE=1
    fi
    if [[ "${ARG}" == "-r" ]]; then
        BUILD_IMAGE=1
    fi
done

# check if image exists
if [ "$( docker images --quiet ${IMAGE} )" ]; then
    echo "Image exists. Stopping all related containers."
    # check if any containers are started
    if [ "$( docker ps --quiet --filter name=${CONTAINER} )" ]; then
        docker rm --force ${CONTAINER}
    fi

    if [[ x"${DELETE_IMAGE}" == x"1" ]]; then
        echo "Deleting image."
        docker image rm --force ${IMAGE}
    fi
else
    BUILD_IMAGE=1
fi

if [[ x"${BUILD_IMAGE}" == x"1" ]]; then
    echo "Building image."
    docker buildx build ${BUILD_ARGS} -t ${IMAGE} -f ${SCRIPT_PATH}/Dockerfile ${PROJ_PATH}
fi

popd &> /dev/null
