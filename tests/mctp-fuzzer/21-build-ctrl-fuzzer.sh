#!/bin/bash

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")

pushd ${SCRIPT_PATH} &> /dev/null

source 00-projdefs.sh
source 01-common.sh
source 02-projdefs-ctrl.sh

cleanup_containers

rm -rf ${PROJ_PATH}/builddir

CXXFLAGS=${CXXFLAGS:-"-std=c++20"}
CC=${CC:-"afl-gcc"}
CXX=${CXX:-"afl-g++"}
# those flags are required for code coverage
# Comment it out for TSAN sanitizer enabled
# For some reason coverage does not like with TSAN and opposite
CFLAGS="-fprofile-arcs -ftest-coverage"
LDFLAGS=${LDFLAGS:-"-lgcov"}

DOCKER_ENV=""
for ARG in "$@"; do
    DOCKER_ENV="${DOCKER_ENV} --env ${ARG}"
done

echo "Added DOCKER ENV: ${DOCKER_ENV}"

docker run \
    --interactive --net=host --privileged --tty \
    --volume "${PROJ_PATH}:${PROJ_PATH}" \
    --workdir ${PROJ_PATH} \
    --env CXXFLAGS="${CXXFLAGS}" --env CC="${CC}" --env CXX="${CXX}" \
    --env CFLAGS="${CFLAGS}" --env LDFLAGS="${LDFLAGS}" \
    ${DOCKER_ENV} \
    ${IMAGE} \
    /bin/bash -c "${BUILD_COMMAND}"

popd &> /dev/null
