#!/bin/bash

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")

pushd ${SCRIPT_PATH} &> /dev/null

source 00-projdefs.sh
source 01-common.sh
source 02-projdefs-ctrl.sh

cleanup_containers

COMMAND="$@"
echo "Command for fuzz tests:"
echo "${COMMAND}"
FUZZ_TIME=${DEFAULT_FUZZ_TIME}

if [[ ! -d ${PROJ_PATH}/${WORK_DIR}/${SEED_DIR} ]]; then
    mkdir -p ${PROJ_PATH}/${WORK_DIR}/${SEED_DIR}
    for i in $(seq 5); do
        dd if=/dev/urandom of=${PROJ_PATH}/${WORK_DIR}/${SEED_DIR}/seed_${i} bs=64 count=10;
    done
fi

eval "HCMD=\"${HOST_PREPARATION_COMMAND:-':'}\""
/bin/bash -c "${HCMD}"

#eval "DCMD=\"${DOCKER_PREPARATION_COMMAND:-':'}\""
if [[ -z "${COMMAND}" ]]; then
    docker run \
        --interactive --net=host --privileged --tty \
        --volume "${PROJ_PATH}:${PROJ_PATH}" \
        --workdir ${PROJ_PATH}/${WORK_DIR}/ \
        ${IMAGE} \
        ./${FUZZ_EXEC} -h
else
    OUTPUT_DIR=${PROJ_PATH}/aflOut$(date +%s)
    mkdir -p ${OUTPUT_DIR}
    realpath ${OUTPUT_DIR}
    echo "Output dir: ${OUTPUT_DIR}"
    echo "Seed dir: ${SEED_DIR}"
    echo "Fuzz time: ${FUZZ_TIME}"
    echo "Fuzz exec: ${FUZZ_EXEC}"
    echo "Full command: >>>>>afl-fuzz -o ${OUTPUT_DIR} -i ./${SEED_DIR}/ -V ${FUZZ_TIME} -t 1000 -- ./${FUZZ_EXEC} ${COMMAND}<<<<<"
    # afl coverage in life
    DCMD="afl-cov -d ${OUTPUT_DIR} --live --coverage-cmd \"./${FUZZ_EXEC} ${COMMAND}\" --code-dir ${PROJ_PATH} &"
    docker run \
        --interactive --net=host --privileged --tty \
        --volume "${PROJ_PATH}:${PROJ_PATH}" \
        --workdir ${PROJ_PATH}/${WORK_DIR}/ --env AFL_SKIP_CPUFREQ=1 \
        --user="${USER}" \
        --volume /run/user/$(id -u)/bus:/run/user/$(id -u)/bus \
        --env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus" \
        ${IMAGE} \
        /bin/bash -c "${DCMD} afl-fuzz -o ${OUTPUT_DIR} -i ./${SEED_DIR}/ -V ${FUZZ_TIME} -t 1000 -- ./${FUZZ_EXEC} ${COMMAND}"
    FULL_COMMAND="./${FUZZ_EXEC} ${COMMAND}"
    echo "Full coverage command: >>>>>afl-cov -d ${OUTPUT_DIR} --coverage-cmd \"${FULL_COMMAND}\" --code-dir ${PROJ_PATH} --overwrite<<<<<"
#    echo "afl-cov -d ${OUTPUT_DIR} --coverage-cmd \"${FULL_COMMAND}\" --code-dir ${PROJ_PATH}" >> "${PROJ_PATH}/code_coverage_aflOut$(date +%s).sh"
    # prepare code coverage
#    docker run \
#        --interactive --net=host --privileged --tty \
#        --volume "${PROJ_PATH}:${PROJ_PATH}" \
#        --workdir ${PROJ_PATH}/${WORK_DIR}/ --env AFL_SKIP_CPUFREQ=1 \
#        ${IMAGE} \
#        /bin/bash -c "${DCMD}; afl-cov -d ${OUTPUT_DIR}  --overwrite --coverage-cmd \"${FULL_COMMAND}\" --code-dir ${PROJ_PATH} --lcov-exclude-pattern ${PROJ_PATH}/conftest.c"
fi

popd &> /dev/null

#        -v /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket \
#        -e DBUS_SYSTEM_BUS_ADDRESS="unix:path=/var/run/dbus/system_bus_socket" \