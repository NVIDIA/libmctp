#!/bin/bash

# Make sure all required tools to work with kernel modules are also properly installed on the Host machine
# If they are missing it is mandatory to install them
# Kernel headers on the Host machine and inside the docker must be of the same version
KERNEL_RELEASE=$(uname -r)
KERNEL_HEADERS="/usr/src/linux-headers-${KERNEL_RELEASE}"
if [ -d ${KERNEL_HEADERS} ]
then 
    echo "INFO: Proper linux kernel headers seems to be available in the Host system"
else
    echo "INFO: Install additional libraries, required for kernel modules compilation on the Host machine"
    echo "INFO: kernel-release: ${KERNEL_RELEASE}"
    echo "INFO: Executing: sudo apt-get install -yy linux-headers-${KERNEL_RELEASE} kmod"
    if [[ ${KERNEL_RELEASE} != *"WSL2"* ]]
    then
        sudo apt-get install -yy linux-headers-${KERNEL_RELEASE} kmod
    else
        echo "INFO: On WSL, we cannot install additional libraries to compile Linux kernel modules"
    fi
fi

SCRIPT_NAME=$(realpath "$0")
SCRIPT_PATH=$(dirname "${SCRIPT_NAME}")

pushd ${SCRIPT_PATH} &> /dev/null

source 01-common.sh
source 04-projdefs-drivers.sh

cleanup_containers

# The below --cap-add option allows to init kernel modules inside docker
#    --cap-add=CAP_SYS_MODULE \
# Also make sure that docker is running as a root user
# /usr/src must be taken from Host for drivers comparibility with the Host OS

docker run \
    --interactive --net=host --tty --rm \
    --cap-add=CAP_SYS_MODULE \
    --volume "${PROJ_PATH}:${PROJ_PATH}" \
	--volume "/usr/src":"/usr/src" \
    --workdir ${PROJ_PATH} \
    ${IMAGE} \
    /bin/bash -c "${BUILD_COMMAND}"

# After compilation verify that all required drivers are available in the system
source 05-verify-mocked-drivers.sh

popd &> /dev/null
