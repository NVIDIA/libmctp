# MCTP mocked drivers

MCTP mocked drivers are used to emulate real HW interfaces.

General idea for such mocked driver is to provide
driver interface in exactly the same way as it is used
in libMctp repository by specific interfaces.

Additionally, mocked drivers provide second interface,
where testing functions may connect.

The mocked driver role is to send data in cross way
from the driver interface to the interface used by test functions.
And the same in opposite direction.

To facilitate mocked drivers debugging functionality each driver
provides its own statistics in /proc files.

Also each driver provides a parameter to immediately skip received packets
without passing them from demux demon side to a test functions interface.
The parameter name is: parameters/skip_packets_in
Its usage is provided below.

## Compilation

For now all kernel drivers may be compiled using a dedicated makefile.
There is no possibility to compile kernel drivers using meson directly.

Each makefile for mocked drivers provide several targets:

    _rmmod_ -> removes drivers from kernel
    _insmod_ -> installs drivers in kernel
    _clean_ -> cleans the compiled files
    _build_ -> builds kernel drivers
    _check_ -> checks if given driver is installed in kernel
    _all_ -> the above in this order: rmmod clean build insmod check

Meson during configuration phase calls all mocked kernel drivers with _all_ target.
So, all mocked drivers should be compiled and installed before ninja work.

Run meson with mocked drivers compilation and installation:

    meson build -Dmocked-drivers=enabled

### Compilation with docker

Folder ./tests/mctp-fuzzer contains auxiliary Dockerfile.drivers, which may be used to facilitate drivers compilation and installation.

To work with the docker file, there are also dedicated bash scripts:

    13-build-docker-drivers.sh allows to prepare docker image, usefull for compilation, installation and debugging mocked kernel drivers.
    14-run-console-for-drivers-as-root.sh allows to connect to docker image.
    30-build-mocked-drivers.sh performs the operation of compiling and installing of the mocked drivers.

Additionally two scripts are helpfull for debugging purposes:

    05-verify-mocked-drivers.sh -> checks, which mocked drivers are installed in the system
    09-remove-mocked-drivers.sh -> removes all MCTP mocked drivers from the system


### Usage notes

**Note 1: Makefiles are prepared to work properly from a Docker image or from a Linux OS.**

**Note 2: Insmod and rmmod commands require root previliges.**

**Note 3: Mocked drivers cannot be installed and used in a standard Windows WSL environment.**

**Warning 1: Any issue with mocked drivers during their usage may cause a requirement to reboot Linux kernel system. Use them carefully and rather in a local environment.**

## Mocked drivers - usage

Most of the functionality and usage of mocked drives are quite similar.
However, there are small differences in interfaces names and
in the way how packes are transferred.

### PCIE mocked driver

    Module name: aspeed-mctp
    Emulated driver interface: /dev/aspeed-mctp
    Test functions driver interface: /dev/aspeed-mctp-mock
    Proc information: /proc/mctp_aspeed-mctp

### SMBUS mocked driver

    Module name: smbus_mock
    Emulated driver interface: /dev/smbus
    Test functions driver interface: /dev/smbus-mock
    Proc information: /proc/mctp_smbus

### SPI mocked driver

SPI mocked driver is a little bit different in comparison to PCIE and SMBUS.
It is forced by a requirement to use also mocked driver for GPIO and MTD.
So, to simulate SPI HW interface, there are required three mocked drivers.

    Module name: spidev
    Emulated driver interface: /dev/spidev0.2
    Test functions driver interface: /dev/spidev0.2-mock
    Proc information: /proc/mctp_spidev0.2

    Module name: gpiolib_sysfs

    Module name: mtd

## Internal structure

Each mocked driver contains two FIFOs to store packets being transferred between interfaces.
The FIFOs status can be viewed in dedicated /proc files.

### /proc information

To check for example PCIE driver proper work try the below commands.

    cat /proc/mctp_aspeed-mctp

    Mock MCTP driver
    FIFO in: full = 0, empty = 1, len = 0
    FIFO out: full = 0, empty = 0, len = 5
    
    mock_mctp_current_packet_rin is null
    mock_mctp_current_packet_rout is null
    
    packets_written_in      : 0
    packets_read_in         : 0
    bytes_written_in        : 0
    bytes_read_in           : 0
    packet_fifo_in          : 0
    
    packets_written_out     : 10397
    packets_read_out        : 10392
    bytes_written_out       : 831760
    bytes_read_out          : 831360
    packet_fifo_out         : 0
    
    errors_copy_to_user_in      : 0
    errors_copy_from_user_in    : 0
    errors_copy_to_user_out     : 0
    errors_copy_from_user_out   : 0

Packets sent from demux demon to mocked driver are pointed by "in" direction.

Packets sent from the mocked driver to any mocked endpoint (test functions) are pointed by "out" direction.

The mock_mctp_current_packet is not null in any case of partial packets reads by tested user applications. Normally, it should be always null.

### Checking driver interfaces

The mocked PCIE driver creates two driver files:
    ls -al /dev/aspeed-mctp*
    crw-rw-rw- 1 root root 239, 0 Aug 11 08:11 /dev/aspeed-mctp
    crw-rw-rw- 1 root root 238, 0 Aug 11 08:11 /dev/aspeed-mctp-mock

/dev/aspeed-mctp - standard PCIE mocked driver, which will be used by demux demon.

/dev/aspeed-mctp-mock - driver files, which should be used by any mocked endpoint application to control packets received from demux demon and sent to demux demon from the driver's side.


### Skipping packets written by demux demon to the kernel driver

To test massive number of packets sent from any test application to demux demon in the Linux user space it may be good to skip the written packets in the mocked Linux Kernel.

For that purpose there could be used one module parameter.

    sudo sh -c "echo 1 > /sys/module/aspeed_mctp/parameters/skip_packets_in"

Verification:

    sudo cat /sys/module/aspeed_mctp/parameters/skip_packets_in
    1