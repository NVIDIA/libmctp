# MCTP Fuzz tests

This folder contains scripts required to run MCTP Fuzz tests.
Follow the below steps to run the tests.
To get guidelines on architecture check next chapter.

## Prerequisities

Install buildx for docker
sudo apt install docker-buildx-plugin

Install coredumplist
```
sudo apt-get install systemd-coredump
```
Change core dump settings to enable afl tests without root usage
```
cat /proc/sys/kernel/core_pattern | /lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h

sudo sh -c "echo core >/proc/sys/kernel/core_pattern"
```

Make sure that in the system is installed systemd and bus functionality is up and running.

## MCTP CTRL daemon - running tests

The tests are run from within the libMctp cloned repository.

### Build docker image

The first step is to build docker image, where the tests will be run.

    ./tests/mctp-fuzzer/11-build-docker.sh

### Compile MCTP ctrl daemon with fuzz tests enabled

The compilation will be performed in docker image.
Note: check for meson options in 00-projdefs.sh file to compile manually.

By default the compilation is done with coverage reports enabled.

Without sanitizers:
    ./tests/mctp-fuzzer/21-build-ctrl-fuzzer.sh

With sanitizers. 
Sanitizers are set by setting specific environment variable in the docker before building process.
Setting AFL_USE_... automatically enables supported sanitizers - provided that your compiler supports it. 
Available are:

    AFL_USE_TSAN=1 - activates the thread sanitizer to find thread race conditions
    AFL_USE_UBSAN=1 - activates the undefined behavior sanitizer
    AFL_USE_ASAN=1 - activates the address sanitizer (memory corruption detection)

Sample commands:
     
    ./tests/mctp-fuzzer/21-build-ctrl-fuzzer.sh "AFL_USE_ASAN=1"

    ./tests/mctp-fuzzer/21-build-ctrl-fuzzer.sh "AFL_USE_UBSAN=1"

    ./tests/mctp-fuzzer/21-build-ctrl-fuzzer.sh "AFL_USE_TSAN=1"

WARNING: for some reason TSAN sanitizer does not like coverage settings.
So, before compiling with TSAN enabled, comment out coverage settings from 21-build-ctrl-fuzzer.sh script.
It can be achieved by making sure that those settings are not used:

    CFLAGS="-fprofile-arcs -ftest-coverage"
    LDFLAGS=${LDFLAGS:-"-lgcov"}

### Run fuzz tests

To run fuzz tests with afl++ use ./tests/mctp-fuzzer/22-run-ctrl-fuzzer.sh script.
It runs mctp-ctrld with fuzzing enabled inside the docker image.

Available options for mctp-ctrld with fuzzing enabled are:

--verbose [0..4]

Verbose level for debug messgaes:
0 - only crucial debugs enabled;
1 - crucial debugs from fuzzer test routines;
2 - debug and informational messages from fuzzer test routines;
3 - debug, informational and trace messages from fuzzer test routines;
4 - full debug information from MCTP CTRL daemon source code.

-t [1,2,3,6,1000]

Interface for fuzzing tests:
1 - SMBUS,
2 - PCIE,
3 - USB,
6 - SPI,
1000 - all from the above list.

--random-input

Use this option only if you run mctp-ctrld daemon without afl++, but as a normal binary.
It is usefull to randomize fuzzer test routines.
Without this option fuzzer test code will expect random vaalues from the standard input.

--parameter-type [0..12]

It is used to choose, with which parameters set mctp-ctrl daemon will be started.
See the source code to check the possibilities.
If this parameter is not passed then the parameter type will be randomized.
Note, that some of the values are causing to work with very specific interface type, which is independent on chosen interface type with option -t.

Sample call to make fuzzing with all possible tests:

    ./tests/mctp-fuzzer/22-run-ctrl-fuzzer.sh -t 1000

The tests are run with coverage report generating process in parallel.
However, if one stops the fuzzing process with CTRL-C then the final coverage report may not be generated. In such a case run coverage report generating a dedicated command (see below).

### Generate coverage report

To run coverage report generator separately one must do it from within docker image.
Run bash in the docker image:

    ./tests/mctp-fuzzer/12-run-console.sh

Go to ./builddir/ctrld folder and run this command:

    afl-cov -d /home/marcin/repos/NVIDIA/libmctp.ctrl_fuzz2/aflOut1710910169 --coverage-cmd "./mctp-ctrl -t 1000" --code-dir /home/marcin/repos/NVIDIA/libmctp.ctrl_fuzz2 --overwrite

If the folder name with fuzzer tests is different then change in each place the folder name: aflOut1710910169

Once coverage report generating process is finished it will provide information where the report is stored. The output report is an html file.

### Verify hang or crash issues

If there is any crash or hang then it is reported in afl output folder (aflOut1710910169/default). 
Such cases will be stored as separate files in specific folders: crashes or hangs.
Each file contains binary data, which was used as standrd input to run afl++ with the tested binary.
To check given crash or hang provide the binary file as a standard input when running mctp-ctrld, for example:

    ./builddir/ctrld/mctp-ctrld -t 1000 --verbose 4 < id:000000,src:000002,time:3174,execs:178,op:havoc,rep:3

## Architecture description - MCTP fuzzer

The AFL++ fuzz tests assume that a UUT is a binary file, which takes fuzzed data from the standard input.
By the fuzzed data we assume some random content, which is adjusted by AFL++ to discover as most of the code paths as possible.
The fuzzing idea is to run the UUT as many counts as possible.

Note: one run of the fuzzer should not take more than 10ms. So, for fuzzing purposes all delay or sleep commands should be commented out, especially when they are waiting for more than 10ms in summary.

The fuzzer's one run should finish returning zero value -> this assumes that the run completed successfully.

Any run, which finishes as:
- reporting a non-zero value (for example unexpected behaviour of UUT);
- crashing of the application;
- hanging for more than timeout provided by -t parameter (by default 1 second),

is reported by the fuzzer as an error and should be verified and resolved after finishing fuzzing tests.

In general tests with fuzzing should take at least one hour and may take more than 24 hours. The tests may be finished if there are no new source code lines discoveries during a test execution.

### MCTP CTRL daemon fuzz tests

To prepare the content for tests with specific values from random input, the application is prepared using two threads.
One thread is the application under tests - mctp-ctrld. The second thread is a simulator of an MCTP responder.

Data transmission uses dedicated sockets, depending on used interface.
Generally, in normal usage, it is assummed that only sockets starting with \0 are used.

Also, the current implementation assumes that there will be only two clients connecting from the UUT:
- one is for the main discovery thread;
- the second is for heartbeat thread for SPI interface.

### Test procedure

All test cases procedure is divided into several parts:

1. Preparing set of arguments, with which the daemon is started.
This part assumes:
- randomizing interface type, if it is not provided with specific parameter;
- randomizing set of aarguments, with which the thread MCTP CTRL daemon is started.

    For now, the proces of randomizing set of arguments is prepared in that way that it covers 100% of sample usages as in real settings in openbmc Nvidia devices. There are also used two samples of json configuration files for SMBUS interface.

2. In the second step there is created the test thread, which will manage the MCTP sockets.
The thread creates the socket in the first place and starts listen on it. Just, before going into a listenning loop the test thread will unlock a mutex in the main function, which waited before
running the MCTP CTRL daemon thread.

3. The main function locks on the mutex just after creating the test thread. When the mutex is unlocked then the MCTP CTRL daemon thread is run with previously prepared arguments.

4. The test thread listens on the socket and wait untli the discovery process will open the socket and starts sending the messages. Depending on the type of a message the test thread prepares a proper response, which at the very end is randomly changed. This randomly changes response is sent back to MCTP CTRL daemon.

5. When there are no new messages the test thread will always send a randmo request to MCTP CTRL daemon just for test purposes.

### Adding new test cases

Adding new test cases may be implemented in at least three places:
- preparing new set of arguments, which will be used to run the MCTP CTRL daemon;
- preparing or modifying new or existing MCTP control command responses;
- preparing or modifying new or existing MCTP vendor command responses.

### Verifying test cases, coverage and sanitizers

Each run of fuzzing should be followed by preparation of the source code coverage report. The coverage report should point on covered at least 80% of the source code lines and at least of 90% of the used functions. Actually, all possible functions should be used after one fuzzing process.

The coverage report should be prepared without sanitizers enabled, because some sanitizers do not like to be run with a functionality to generate coverage reports.

After the coverage is verified then the fuzzer tests could be run one more time, but with chosen sanitizers enabled. If there is any issue with sanitizers then it is possible that the fuzzer will not even start. In such cases, try to run the fuzzer with random data generator (without randomized data taken from standard input) and with specific interfaces. 

Any sanitizer issue is reported with exact detailed information what was wrong.

## Nice to have things

1. Add fuzz tests for VDM util.
2. Prepare better coverage report generation scripts and instruction.

