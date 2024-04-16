# Just, check if all required mocked modules are in the system

MOCKED_DRIVERS=( \
    "aspeed_mctp" \
    "smbus_mock" \
    "mtd" \
    "spidev" \
    "gpiolib_sysfs" \
    )

ALL_DRIVERS=$(lsmod)
MISSING_MODULE=0
for MOCKED_DRIVER_NAME in ${MOCKED_DRIVERS[@]}; do
    FOUND_DRIVER=$(lsmod | grep -o "^$MOCKED_DRIVER_NAME")
    if [[ "$MOCKED_DRIVER_NAME" == "$FOUND_DRIVER" ]]
    then
        echo "Required mocked module driver <$MOCKED_DRIVER_NAME> is already available in the system."
    else
        echo "Required mocked module driver <$MOCKED_DRIVER_NAME> is not available in the system."
        MISSING_MODULE=1
    fi
done

if [ $MISSING_MODULE -gt 0 ]
then
    echo "INFO: compile and insmod missing libmctp mocked module drivers"
    exit -1
fi

echo "INFO: all required mocked modules are in the system"
