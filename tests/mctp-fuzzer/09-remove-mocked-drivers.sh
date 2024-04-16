# Remove MCTP mocked drivers from the system

MOCKED_DRIVERS=( \
    "aspeed_mctp" \
    "smbus_mock" \
    "mtd" \
    "spidev" \
    "gpiolib_sysfs" \
    )

for MOCKED_DRIVER_NAME in ${MOCKED_DRIVERS[@]}; do
    sudo rmmod ${MOCKED_DRIVER_NAME}
done
