MOD_MTD = mtd
MOD_SPI = spidev
MOD_GPIO = gpiolib-sysfs
KPATH :=/lib/modules/$(shell uname -r)/build
mkfile_path := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

obj-m += $(MOD_MTD).o $(MOD_GPIO).o $(MOD_SPI).o

# if SCHED_TYPE contains bash then it is rather Docker container,
#   but if not then it is rather normal Linux Host OS
SCHED_TYPE := $(shell cat /proc/1/sched | head -n 1 | grep -o bash)
ifeq ($(SCHED_TYPE),bash)
  SUDO=""
else
  SUDO="sudo"
endif

.PHONY: all _rmmod rmmod clean compile insmod _insmod check

all: _rmmod clean compile _insmod check

rmmod: _rmmod check
insmod: _insmod check

_rmmod:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_SPI)))
	$(if $(MODULE_INSMOD),$(shell $(SUDO) rmmod $(MOD_SPI)),$(info INFO: No need to do rmmod $(MOD_SPI).))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^gpiolib_sysfs))
	$(if $(MODULE_INSMOD),$(shell $(SUDO) rmmod $(MOD_GPIO)),$(info INFO: No need to do rmmod gpiolib_sysfs.))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_MTD)))
	$(if $(MODULE_INSMOD),$(shell $(SUDO) rmmod $(MOD_MTD)),$(info INFO: No need to do rmmod $(MOD_MTD).))

clean:
	make -C $(KPATH) M=$(mkfile_path) clean

compile:
	make -C $(KPATH) M=$(mkfile_path) KBUILD_CFLAGS+=-I$(mkfile_path)/../../.. EXTRA_CFLAGS="-O2" modules

_insmod:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_MTD)))
	$(if $(MODULE_INSMOD),$(info INFO: No need to do insmod $(MOD_MTD).ko.),$(shell $(SUDO) insmod $(MOD_MTD).ko))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^gpiolib_sysfs))
	$(if $(MODULE_INSMOD),$(info INFO: No need to do insmod $(MOD_GPIO).ko.),$(shell $(SUDO) insmod $(MOD_GPIO).ko))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_SPI)))
	$(if $(MODULE_INSMOD),$(info INFO: No need to do insmod $(MOD_SPI).ko.),$(shell $(SUDO) insmod $(MOD_SPI).ko))

check:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_MTD)))
	$(if $(MODULE_INSMOD),$(eval $(info INFO: Module $(MOD_MTD) is loaded)),$(eval $(info INFO: Module $(MOD_MTD) is not loaded)))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^gpiolib_sysfs))
	$(if $(MODULE_INSMOD),$(eval $(info INFO: Module $(MOD_GPIO) is loaded)),$(eval $(info INFO: Module $(MOD_GPIO) is not loaded)))
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_SPI)))
	$(if $(MODULE_INSMOD),$(eval $(info INFO: Module $(MOD_SPI) is loaded)),$(eval $(info INFO: Module $(MOD_SPI) is not loaded)))

$(V).SILENT:
