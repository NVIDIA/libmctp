MOD_NAME := aspeed_mctp
KPATH :=/lib/modules/$(shell uname -r)/build
mkfile_path := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

obj-m += $(MOD_NAME).o

# if SCHED_TYPE contains bash then it is rather Docker container,
#   but if not then it is rather normal Linux Host OS
SCHED_TYPE := $(shell cat /proc/1/sched | head -n 1 | grep -o bash)
ifeq ($(SCHED_TYPE),bash)
  SUDO=
else
  SUDO=sudo
endif

.PHONY: all _rmmod rmmod clean compile insmod _insmod check

all: _rmmod clean compile _insmod check

rmmod: _rmmod check
insmod: _insmod check

_rmmod:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_NAME)))
	$(if $(MODULE_INSMOD),$(shell $(SUDO) rmmod $(MOD_NAME)),$(info INFO: No need to do 'rmmod'.))

clean:
	make -C $(KPATH) M=$(mkfile_path) clean

compile:
	make -C $(KPATH) M=$(mkfile_path) KBUILD_CFLAGS+=-I$(mkfile_path)/../../.. EXTRA_CFLAGS="-O2" modules

_insmod:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_NAME)))
	$(if $(MODULE_INSMOD),$(info INFO: No need to do 'insmod'.),$(shell $(SUDO) insmod $(MOD_NAME).ko))

check:
	$(eval MODULE_INSMOD=$(shell lsmod | grep -o ^$(MOD_NAME)))
	$(if $(MODULE_INSMOD),$(eval $(info INFO: Module $(MOD_NAME) is loaded)),$(eval $(info INFO: Module $(MOD_NAME) is not loaded)))

$(V).SILENT:

