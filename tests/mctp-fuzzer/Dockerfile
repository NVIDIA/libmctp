FROM ubuntu:23.04

# Ubuntu 23.04 comes with ubuntu user, which we do not need
RUN touch /var/mail/ubuntu && chown ubuntu /var/mail/ubuntu && userdel -r ubuntu

### Only change these if you know what you are doing:
# LLVM 15 does not look good so we stay at 14 to still have LTO
ENV LLVM_VERSION=14
# GCC 12 is producing compile errors for some targets so we stay at GCC 11
ENV GCC_VERSION=11

RUN apt-get update -y --fix-missing
RUN apt-get full-upgrade -y
RUN apt-get install -y \
    apt-utils \
    dialog \
    sudo

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

ENV LANG C.UTF-8

ARG UNAME=fuzz
ARG UID=1000
ARG GID=1000

RUN sudo apt-get install -y --no-install-recommends \
    gcc-11 g++-11 gcc-11-plugin-dev libstdc++-11-dev \
    gcc-12 g++-12 gcc-12-plugin-dev libstdc++-12-dev
RUN sudo apt-get install -y --no-install-recommends \
    llvm-13 llvm-14 llvm \
    clang-13 clang-14 clang \
    lld-13 lld-14 lld
RUN sudo apt-get install -y --no-install-recommends \
    libsqlite3-0 lcov
RUN sudo apt-get install -y --no-install-recommends \
    llvm-13-dev llvm-14-dev llvm-dev
RUN sudo apt-get install -y --no-install-recommends \
    git automake bison build-essential cargo cmake flex make ninja-build
RUN sudo apt-get install -y --no-install-recommends \
    curl iproute2 iputils-ping net-tools nlohmann-json3-dev unzip wget \
    python3-dbus python3-dev python3-pip python3-setuptools \
    libboost-all-dev libcereal-dev libdbus-1-3 libdbus-1-dev libdbus-glib-1-2 \
    libfmt-dev libglib2.0-dev libgtest-dev libgtk-3-dev libi2c-dev \
    libjson-c-dev libmbedcrypto7 libmbedtls-dev libmbedx509-1 libpixman-1-dev \
    libsdbus-c++-dev libssl-dev libsystemd0 libsystemd-dev liburing2 liburing-dev
RUN sudo apt-get install -y --no-install-recommends \
    systemd libsystemd-dev
RUN sudo rm -rf /var/lib/apt/lists/*

RUN sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 10
RUN sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 20
RUN sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 10
RUN sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 20
RUN sudo update-alternatives --set gcc /usr/bin/gcc-12
RUN sudo update-alternatives --set g++ /usr/bin/g++-12
RUN sudo update-alternatives --install /usr/bin/cc cc /usr/bin/gcc 30
RUN sudo update-alternatives --set cc /usr/bin/gcc
RUN sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++ 30
RUN sudo update-alternatives --set c++ /usr/bin/g++

RUN wget -qO- https://sh.rustup.rs | CARGO_HOME=/etc/cargo sh -s -- -y -q --no-modify-path
ENV PATH=$PATH:/etc/cargo/bin

ENV LLVM_CONFIG=llvm-config-${LLVM_VERSION}
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /tmp/AFLcov
RUN cd /tmp/AFLcov && make install
#RUN rm -rf /tmp/AFLcov

RUN pip3 install --break-system-packages inflection mako meson

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git --single-branch /tmp/AFLplusplus
RUN cd /tmp/AFLplusplus && make source-only -j4 && sudo make install
#RUN rm -rf /tmp/AFLplusplus

RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME

USER $UNAME
WORKDIR /home/$UNAME
