FROM finalduty/archlinux:weekly
MAINTAINER Sirko Höer <sirkohoeer@gmail.com>

COPY .code/pacman.conf /etc/pacman.conf

#install main packages
RUN echo "installing basic packages ..."

RUN pacman -Syu --noconfirm 
RUN pacman -S --noconfirm \
    screen \
    git \
    vim \
    net-tools \
    base-devel \
    llvm \
    clang \
    python-setuptools \
    curl \
    elfutils \
    libmpc \
    llvm-libs \
    lld \
    bc \
    dejagnu \
    patch \
    make \
    fakeroot \
    sudo \
    bison \
    gperf \
    pkgconfig \
    wget \
    cmake 

# install dep for suricata
RUN pacman -Syu --noconfirm 
RUN pacman -S --noconfirm  \
    jansson \
    libnet \
    libyaml \
    nss

#add user build
RUN echo "adding a user called build ..."
RUN useradd --no-create-home --shell=/bin/bash build && usermod -L build
RUN echo "build ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

#copy required file for the x-compile installation
COPY .code /code/

#clean up ...
RUN echo "Cleaning up the directory ..."
WORKDIR /code
RUN pacman -Scc --noconfirm
RUN rm -rf *

# copy targets and build system
RUN mkdir -p targets
RUN mkdir -p seeds
RUN mkdir -p patched_file
COPY .code/*.c /code/
COPY .code/seeds /code/seeds
COPY .code/patched_file /code/patched_file
COPY .code/build.sh /code/
COPY .code/Makefile /code/

