bin_PROGRAMS = tile-pcie-logd

tile-pcie-logd_SOURCE = tile-pcie-logd.c

AM_CFLAGS = -std=gnu99 -Wall -Werror -g -O2 -I$(TILERA_ROOT)/include \
            -DTILEPCI_HOST

tile-pcie-logd_LDDADD = -pthread
EXTRA_DIST = LICENSE README
