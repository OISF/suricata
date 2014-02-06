
EXTRA_DIST = LICENSE README

if BUILD_PCIE_LOGGING
bin_PROGRAMS = tile_pcie_logd

tile_pcie_logd_SOURCE = tile_pcie_logd.c

AM_CFLAGS = -std=gnu99 -Wall -Werror -g -O2 -I$(TILERA_ROOT)/include \
            -DTILEPCI_HOST

tile_pcie_logd_LDDADD = -pthread

endif
