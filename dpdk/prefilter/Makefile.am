if BUILD_DPDK_APPS

# binary name
APP = prefilter

# all source are stored in SRCS
SRCS = \
    prefilter.c \
    util-prefilter.c \
    logger.c \
    logger-basic.c \
    dev-conf.c \
    dev-conf-suricata.c \
    lcores-manager.c \
    lcore-worker.c \
    lcore-worker-suricata.c \
    stats.c \
    hash-table-bypass.c

OBJS = \
    prefilter.o \
    util-prefilter.o \
    logger.o \
    logger-basic.o \
    dev-conf.o \
    dev-conf-suricata.o \
    lcores-manager.o \
    lcore-worker.o \
    lcore-worker-suricata.o \
    stats.o \
    hash-table-bypass.o

all:
	if [ $$test -e $(CONFIGURE_PREFIX)/lib/libsuricata.so ] \
	&& [ $$test -e $(CONFIGURE_PREFIX)/lib/libhtp.so ] \
	&& ! [ $(test -n "$(ldconfig -p | grep libsuricata.so)") ]; then \
		$(MAKE) shared; \
	else \
		echo "*********** Compiling DPDK apps ***********"; \
		echo "1) run from root directory"; \
		echo "	make dpdk-apps-prereq"; \
		echo "2) add Suricata library to ldconfig e.g.: "; \
		echo "	echo $(CONFIGURE_PREFIX)/lib/ | sudo tee /etc/ld.so.conf.d/dpdk-apps.conf"; \
		echo "3) run:"; \
		echo "	sudo ldconfig"; \
		echo "4.a) either run from root directory:"; \
		echo "	make dpdk-apps"; \
		echo "4.b) or run from within DPDK app directory:"; \
		echo "	make [shared/static]"; \
		echo "*********** Compiling DPDK apps ***********"; \
	fi
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE = $(LIBDPDK_PC_FILE)
CFLAGS += -O3 $(LIBDPDK_CFLAGS) -I $(CONFIGURE_PREFIX)/include/suricata/ -I $(CONFIGURE_PREFIX)/include/ \
          -DHAVE_DPDK -DTLS_C11
LDFLAGS_SHARED = $(LIBDPDK_LDFLAGS_SHARED) -L $(CONFIGURE_PREFIX)/lib/ -lsuricata -lhtp $(LIBS)
LDFLAGS_STATIC = $(LIBDPDK_LDFLAGS_STATIC)

CFLAGS += -I. -DALLOW_EXPERIMENTAL_API

$(OBJS): %.o: %.c Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) -c $< -o $@

build/$(APP)-shared: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)


build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)* build/*.o
	rm -f $(APP){,-shared,-static} *.o
	test -d build && rmdir -p build || true

endif