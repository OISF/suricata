TOPTARGETS = shared static check clean
SUBDIRS = prefilter

if BUILD_DPDK_APPS

help:
	echo "install Suricata, Suricata headers and library and run make dpdk-apps from root directory"

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

endif