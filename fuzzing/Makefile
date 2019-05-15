seeds = seeds
src_target = .
build_target = playground

$(shell mkdir -p $(build_target))

FUZZERS = 	fuzz_der \
			fuzz_app \
			fuzz_app_1 \
			fuzz_app_ftp \
			fuzz_app_ssl \
			fuzz_app_dns \
			fuzz_app_dnstcp \
			fuzz_app_dns_reg \
			fuzz_app_dnstcp_reg \
			fuzz_config fuzz_rules \
			fuzz_decoder \
			fuzz_decoder_ppp_new \
			fuzz_decoder_mime \
			fuzz_decoder_ipv6 \
			fuzz_decoder_ipv4 \
			fuzz_decoder_ethernet \
			fuzz_decoder_erspan \
			fuzz_decoder_ICMP \
			fuzz_decoder_MPLs \
			fuzz_decoder_sctp \
			fuzz_decoder_sll \
			fuzz_decoder_vlan \
			fuzz_decoder_tcp \
			fuzz_decoder_udp  
			


CFLAGS += $(shell pkg-config --cflags jansson nss)
LDFLAGS += $(shell pkg-config --libs jansson nss )

all: suricata targets

.PHONY: targets
target: $(FUZZERS)

fuzz_%: $(src_target)/fuzz_%.c
	$(shell mkdir -p $(build_target)/$*)
	clang -O1 -g \
		$< \
		${CFLAGS} ${LDFLAGS} \
		-DCLS=64 \
		-D HAVE_MAGIC \
		-I../src -I../libhtp \
		-fsanitize=fuzzer,address,undefined,signed-integer-overflow,bool,pointer-overflow  \
		-fsanitize-coverage=trace-pc-guard \
		-fsanitize-thread-memory-access \
		-lstdc++ \
		-lmagic -lcap-ng -lpcap -lpthread -lnet -lyaml -lpcre -lz -llzma \
		../src/suricata_fuzz.a \
		../libhtp/htp/.libs/libhtp.a \
		/usr/lib/liblz4.so \
		-o $(build_target)/$*/$@
	$(shell mkdir -p $(build_target)/$*/seed)
	$(shell mkdir -p $(build_target)/$*/corpus)
	$(shell (ls $(seeds)/$*/* >> /dev/null 2>&1 && cp $(seeds)/$*/* $(build_target)/$*/seed))


.PHONY: suricata
suricata:
	./build_parent.sh

.PHONY: scan_suricata
scan_suricata:
	./scan_build_parent.sh


# create and run docker env for the targets
.PHONY: docker
docker:
	cp -rfv *.c docker/.code
	cp -rfv seeds docker/.code
	cp -rfv patched_file docker/.code
	cp -rfv Makefile docker/.code
	cp -rfv build_parent.sh docker/.code
	cp -rfv scan_build_parent.sh docker/.code
	docker build -t fuzz-suricata.archlinux docker

.PHONY: start-docker
start-docker:
	docker run -it fuzz-suricata.archlinux bash

# cleaning project
.PHONY: clean
clean:
	rm -rfv playground

.PHONY: clean-all
clean-all:
	rm -rfv playground 
	rm -rfv suricata_static_analyzer

.PHONY: clean-docker
clean-docker:
	docker image rm --force fuzz-suricata.archlinux

