EXTRA_DIST= include bypass_filter.c filter.c lb.c vlan_filter.c xdp_filter.c \
	    xdp_lb.c xdp_synproxy_kern.c hash_func01.h

if BUILD_EBPF

# Maintaining a local copy of UAPI linux/bpf.h
BPF_CFLAGS = -Iinclude

BPF_TARGETS  = lb.bpf
BPF_TARGETS += filter.bpf
BPF_TARGETS += bypass_filter.bpf
BPF_TARGETS += xdp_filter.bpf
BPF_TARGETS += xdp_lb.bpf
BPF_TARGETS += vlan_filter.bpf
BPF_TARGETS += xdp_synproxy_kern.bpf

all: $(BPF_TARGETS)


$(BPF_TARGETS): %.bpf: %.c
#      From C-code to LLVM-IR format suffix .ll (clang -S -emit-llvm)
	${CLANG} -Wall $(BPF_CFLAGS) -O2 -g \
		-I/usr/include/$(build_cpu)-$(build_os)/ \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-target bpf -S -emit-llvm $< -o ${@:.bpf=.ll}
#      From LLVM-IR to BPF-bytecode in ELF-obj file
	${LLC} -march=bpf -filetype=obj ${@:.bpf=.ll} -o $@
	${RM} ${@:.bpf=.ll}

CLEANFILES = *.bpf *.ll

endif
