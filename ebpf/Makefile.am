if BUILD_EBPF

# Maintaining a local copy of UAPI linux/bpf.h
BPF_CFLAGS = -Iinclude

CLANG = ${CC}

BPF_TARGETS  = lb.bpf
BPF_TARGETS += filter.bpf
BPF_TARGETS += bypass_filter.bpf
BPF_TARGETS += xdp_filter.bpf
BPF_TARGETS += vlan_filter.bpf

all: $(BPF_TARGETS)

EXTRA_DIST= include bypass_filter.c filter.c lb.c vlan_filter.c xdp_filter.c

$(BPF_TARGETS): %.bpf: %.c
#      From C-code to LLVM-IR format suffix .ll (clang -S -emit-llvm)
	${CLANG} -Wall $(BPF_CFLAGS) -O2 \
		-I/usr/include/$(build_cpu)-$(build_os)/ \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-target bpf -S -emit-llvm $< -o ${@:.bpf=.ll}
#      From LLVM-IR to BPF-bytecode in ELF-obj file
	${LLC} -march=bpf -filetype=obj ${@:.bpf=.ll} -o $@
	${RM} ${@:.bpf=.ll}

CLEANFILES = *.bpf *.ll

endif
