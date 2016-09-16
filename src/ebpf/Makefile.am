if BUILD_EBPF

all: lb.bpf filter.bpf

%.bpf: %.c
	clang-3.7 -Wall -O2 -D__KERNEL__ -D__ASM_SYSREG_H -emit-llvm -c $< -o - | llc-3.7 -march=bpf -filetype=obj -o $@

endif
