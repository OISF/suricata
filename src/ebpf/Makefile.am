if BUILD_EBPF

all: lb.bpf filter.bpf bypass_filter.bpf xdp_filter.bpf vlan_filter.bpf

%.bpf: %.c
	${CC} -Wall -O2 -D__KERNEL__ -D__ASM_SYSREG_H -emit-llvm -c $< -o - | ${LLC} -march=bpf -filetype=obj -o $@

CLEANFILES = *.bpf

endif
