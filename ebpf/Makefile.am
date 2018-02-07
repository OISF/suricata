if BUILD_EBPF

# Maintaining a local copy of UAPI linux/bpf.h
BPF_CFLAGS = -Iinclude

all: lb.bpf filter.bpf bypass_filter.bpf xdp_filter.bpf vlan_filter.bpf

%.bpf: %.c
	${CC} -Wall $(BPF_CFLAGS) -O2  -I/usr/include/$(build_cpu)-$(build_os)/ -D__KERNEL__ -D__ASM_SYSREG_H -target bpf -emit-llvm -c $< -o - | ${LLC} -march=bpf -filetype=obj -o $@

CLEANFILES = *.bpf

endif
