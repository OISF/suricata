#! /bin/bash

# A simple script to speed up build/test/debug iterations for XDP stuff.

if [ "$#" -ne 1 ]; then
  echo "USAGE: build-xdp.sh <name-of-source-file>"
  exit 1
fi

docker exec suricata-dev \
  bash -c "cd /workspaces/suricata-awn/ebpf && clang-10 -Wall -Iinclude -O2 \
      -I/usr/include/x86_64-linux-gnu/ \
      -D__KERNEL__ -D__ASM_SYSREG_H \
      -target bpf -S -emit-llvm $1.c -o $1.ll \
    && llc-10 -march=bpf -filetype=obj $1.ll -o $1.bpf \
    && rm -f $1.ll"

if [ $? -ne 0 ]; then
  echo "Build failed. Make sure your BoB container is running. Start it using:"
  echo "  pack docker run --name suricata-dev --container-user vagrant  cell.rtkbox.bob-debian16"
  exit 1
fi

set -e

if [ -z ${RTK_SENSOR_HOSTNAME} ]; then
  echo "RTK_SENSOR_HOSTNAME is not set. Skipping scp."
  exit 0
fi

echo "Copying $1.bpf to $RTK_SENSOR_HOSTNAME..."
scp -F $RTK_BUILD_ROOT/etc/ssh_config ./$1.bpf $RTK_SENSOR_HOSTNAME:~/ebpf

echo "Restarting Suricata on $RTK_SENSOR_HOSTNAME..."
ssh -F $RTK_BUILD_ROOT/etc/ssh_config vagrant@$RTK_SENSOR_HOSTNAME -t \
  "sudo cp /home/vagrant/ebpf/$1.bpf /opt/suricata6/ebpf && \
  sudo systemctl restart suricata6.service"

echo "Suricata restarted. Tail /var/log/suricata.log to seen when XDP has initialized."
echo "Example: \"Successfully loaded eBPF file '/opt/suricata6/ebpf/xdp_stream_filter.bpf' on 'lan0'\""