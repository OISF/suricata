#! /bin/bash

# A simple script to speed up build/test/debug iterations for XDP stuff.

if [ "$#" -lt 1 ]; then
  echo "USAGE: build-xdp.sh [-d|--debug] <name-of-source-file>"
  exit 1
fi

DEBUG_FLAGS=()

SOURCE_FILE=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--debug)
      DEBUG_FLAGS="-g"
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      SOURCE_FILE+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

if [ ! -z "$DEBUG_FLAGS" ]; then
  echo "Debug info enabled. Use \"llvm-objdump -S $SOURCE_FILE.bpf\" to see annotated assembly listing."
fi

docker exec suricata-dev \
  bash -c "cd /workspaces/suricata-awn/ebpf && clang-10 -Wall -Iinclude -O2 \
      -I/usr/include/x86_64-linux-gnu/ \
      -D__KERNEL__ -D__ASM_SYSREG_H \
      -target bpf -S $DEBUG_FLAGS -emit-llvm $SOURCE_FILE.c -o $SOURCE_FILE.ll \
    && llc-10 -march=bpf -filetype=obj $SOURCE_FILE.ll -o $SOURCE_FILE.bpf \
    && rm -f $SOURCE_FILE.ll"

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

echo "Copying $SOURCE_FILE.bpf to $RTK_SENSOR_HOSTNAME..."
scp -F $RTK_BUILD_ROOT/etc/ssh_config ./$SOURCE_FILE.bpf $RTK_SENSOR_HOSTNAME:~/ebpf

echo "Restarting Suricata on $RTK_SENSOR_HOSTNAME..."
ssh -F $RTK_BUILD_ROOT/etc/ssh_config vagrant@$RTK_SENSOR_HOSTNAME -t \
  "sudo cp /home/vagrant/ebpf/$SOURCE_FILE.bpf /opt/suricata6/ebpf && \
  sudo systemctl restart suricata6.service"

echo "Suricata restarted. Tail /var/log/suricata.log to seen when XDP has initialized."
echo "Example: \"Successfully loaded eBPF file '/opt/suricata6/ebpf/xdp_stream_filter.bpf' on 'lan0'\""