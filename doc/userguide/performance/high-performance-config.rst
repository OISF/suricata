High Performance Configuration
==============================

NIC
---

One of the major dependencies for Suricata's performance is the Network Interface Card. There are many vendors and possibilities. Some NICs have and require their own specific instructions of how to set up the NIC and utilize all of its benefits properly in order to run Suricata  - like Napatech, Netronome, Accolade, Myricom etc.

For Intel, Mellanox and commodity NICs you could utilize the following suggestions below. 

It is recommended that the latest available stable NIC drivers are used. In general when changing the NIC settings it is advisable to use the latest `ethtool` version. Some NICs ship with their own `ethtool` so you should use that. Here is an example of how to set up the ethtool if needed:  

::

 wget https://mirrors.edge.kernel.org/pub/software/network/ethtool/ethtool-5.2.tar.xz
 tar -xf ethtool-5.2.tar.xz
 cd ethtool-5.2
 ./configure && make clean && make && make install
 ls -lh /usr/local/sbin/ethtool

When doing high performance optimisation make sure `irqbalance` is off and not running:

::

  service irqbalance stop

Depending on the NIC's available queues (for example Intel's x710/i40 has 64 available per port/interface) you could set up your worker threads accordingly. Usually you would be able to see how many queues are available by running:

::

 /usr/local/sbin/ethtool -l eth1

Some NICs - generally lower end 1Gbps - do not support symmetric hashing see :doc:`packet-capture`. On those systems due to considerations for out of order packets the following set up with af-packet is suggested (the example below uses `eth1`):

::

 /usr/local/sbin/ethtool -L eth1 combined 1

then set up af-packet with number of desired workers threads `threads: auto` (auto by default will use number of CPUs available) and `cluster-type: cluster_flow` (also the default setting)

For higher end systems/NICs a better and more performant solution could be utilizing the NIC itself a bit more. x710/i40 and similar Intel NICs or Mellanox MT27800 Family [ConnectX-5] for example can easily be set up to do a bigger chunk of the work using more RSS queues and symmetric hashing in order to allow for increased performance on the Suricata side by using af-packet with `cluster-type: cluster_qm` mode. In that mode with af-packet all packets linked by network card to a RSS queue are sent to the same socket. Below is an example of a suggested config set up based on a 16 core one CPU/NUMA node socket system using x710:  

::

 rmmod i40e && modprobe i40e
 ifconfig eth1 down
 /usr/local/sbin/ethtool -L eth1 combined 16
 /usr/local/sbin/ethtool -K eth1 rxhash on
 /usr/local/sbin/ethtool -K eth1 ntuple on
 ifconfig eth1 up
 /usr/local/sbin/ethtool -X eth1 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 16
 /usr/local/sbin/ethtool -A eth1 rx off tx off
 /usr/local/sbin/ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 125
 /usr/local/sbin/ethtool -G eth1 rx 1024

Make sure the RSS hash function is Toeplitz:

::

 /usr/local/sbin/ethtool -X eth1 hfunc toeplitz
 
Let the NIC balance as much as possible:

::

 for proto in tcp4 udp4 tcp6 udp6; do
    /usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sdfn
 done

and in the af-packet section of suricata.yaml: 

::

 af-packet:
  - interface: eth1
    # Number of receive threads. "auto" uses the number of cores
    threads: 16
    # Default clusterid. AF_PACKET will load balance packets based on flow.
    cluster-id: 99
    # Default AF_PACKET cluster type. AF_PACKET can load balance per flow or per hash.
    # This is only supported for Linux kernel > 3.1
    # possible value are:
    #  * cluster_flow: all packets of a given flow are send to the same socket
    #  * cluster_cpu: all packets treated in kernel by a CPU are send to the same socket
    #  * cluster_qm: all packets linked by network card to a RSS queue are sent to the same
    #  socket. Requires at least Linux 3.14.
    #  * cluster_ebpf: eBPF file load balancing. See doc/userguide/capture-hardware/ebpf-xdp.rst for
    #  more info.
    # Recommended modes are cluster_flow on most boxes and cluster_cpu or cluster_qm on system
    # with capture card using RSS (require cpu affinity tuning and system irq tuning)
    cluster-type: cluster_qm
    ...
    ...

CPU affinity and NUMA
---------------------

Intel based systems
~~~~~~~~~~~~~~~~~~~

If the system has more then one NUMA node there are some more possibilities. In those cases it is generally recommended to use as many worker threads as cpu cores available/possible - from the same NUMA node. The example below uses 72 core machine and the sniffing NIC that Suricata uses located on NUMA node 1.

In the case below we are using 36 worker threads out of NUMA node 1's CPU, af-packet runmode with `cluster-type: cluster_qm`.

If the CPU's NUMA set up is as follows:

::

    lscpu
    Architecture:        x86_64
    CPU op-mode(s):      32-bit, 64-bit
    Byte Order:          Little Endian
    CPU(s):              72
    On-line CPU(s) list: 0-71
    Thread(s) per core:  2
    Core(s) per socket:  18
    Socket(s):           2
    NUMA node(s):        2
    Vendor ID:           GenuineIntel
    CPU family:          6
    Model:               79
    Model name:          Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz
    Stepping:            1
    CPU MHz:             1199.724
    CPU max MHz:         3600.0000
    CPU min MHz:         1200.0000
    BogoMIPS:            4589.92
    Virtualization:      VT-x
    L1d cache:           32K
    L1i cache:           32K
    L2 cache:            256K
    L3 cache:            46080K
    NUMA node0 CPU(s):   0-17,36-53
    NUMA node1 CPU(s):   18-35,54-71

It is recommended that 36 worker threads are used and the NIC set up could be as follows:

::

    rmmod i40e && modprobe i40e
    ifconfig eth1 down
    /usr/local/sbin/ethtool -L eth1 combined 36
    /usr/local/sbin/ethtool -K eth1 rxhash on
    /usr/local/sbin/ethtool -K eth1 ntuple on
    ifconfig eth1 up
    ./set_irq_affinity local eth1
    /usr/local/sbin/ethtool -X eth1 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 36
    /usr/local/sbin/ethtool -A eth1 rx off tx off
    /usr/local/sbin/ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 125
    /usr/local/sbin/ethtool -G eth1 rx 1024
    for proto in tcp4 udp4 tcp6 udp6; do
        echo "/usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sdfn"
        /usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sdfn
    done

In the example above the `set_irq_affinity` script is used form the NIC drivers sources.
In the cpu affinity section of suricata.yaml config :

::

 # Suricata is multi-threaded. Here the threading can be influenced.
 threading:
  set-cpu-affinity: yes
  # Tune cpu affinity of threads. Each family of threads can be bound
  # on specific CPUs.
  #
  # These 2 apply to the all runmodes:
  # management-cpu-set is used for flow timeout handling, counters
  # worker-cpu-set is used for 'worker' threads
  #
  # Additionally, for autofp these apply:
  # receive-cpu-set is used for capture threads
  # verdict-cpu-set is used for IPS verdict threads
  #
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "1-10" ]  # include only these CPUs in affinity settings
    - receive-cpu-set:
        cpu: [ "0-10" ]  # include only these CPUs in affinity settings
    - worker-cpu-set:
        cpu: [ "18-35", "54-71" ]
        mode: "exclusive"
        # Use explicitely 3 threads and don't compute number by using
        # detect-thread-ratio variable:
        # threads: 3
        prio:
          low: [ 0 ]
          medium: [ "1" ]
          high: [ "18-35","54-71" ]
          default: "high"
    #- verdict-cpu-set:
    #    cpu: [ 0 ]
    #    prio:
    #      default: "high"

In the af-packet section of suricata.yaml config :

::

  - interface: eth1
    # Number of receive threads. "auto" uses the number of cores
    threads: 18 
    cluster-id: 99
    cluster-type: cluster_qm
    defrag: no
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 100000
    block-size: 1048576
  - interface: eth1
    # Number of receive threads. "auto" uses the number of cores
    threads: 18 
    cluster-id: 99
    cluster-type: cluster_qm
    defrag: no
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 100000
    block-size: 1048576

That way we can map 36 worker threads in total per CPUs NUMA 1 range - 18-35,54-71.
    
AMD based systems
~~~~~~~~~~~~~~~~~

Another example can be using an AMD based system where the architecture and design of the system itself plus the NUMA nodes interaction is different as it is based on the HyperTransport (HT) technology. In that case per NUMA thread/lock would not be needed. The example below shows a suggestion for such a configuration utilising af-packet, `cluster-type: cluster_flow`. The Mellanox NIC is located on NUMA 0.

The CPU set up is as follows:

::

    Architecture:          x86_64
    CPU op-mode(s):        32-bit, 64-bit
    Byte Order:            Little Endian
    CPU(s):                128
    On-line CPU(s) list:   0-127
    Thread(s) per core:    2
    Core(s) per socket:    32
    Socket(s):             2
    NUMA node(s):          8
    Vendor ID:             AuthenticAMD
    CPU family:            23
    Model:                 1
    Model name:            AMD EPYC 7601 32-Core Processor
    Stepping:              2
    CPU MHz:               1200.000
    CPU max MHz:           2200.0000
    CPU min MHz:           1200.0000
    BogoMIPS:              4391.55
    Virtualization:        AMD-V
    L1d cache:             32K
    L1i cache:             64K
    L2 cache:              512K
    L3 cache:              8192K
    NUMA node0 CPU(s):     0-7,64-71
    NUMA node1 CPU(s):     8-15,72-79
    NUMA node2 CPU(s):     16-23,80-87
    NUMA node3 CPU(s):     24-31,88-95
    NUMA node4 CPU(s):     32-39,96-103
    NUMA node5 CPU(s):     40-47,104-111
    NUMA node6 CPU(s):     48-55,112-119
    NUMA node7 CPU(s):     56-63,120-127

The `ethtool`, `show_irq_affinity.sh` and `set_irq_affinity_cpulist.sh` tools are provided from the official river sources. In the 
Set up the NIC, including offloading and load balancing:

::

 ifconfig eno6 down
 /opt/mellanox/ethtool/sbin/ethtool -L eno6 combined 15
 /opt/mellanox/ethtool/sbin/ethtool -K eno6 rxhash on
 /opt/mellanox/ethtool/sbin/ethtool -K eno6 ntuple on
 ifconfig eno6 up
 /sbin/set_irq_affinity_cpulist.sh 1-7,64-71 eno6
 /opt/mellanox/ethtool/sbin/ethtool -X eno6 hfunc toeplitz
 /opt/mellanox/ethtool/sbin/ethtool -X eno6 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A

In the example above we skip CPU 0 (1-7,64-71 for the irq affinity)  as it is usually used by default on Linux systems by many applications/tools.
Let the NIC balance as much as possible:

::

 for proto in tcp4 udp4 tcp6 udp6; do
    /usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sdfn
 done

In the cpu affinity section of suricata.yaml config :

::

 # Suricata is multi-threaded. Here the threading can be influenced.
 threading:
  set-cpu-affinity: yes
  # Tune cpu affinity of threads. Each family of threads can be bound
  # on specific CPUs.
  #
  # These 2 apply to the all runmodes:
  # management-cpu-set is used for flow timeout handling, counters
  # worker-cpu-set is used for 'worker' threads
  #
  # Additionally, for autofp these apply:
  # receive-cpu-set is used for capture threads
  # verdict-cpu-set is used for IPS verdict threads
  #
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "120-127" ]  # include only these cpus in affinity settings
    - receive-cpu-set:
        cpu: [ 0 ]  # include only these cpus in affinity settings
    - worker-cpu-set:
        cpu: [ "8-55" ]
        mode: "exclusive"
        # Use explicitely 3 threads and don't compute number by using
        # detect-thread-ratio variable:
        # threads: 3
        prio:
          high: [ "8-55" ]
          default: "high"

In the af-packet section of suricata.yaml config :

::

  - interface: eth1
    # Number of receive threads. "auto" uses the number of cores
    threads: 48 # 48 worker threads on cpus "8-55" above
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 100000
    block-size: 1048576


In the example above we have 15 RSS queues pinned to cores 1-7,64-71 on NUMA node 0 and 40 worker threads using other CPUs on different NUMA nodes.

**NOTE:** Performance and optimization of the whole system can be affected upon regular NIC driver and pkg/kernel upgrades so it should be monitored regularly.
