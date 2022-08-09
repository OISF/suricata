High Performance Configuration
==============================

NIC
---

One of the major dependencies for Suricata's performance is the Network 
Interface Card. There are many vendors and possibilities. Some NICs have and 
require their own specific instructions and tools of how to set up the NIC. 
This ensures the greatest benefit when running Suricata. Vendors like 
Napatech, Netronome, Accolade, Myricom include those tools and documentation 
as part of their sources.

For Intel, Mellanox and commodity NICs the following suggestions below could 
be utilized. 

It is recommended that the latest available stable NIC drivers are used. In 
general when changing the NIC settings it is advisable to use the latest 
``ethtool`` version. Some NICs ship with their own ``ethtool`` that is 
recommended to be used. Here is an example of how to set up the ethtool 
if needed:  

::

 wget https://mirrors.edge.kernel.org/pub/software/network/ethtool/ethtool-5.2.tar.xz
 tar -xf ethtool-5.2.tar.xz
 cd ethtool-5.2
 ./configure && make clean && make && make install
 /usr/local/sbin/ethtool --version

When doing high performance optimisation make sure ``irqbalance`` is off and 
not running:

::

  service irqbalance stop

Depending on the NIC's available queues (for example Intel's x710/i40 has 64 
available per port/interface) the worker threads can be set up accordingly. 
Usually the available queues can be seen by running:

::

 /usr/local/sbin/ethtool -l eth1

Some NICs - generally lower end 1Gbps - do not support symmetric hashing see 
:doc:`packet-capture`. On those systems due to considerations for out of order 
packets the following setup with af-packet is suggested (the example below 
uses ``eth1``):

::

 /usr/local/sbin/ethtool -L eth1 combined 1

then set up af-packet with number of desired workers threads ``threads: auto`` 
(auto by default will use number of CPUs available) and 
``cluster-type: cluster_flow`` (also the default setting)

For higher end systems/NICs a better and more performant solution could be 
utilizing the NIC itself a bit more. x710/i40 and similar Intel NICs or 
Mellanox MT27800 Family [ConnectX-5] for example can easily be set up to do 
a bigger chunk of the work using more RSS queues and symmetric hashing in order
to allow for increased performance on the Suricata side by using af-packet 
with ``cluster-type: cluster_qm`` mode. In that mode with af-packet all packets
linked by network card to a RSS queue are sent to the same socket. Below is 
an example of a suggested config set up based on a 16 core one CPU/NUMA node 
socket system using x710:  

::

 rmmod i40e && modprobe i40e
 ifconfig eth1 down
 /usr/local/sbin/ethtool -L eth1 combined 16
 /usr/local/sbin/ethtool -K eth1 rxhash on
 /usr/local/sbin/ethtool -K eth1 ntuple on
 ifconfig eth1 up
 /usr/local/sbin/ethtool -X eth1 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 16
 /usr/local/sbin/ethtool -A eth1 rx off 
 /usr/local/sbin/ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 125
 /usr/local/sbin/ethtool -G eth1 rx 1024

The commands above can be reviewed in detail in the help or manpages of the 
``ethtool``. In brief the sequence makes sure the NIC is reset, the number of 
RSS queues is set to 16, load balancing is enabled for the NIC, a low entropy 
toeplitz key is inserted to allow for symmetric hashing, receive offloading is 
disabled, the adaptive control is disabled for lowest possible latency and 
last but not least, the ring rx descriptor size is set to 1024.
Make sure the RSS hash function is Toeplitz:

::

 /usr/local/sbin/ethtool -X eth1 hfunc toeplitz
 
Let the NIC balance as much as possible:

::

 for proto in tcp4 udp4 tcp6 udp6; do
    /usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sdfn
 done

In some cases:

::

 /usr/local/sbin/ethtool -N eth1 rx-flow-hash $proto sd

might be enough or even better depending on the type of traffic. However not 
all NICs allow it. The ``sd`` specifies the multi queue hashing algorithm of 
the NIC (for the particular proto) to use src IP, dst IP only. The ``sdfn`` 
allows for the tuple src IP, dst IP, src port, dst port to be used for the 
hashing algorithm.
In the af-packet section of suricata.yaml: 

::

 af-packet:
  - interface: eth1
    threads: 16
    cluster-id: 99
    cluster-type: cluster_qm
    ...
    ...

CPU affinity and NUMA
---------------------

Intel based systems
~~~~~~~~~~~~~~~~~~~

If the system has more then one NUMA node there are some more possibilities. 
In those cases it is generally recommended to use as many worker threads as 
cpu cores available/possible - from the same NUMA node. The example below uses 
a 72 core machine and the sniffing NIC that Suricata uses located on NUMA node 1. 
In such 2 socket configurations it is recommended to have Suricata and the 
sniffing NIC to be running and residing on the second NUMA node as by default 
CPU 0 is widely used by many services in Linux. In a case where this is not 
possible it is recommended that (via the cpu affinity config section in 
suricata.yaml and the irq affinity script for the NIC) CPU 0 is never used. 

In the case below 36 worker threads are used out of NUMA node 1's CPU, 
af-packet runmode with ``cluster-type: cluster_qm``.

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

It is recommended that 36 worker threads are used and the NIC set up could be 
as follows:

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

In the example above the ``set_irq_affinity`` script is used from the NIC 
driver's sources.
In the cpu affinity section of suricata.yaml config:

::

 # Suricata is multi-threaded. Here the threading can be influenced.
 threading:
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "1-10" ]  # include only these CPUs in affinity settings
    - receive-cpu-set:
        cpu: [ "0-10" ]  # include only these CPUs in affinity settings
    - worker-cpu-set:
        cpu: [ "18-35", "54-71" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1" ]
          high: [ "18-35","54-71" ]
          default: "high"

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

That way 36 worker threads can be mapped (18 per each af-packet interface slot) 
in total per CPUs NUMA 1 range - 18-35,54-71. That part is done via the  
``worker-cpu-set`` affinity settings. ``ring-size`` and ``block-size`` in the 
config section  above are decent default values to start with. Those can be 
better adjusted if needed as explained in :doc:`tuning-considerations`.
    
AMD based systems
~~~~~~~~~~~~~~~~~

Another example can be using an AMD based system where the architecture and 
design of the system itself plus the NUMA node's interaction is different as 
it is based on the HyperTransport (HT) technology. In that case per NUMA 
thread/lock would not be needed. The example below shows a suggestion for such 
a configuration utilising af-packet, ``cluster-type: cluster_flow``. The 
Mellanox NIC is located on NUMA 0.

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

The ``ethtool``, ``show_irq_affinity.sh`` and ``set_irq_affinity_cpulist.sh`` 
tools are provided from the official driver sources. 
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

In the example above (1-7,64-71 for the irq affinity) CPU 0 is skipped as it is usually used by default on Linux systems by many applications/tools.
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
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "120-127" ]  # include only these cpus in affinity settings
    - receive-cpu-set:
        cpu: [ 0 ]  # include only these cpus in affinity settings
    - worker-cpu-set:
        cpu: [ "8-55" ]
        mode: "exclusive"
        prio:
          high: [ "8-55" ]
          default: "high"

In the af-packet section of suricata.yaml config:

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


In the example above there are 15 RSS queues pinned to cores 1-7,64-71 on NUMA 
node 0 and 40 worker threads using other CPUs on different NUMA nodes. The 
reason why CPU 0 is skipped in this set up is as in Linux systems it is very 
common for CPU 0 to be used by default by many tools/services. The NIC itself in 
this config is positioned on NUMA 0 so starting with 15 RSS queues on that 
NUMA node and keeping those off for other tools in the system could offer the 
best advantage. 

.. note:: Performance and optimization of the whole system can be affected upon regular NIC driver and pkg/kernel upgrades so it should be monitored regularly and tested out in QA/test environments first. As a general suggestion it is always recommended to run the latest stable firmware and drivers as  instructed and provided by the particular NIC vendor. 

Other considerations
~~~~~~~~~~~~~~~~~~~~

Another advanced option to consider is the ``isolcpus`` kernel boot parameter 
is a way of allowing CPU cores to be isolated for use of general system 
processes. That way ensures total dedication of those CPUs/ranges for the 
Suricata process only.

``stream.wrong_thread`` / ``tcp.pkt_on_wrong_thread`` are counters available
in ``stats.log`` or ``eve.json`` as ``event_type: stats`` that indicate issues with
the load balancing. There could be traffic/NICs settings related as well. In 
very high/heavily increasing counter values it is recommended to experiment 
with a different load balancing method either via the NIC or for example using
XDP/eBPF. There is an issue open 
https://redmine.openinfosecfoundation.org/issues/2725 that is a placeholder 
for feedback and findings.
