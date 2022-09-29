AF_XDP
======

AF_XDP (eXpress Data Path) is a high speed capture framework for Linux that was
introduced in Linux v4.18. AF_XDP aims at improving capture performance by
redirecting ingress frames to user-space memory rings, thus bypassing the network
stack.

Note that during ``af_xdp`` operation the selected interface cannot be used for
regular network usage.

Further reading:

    - https://www.kernel.org/doc/html/latest/networking/af_xdp.html

Compiling Suricata
------------------

Linux
~~~~~

libxdp and libpbf are required for this feature. When building from source the
development files will also be required.

Example::

    dnf -y install libxdp-devel libbpf-devel

This feature is enabled provided the libraries above are installed, the user
does not need to add any additional command line options. 

The command line option ``--disable-af-xdp`` can be used to disable this
feature.

Example::

    ./configure --disable-af-xdp

Starting Suricata
-----------------

IDS
~~~

Suricata can be started as follows to use af-xdp:

::

  af-xdp:
    suricata --af-xdp=<interface>
    suricata --af-xdp=igb0

In the above example Suricata will start reading from the `igb0` network interface.

AF_XDP Configuration
--------------------

Each of these settings can be configured under ``af-xdp`` within the "Configure
common capture settings" section of suricata.yaml configuration file.

The number of threads created can be configured in the suricata.yaml configuration
file. It is recommended to use threads equal to NIC queues/CPU cores.

Another option is to select ``auto`` which will allow Suricata to configure the
number of threads based on the number of RSS queues available on the NIC.

With ``auto`` selected, Suricata spawns receive threads equal to the number of
configured RSS queues on the interface.

::

  af-xdp:
   threads: <number>
   threads: auto
   threads: 8

Advanced setup
---------------

af-xdp capture source will operate using the default configuration settings.
However, these settings are available in the suricata.yaml configuration file.

Available configuration options are:

force-xdp-mode
~~~~~~~~~~~~~~

There are two operating modes employed when loading the XDP program, these are:

- XDP_DRV: Mode chosen when the driver supports AF_XDP
- XDP_SKB: Mode chosen when no AF_XDP support is unavailable

XDP_DRV mode is the preferred mode, used to ensure best performance.

::

  af-xdp:
    force-xdp-mode: <value> where: value = <skb|drv|none>
    force-xdp-mode: drv

force-bind-mode
~~~~~~~~~~~~~~~

During binding the kernel will first attempt to use zero-copy (preferred). If
zero-copy support is unavailable it will fallback to copy mode, copying all
packets out to user space.

::

  af-xdp:
    force-bind-mode: <value> where: value = <copy|zero|none>
    force-bind-mode: zero

For both options, the kernel will attempt the 'preferred' option first and
fallback upon failure. Therefore the default (none) means the kernel has
control of which option to apply. By configuring these options the user
is forcing said option. Note that if enabled, the bind will only attempt
this option, upon failure the bind will fail i.e. no fallback.

mem-unaligned
~~~~~~~~~~~~~~~~

AF_XDP can operate in two memory alignment modes, these are:

- Aligned chunk mode
- Unaligned chunk mode

Aligned chunk mode is the default option which ensures alignment of the
data within the UMEM.

Unaligned chunk mode uses hugepages for the UMEM.
Hugepages start at the size of 2MB but they can be as large as 1GB.
Lower count of pages (memory chunks) allows faster lookup of page entries.
The hugepages need to be allocated on the NUMA node where the NIC and CPU resides.
Otherwise, if the hugepages are allocated only on NUMA node 0 and the NIC is
connected to NUMA node 1, then the application will fail to start.
Therefore, it is recommended to first find out to which NUMA node the NIC is
connected to and only then allocate hugepages and set CPU cores affinity
to the given NUMA node.

Memory assigned per socket/thread is 16MB, so each worker thread requires at least
16MB of free space. As stated above hugepages can be of various sizes, consult the
OS to confirm with ``cat /proc/meminfo``.

Example ::
  
    8 worker threads * 16Mb = 128Mb
    hugepages = 2048 kB
    so: pages required = 62.5 (63) pages

See https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt for detailed
description.

To enable unaligned chunk mode:

::

  af-xdp:
    mem-unaligned: <yes/no>
    mem-unaligned: yes

Introduced from Linux v5.11 a ``SO_PREFER_BUSY_POLL`` option has been added to
AF_XDP that allows a true polling of the socket queues. This feature has
been introduced to reduce context switching and improve CPU reaction time
during traffic reception.

Enabled by default, this feature will apply the following options, unless
disabled (see below). The following options are used to configure this feature.

enable-busy-poll
~~~~~~~~~~~~~~~~

Enables or disables busy polling.

::

  af-xdp:
    enable-busy-poll: <yes/no>
    enable-busy-poll: yes

busy-poll-time
~~~~~~~~~~~~~~

Sets the approximate time in microseconds to busy poll on a ``blocking receive``
when there is no data.

::

  af-xdp:
    busy-poll-time: <time>
    busy-poll-time: 20

busy-poll-budget
~~~~~~~~~~~~~~~~

Budget allowed for batching of ingress frames. Larger values means more
frames can be stored/read. It is recommended to test this for performance.

::

  af-xdp:
    busy-poll-budget: <budget>
    busy-poll-budget: 64

Linux tunables
~~~~~~~~~~~~~~~

The ``SO_PREFER_BUSY_POLL`` option works in concert with the following two Linux
knobs to ensure best capture performance. These are not socket options:

- gro-flush-timeout
- napi-defer-hard-irq

The purpose of these two knobs is to defer interrupts and to allow the
NAPI context to be scheduled from a watchdog timer instead
``(gro-flush-timeout)``. The ``napi-defer-hard-irq`` indicates the number of
attempts before exiting. When enabled the softirq NAPI context will
exit early and allow busy polling.

When no traffic is received for ``gro-flush-timeout`` this watchdog will
timeout and softirq handling will resume.

::

  af-xdp:
    gro-flush-timeout: 2000000
    napi-defer-hard-irq: 2


Hardware setup
---------------

Intel NIC setup
~~~~~~~~~~~~~~~

Intel network cards don't support symmetric hashing but it is possible to emulate
it by using a specific hashing function.

Follow these instructions closely for desired result::

 ifconfig eth3 down

Enable symmetric hashing ::

 ifconfig eth3 down 
 ethtool -L eth3 combined 16 # if you have at least 16 cores
 ethtool -K eth3 rxhash on 
 ethtool -K eth3 ntuple on
 ifconfig eth3 up
 ./set_irq_affinity 0-15 eth3
 ethtool -X eth3 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 16
 ethtool -x eth3
 ethtool -n eth3

In the above setup you are free to use any recent ``set_irq_affinity`` script. It is available in any Intel x520/710 NIC sources driver download.

**NOTE:**
We use a special low entropy key for the symmetric hashing. `More info about the research for symmetric hashing set up <http://www.ndsl.kaist.edu/~kyoungsoo/papers/TR-symRSS.pdf>`_

Disable any NIC offloading
~~~~~~~~~~~~~~~~~~~~~~~~~~

Suricata shall disable NIC offloading based on configuration parameter ``disable-offloading``, which is enabled by default.
See ``capture`` section of yaml file.

::

  capture:
    # disable NIC offloading. It's restored when Suricata exits.
    # Enabled by default.
    #disable-offloading: false

Balance as much as you can
~~~~~~~~~~~~~~~~~~~~~~~~~~

Try to use the network card's flow balancing as much as possible ::
 
 for proto in tcp4 udp4 ah4 esp4 sctp4 tcp6 udp6 ah6 esp6 sctp6; do 
    /sbin/ethtool -N eth3 rx-flow-hash $proto sd
 done

This command triggers load balancing using only source and destination IPs. This may be not optimal
in terms of load balancing fairness but this ensures all packets of a flow will reach the same thread
even in the case of IP fragmentation (where source and destination port will not be available for
some fragmented packets).
