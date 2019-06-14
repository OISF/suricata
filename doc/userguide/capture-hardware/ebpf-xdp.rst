eBPF and XDP
============

Introduction
------------

eBPF stands for extended BPF. This is an extended version of Berkeley Packet Filter available in recent
Linux kernel versions.

It provides more advanced features with eBPF programs developed in C and capability to use structured data shared
between kernel and userspace.

eBPF is used for three things in Suricata:

- eBPF filter: any BPF like filter can be developed. An example of filter accepting only packet for some VLANs is provided. A bypass implementation is also provided.
- eBPF load balancing: provide programmable load balancing. A simple ippair load balancing is provided.
- XDP programs: suricata can load XDP programs. A bypass program is provided.

Bypass can be implemented in eBPF and XDP. The advantage of XDP is that the packets are dropped at the earliest stage
possible. So performance is better. But bypassed packets don't reach the network so you can't use this on regular
traffic but only on duplicated/sniffed traffic.

XDP
~~~

XDP provides another Linux native way of optimising Suricata's performance on sniffing high speed networks.

::

 XDP or eXpress Data Path provides a high performance, programmable network data path in the Linux kernel as part of the IO Visor Project. XDP provides bare metal packet processing at the lowest point in the software stack which makes it ideal for speed without compromising programmability. Furthermore, new functions can be implemented dynamically with the integrated fast path without kernel modification.

`More info about XDP <https://www.iovisor.org/technology/xdp>`__

Requirements
------------

You will need a kernel that supports XDP and, for real performance improvement, a network
card that support XDP in the driver.

Suricata XDP code has been tested with 4.13.10 but 4.15 or later is necessary to use all
features like the CPU redirect map.

If you are using an Intel network card, you will need to stay with in tree kernel NIC drivers.
The out of tree drivers do not contain the XDP support.

Having a network card with support for RSS symmetric hashing is a good point or you will have to
use the XDP CPU redirect map feature.

Prerequisites
-------------

This guide has been confirmed on Debian/Ubuntu "LTS" Linux.

Disable irqbalance
~~~~~~~~~~~~~~~~~~

::

 systemctl stop irqbalance
 systemctl disable irqbalance

Kernel
~~~~~~

You need to run a kernel 4.13 or newer.

Clang
~~~~~

Make sure you have clang (>=3.9) installed on the system  ::

 sudo apt-get install clang

libbpf
~~~~~~

Suricata uses libbpf to interact with eBPF and XDP ::

 git clone https://github.com/libbpf/libbpf.git

Now, you can build and install the library ::

 cd libbpf/src/
 make && sudo make install

 sudo make install_headers
 sudo ldconfig


Compile and install Suricata
----------------------------

To get Suricata source, you can use the usual ::

 git clone  https://github.com/OISF/suricata.git
 cd suricata && git clone https://github.com/OISF/libhtp.git -b 0.5.x

 ./autogen.sh

Then you need to add the ebpf flags to configure ::

 CC=clang ./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ \
 --enable-ebpf --enable-ebpf-build

 make clean && make
 sudo  make install-full
 sudo ldconfig
 sudo mkdir /etc/suricata/ebpf/

The ``clang`` compiler is needed if you want to build eBPF files as the build
is done via a specific eBPF backend available only in llvm/clang suite.

Setup bypass
------------

If you plan to use eBPF or XDP for a kernel/hardware level bypass, you need to enable
some of the following features:

First, enable `bypass` in the `stream` section in ``suricata.yaml`` ::

 stream:
   bypass: true

This will bypass flows as soon as the stream depth will be reached.

If you want, you can also bypass encrypted flows by setting `encryption-handling` to `bypass`
in the app-layer tls section ::

  app-layer:
    protocols:
      tls:
        enabled: yes
        detection-ports:
          dp: 443
  
        encryption-handling: bypass

Another solution is to use a set of signatures using the ``bypass`` keyword to obtain
a selective bypass. Suricata traffic ID defines flowbits that can be used in other signatures.
For instance one could use ::

 alert any any -> any any (msg:"bypass video"; flowbits:isset,traffic/label/video; noalert; bypass; sid:1000000; rev:1;)
 alert any any -> any any (msg:"bypass Skype"; flowbits:isset,traffic/id/skype; noalert; bypass; sid:1000001; rev:1;)

Setup eBPF filter
-----------------

The file `ebpf/vlan_filter.c` contains a list of vlan id in a switch
that you need to edit to get something adapted to your network. Another really
basic filter dropping IPv6 packets is also available in `ebpf/filter.c`.

Suricata can load as eBPF filter any eBPF code exposing a ``filter`` section.

Once modifications and build via `make` are done, you can copy the resulting
eBPF filter as needed ::

 cp ebpf/vlan_filter.bpf /etc/suricata/ebpf/

Then setup the `ebpf-filter-file` variable in af-packet section in ``suricata.yaml`` ::

  - interface: eth3
    threads: 16
    cluster-id: 97
    cluster-type: cluster_flow # choose any type suitable
    defrag: yes
    # eBPF file containing a 'loadbalancer' function that will be inserted into the
    # kernel and used as load balancing function
    ebpf-filter-file:  /etc/suricata/ebpf/vlan_filter.bpf
    use-mmap: yes
    ring-size: 200000

You can then run suricata normally ::

 /usr/bin/suricata --pidfile /var/run/suricata.pid  --af-packet=eth3 -vvv 

Setup eBPF bypass
-----------------

You can also use eBPF bypass. To do that load the `bypass_filter.bpf` file and
update af-packet configuration in ``suricata.yaml`` to set bypass to yes ::

  - interface: eth3
    threads: 16
    cluster-id: 97
    cluster-type: cluster_qm # symmetric RSS hashing is mandatory to use this mode
    # eBPF file containing a 'filter' function that will be inserted into the
    # kernel and used as packet filter function
    ebpf-filter-file:  /etc/suricata/ebpf/bypass_filter.bpf
    bypass: yes
    use-mmap: yes
    ring-size: 200000

Constraints on eBPF code to have a bypass compliant code are stronger than for regular filter. The
filter must expose `flow_table_v4` and `flow_table_v6` per CPU array maps with similar definitions
as the one available in `bypass_filter.c`. These two maps will be accessed and
maintained by Suricata to handle the lists of flow to bypass.

If you are not using vlan tracking (``vlan.use-for-tracking`` set to false in suricata.yaml) then you also have to set
the VLAN_TRACKING define to 0 in ``bypass_filter.c``.

Setup eBPF load balancing
-------------------------

eBPF load balancing allows to load balance the traffic on the listening sockets
With any logic implemented in the eBPF filter. The value returned by the function
tagged with the ``loadbalancer`` section is used with a modulo on the CPU count to know in
which socket the packet has to be send.

An implementation of a simple IP pair hashing function is provided in the ``lb.bpf``
file.

Copy the resulting eBPF filter as needed ::

 cp ebpf/lb.bpf /etc/suricata/ebpf/

Then use ``cluster_ebpf`` as load balancing method in the interface section of af-packet
and point the ``ebpf-lb-file`` variable to the ``lb.bpf`` file ::

  - interface: eth3
    threads: 16
    cluster-id: 97
    cluster-type: cluster_ebpf
    defrag: yes
    # eBPF file containing a 'loadbalancer' function that will be inserted into the
    # kernel and used as load balancing function
    ebpf-lb-file:  /etc/suricata/ebpf/lb.bpf
    use-mmap: yes
    ring-size: 200000

Setup XDP bypass
----------------

XDP bypass will allow Suricata to tell the kernel that packets for some
flows have to be dropped via the XDP mechanism. This is a really early
drop that occurs before the datagram is reaching the Linux kernel
network stack.

Linux 4.15 or newer are recommended to use that feature. You can use it
on older kernel if you set ``BUILD_CPUMAP`` to 0 in ``ebpf/xdp_filter.c``.

Copy the resulting xdp filter as needed::

 cp ebpf/xdp_filter.bpf /etc/suricata/ebpf/

Setup af-packet section/interface in ``suricata.yaml``.

We will use ``cluster_qm`` as we have symmetric hashing on the NIC, ``xdp-mode: driver`` and we will
also use the ``/etc/suricata/ebpf/xdp_filter.bpf`` (in our example TCP offloading/bypass) ::

  - interface: eth3
    threads: 16
    cluster-id: 97
    cluster-type: cluster_qm # symmetric hashing is a must!
    defrag: yes
    # Xdp mode, "soft" for skb based version, "driver" for network card based
    # and "hw" for card supporting eBPF.
    xdp-mode: driver
    xdp-filter-file:  /etc/suricata/ebpf/xdp_filter.bpf
    # if the ebpf filter implements a bypass function, you can set 'bypass' to
    # yes and benefit from these feature
    bypass: yes
    use-mmap: yes
    ring-size: 200000
    # Uncomment the following if you are using hardware XDP with
    # a card like Netronome (default value is yes)
    # use-percpu-hash: no


XDP bypass is compatible with AF_PACKET IPS mode. Packets from bypassed flows will be send directly
from one card to the second card without going by the kernel network stack.

If you are using hardware XDP offload you may have to set ``use-percpu-hash`` to false and
build and install the XDP filter file after setting ``USE_PERCPU_HASH`` to 0.

In the XDP filter file, you can set ``ENCRYPTED_TLS_BYPASS`` to 1 if you want to bypass
the encrypted TLS 1.2 packets in the eBPF code. Be aware that this will mean that Suricata will
be blind on packets on port 443 with the correct pattern.

If you are not using vlan tracking (``vlan.use-for-tracking`` set to false in suricata.yaml) then you also have to set
the VLAN_TRACKING define to 0 in ``xdp_filter.c``.

Intel NIC setup
~~~~~~~~~~~~~~~

Intel network card don't support symmetric hashing but it is possible to emulate
it by using a specific hashing function.

Follow these instructions closely for desired result::

 ifconfig eth3 down

Use in tree kernel drivers: XDP support is not available in Intel drivers available on Intel website.

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

Run the following command to disable offloading ::

 for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
 	/sbin/ethtool -K eth3 $i off 2>&1 > /dev/null;
 done

Balance as much as you can
~~~~~~~~~~~~~~~~~~~~~~~~~~

Try to use the network's card balancing as much as possible ::
 
 for proto in tcp4 udp4 ah4 esp4 sctp4 tcp6 udp6 ah6 esp6 sctp6; do 
 	/sbin/ethtool -N eth3 rx-flow-hash $proto sdfn
 done

The XDP CPU redirect case
~~~~~~~~~~~~~~~~~~~~~~~~~

If ever your hardware is not able to do a symmetric load balancing but support XDP in driver mode, you
can then use the CPU redirect map support available in the xdp_filter.bpf file. In this mode, the load
balancing will be done by the XDP filter and each CPU will handle the whole packet treatment including
the creation of the skb structure in kernel.

You will need Linux 4.15 or newer to use that feature.

To do so set the `xdp-cpu-redirect` variable in af-packet interface configuration to a set of CPUs.
Then use the `cluster_cpu` as load balancing function. You will also need to set the affinity
accordingly.

It is possible to use `xdp_monitor` to have information about the behavior of CPU redirect. This
program is available in Linux tree under the `samples/bpf` directory and will be build by the
make command. Sample output is the following ::

 sudo ./xdp_monitor --stats
 XDP-event       CPU:to  pps          drop-pps     extra-info
 XDP_REDIRECT    11      2,880,212    0            Success
 XDP_REDIRECT    total   2,880,212    0            Success
 XDP_REDIRECT    total   0            0            Error
 cpumap-enqueue   11:0   575,954      0            5.27       bulk-average
 cpumap-enqueue  sum:0   575,954      0            5.27       bulk-average
 cpumap-kthread  0       575,990      0            56,409     sched
 cpumap-kthread  1       576,090      0            54,897     sched

Start Suricata with XDP
~~~~~~~~~~~~~~~~~~~~~~~

You can now start Suricata with XDP bypass activated ::

 /usr/bin/suricata -c /etc/suricata/xdp-suricata.yaml --pidfile /var/run/suricata.pid  --af-packet=eth3 -vvv 

Confirm you have the XDP filter engaged in the output (example)::

 ...
 ...
 (runmode-af-packet.c:220) <Config> (ParseAFPConfig) -- Enabling locked memory for mmap on iface eth3
 (runmode-af-packet.c:231) <Config> (ParseAFPConfig) -- Enabling tpacket v3 capture on iface eth3
 (runmode-af-packet.c:326) <Config> (ParseAFPConfig) -- Using queue based cluster mode for AF_PACKET (iface eth3)
 (runmode-af-packet.c:424) <Info> (ParseAFPConfig) -- af-packet will use '/etc/suricata/ebpf/xdp_filter.bpf' as XDP filter file
 (runmode-af-packet.c:429) <Config> (ParseAFPConfig) -- Using bypass kernel functionality for AF_PACKET (iface eth3)
 (runmode-af-packet.c:609) <Config> (ParseAFPConfig) -- eth3: enabling zero copy mode by using data release call
 (util-runmodes.c:296) <Info> (RunModeSetLiveCaptureWorkersForDevice) -- Going to use 8 thread(s)
 ...
 ...

Pinned maps usage
-----------------

Pinned maps stay attached to the system if the creating process disappears and
they can also be accessed by external tools. In Suricata bypass case, this can be
used to keep active bypassed flow tables, so Suricata is not hit by previously bypassed flows when
restarting. In the socket filter case, this can be used to maintain a map from tools outside
of Suricata.

To use pinned maps, you first have to mount the `bpf` pseudo filesystem ::

  sudo mount -t bpf none /sys/fs/bpf

You can also add to your `/etc/fstab` ::

 bpffs                      /sys/fs/bpf             bpf     defaults 0 0

and run `sudo mount -a`.

Pinned maps will be accessible as file from the `/sys/fs/bpf` directory. Suricata
will pin them under the name `suricata-$IFACE_NAME-$MAP_NAME`.

To activate pinned maps for a interface, set `pinned-maps` to `true` in the `af-packet`
configuration of this interface ::

  - interface: eth3
    pinned-maps: true

This option can be used to expose the maps of a socket filter to other processes.
This allows for example, the external handling of a accept list or block list of
IP addresses. See `scbpf` tool avalable in the `ebpf/scpbf` directory for an example
of external list handling.

In the case of XDP, the eBPF filter is attached to the interface so if you
activate `pinned-maps` the eBPF will remain attached to the interface and
the maps will remain accessible upon Suricata start.
If XDP bypass is activated, Suricata will try at start to open the pinned maps
`flow_v4_table` and `flow_v6_table`. If they are present, this means the XDP filter
is still there and Suricata will just use them instead of attaching the XDP file to
the interface.

So if you want to reload the XDP filter, you need to remove the files from `/sys/fs/bpf/`
before starting Suricata.

In case, you are not using bypass, this means that the used maps are managed from outside
Suricata. As their names are not known by Suricata, you need to specify a name of a map to look
for, that will be used to check for the presence of the XDP filter ::

  - interface: eth3
    pinned-maps: true
    pinned-maps-name: ipv4_drop
    xdp-filter-file: /etc/suricata/ebpf/xdp_filter.bpf

If XDP bypass is used in IPS mode stopping Suricata will trigger an interruption in the traffic.
To fix that, the provided XDP filter `xdp_filter.bpf` is containing a map that will trigger
a global bypass if set to 1. You need to use `pinned-maps` to benefit from this feature.

To use it you need to set `#define USE_GLOBAL_BYPASS   1` (instead of 0) in the `xdp_filter.c` file and rebuild
the eBPF code and install the eBPF file in the correct place. If you write `1` as key `0` then the XDP
filter will switch to global bypass mode. Set key `0` to value `0` to send traffic to Suricata.

The switch must be activated on all sniffing interfaces. For an interface named `eth0` the global
switch map will be `/sys/fs/bpf/suricata-eth0-global_bypass`.

Hardware bypass with Netronome
------------------------------

Netronome cards support hardware bypass. In this case the eBPF code is running in the card
itself. This introduces some architectural differences compared to driver mode and the configuration
and eBPF filter need to be updated.

On eBPF side, as of Linux 4.19 CPU maps and interfaces redirect are not supported and these features
need to be disabled. By architecture, per CPU hash should not be used and has to be disabled.
To achieve this, edit the beginning of `ebpf/xdp_filter.c` and do ::

 #define BUILD_CPUMAP        0
 /* Increase CPUMAP_MAX_CPUS if ever you have more than 64 CPUs */
 #define CPUMAP_MAX_CPUS     64

 #define USE_PERCPU_HASH    0
 #define GOT_TX_PEER    0

Then build the bpf file with `make` and install it in the expected place.

On Suricata configuration side, this is rather simple as you need to activate
hardware mode and the `no-percpu-hash` option in the `af-packet` configuration
of the interface ::

    xdp-mode: hw
    no-percpu-hash: true

The load  balancing will be done on IP pairs inside the eBPF code, so
using `cluster_qm` as cluster type is a good idea ::

    cluster-type: cluster_qm

As of Linux 4.19, the number of threads must be a power of 2. So set
`threads` variable of the `af-packet` interface to a power
of 2 and in the eBPF filter set the following variable accordingly ::

 #define RSS_QUEUE_NUMBERS   32

Getting live info about bypass
------------------------------

You can get information about bypass via the stats event and through the unix socket.
``iface-stat`` will return the number of bypassed packets (adding packets for a flow when it timeout) ::

 suricatasc -c "iface-stat enp94s0np0" | jq
 {
   "message": {
     "pkts": 56529854964,
     "drop": 932328611,
     "bypassed": 1569467248,
     "invalid-checksums": 0
   },
   "return": "OK"
 }

``iface-bypassed-stats`` command will return the number of elements in IPv4 and IPv6 flow tables for
each interface ::

 # suricatasc
 >>> iface-bypassed-stats
 Success:
 {
     "enp94s0np0": {
        "ipv4_fail": 0,
        "ipv4_maps_count": 2303,
        "ipv4_success": 4232,
        "ipv6_fail": 0,
        "ipv6_maps_count": 13131,
        "ipv6_success": 13500

     }
 }

The stats entry also contains a `stats.flow_bypassed` object that has local and capture
bytes and packets counters as well as a bypassed and closed flow counter ::

 {
   "local_pkts": 0,
   "local_bytes": 0,
   "local_capture_pkts": 20,
   "local_capture_bytes": 25000,
   "closed": 84,
   "pkts": 4799,
   "bytes": 2975133
 }

`local_pkts` and `local_bytes` are for Suricata bypassed flows. This can be because
local bypass is used or because the capture method can not bypass more flows.
`pkts` and `bytes` are counters coming from the capture method. They can take some
time to appear due to the accounting at timeout.
`local_capture_pkts` and `local_capture_bytes` are counters for packets that are seen
by Suricata before the capture method efficiently bypass the traffic. There is almost
always some for each flow because of the buffer in front of Suricata reading threads.
