
Set up
======

XDP
---

XDP provides another Linux native way of optimising Suricata's performance on sniffing high speed networks.

::

 XDP or eXpress Data Path provides a high performance, programmable network data path in the Linux kernel as part of the IO Visor Project. XDP provides bare metal packet processing at the lowest point in the software stack which makes it ideal for speed without compromising programmability. Furthermore, new functions can be implemented dynamically with the integrated fast path without kernel modification.

`More info about XDP <https://www.iovisor.org/technology/xdp>`__

Requirements
------------

- Newer kernel that supports XDP (4.13.10 in our case)
- RSS symmetric hashing on the NIC ( Intel 82599ES 10-Gigabit/x520/x540 in our case)
- In tree kernel drivers NIC drivers

Prerequisites
-------------

This guide has been confirmed on Debian/Ubutnu LTS Linux.

Disable irqbalance
~~~~~~~~~~~~~~~~~~

::

 systemctl stop irqbalance
 systemctl disable irqbalance

Kernel
~~~~~~

Install kernel 4.13.+ and reboot.

Clang
~~~~~

Make sure you have clang installed on the system.
::

 apt-get install clang

BPF
~~~

Suricata use libbpf to interact with eBPF and XDP. This library is available
in the Linux tree. Before 4.16, a patched libbpf library is also needed::

 git clone -b libbpf-xdp  https://github.com/regit/linux.git

If you have a recent enough kernel, you can skip this part.

Now, you can build and install the library ::

 cd linux/tools/lib/bpf/
 make && sudo make install

 sudo mkdir -p /usr/local/include/bpf/
 sudo cp *bpf.h /usr/local/include/bpf/
 sudo ldconfig


Compile and install Suricata
----------------------------

::

 git clone  https://github.com/OISF/suricata.git
 cd suricata && git clone https://github.com/OISF/libhtp.git -b 0.5.x

 ./autogen.sh

 CC=clang ./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ \
 --enable-ebpf --enable-ebpf-build

 make clean && make
 sudo  make install-full
 sudo ldconfig
 sudo mkdir /etc/suricata/ebpf/

Copy the resulting xdp fiter as needed::

 cp src/ebpf/xdp_filter.bpf /etc/suricata/ebpf/

Setup af-packet section/interface in ``suricata.yaml``.

We will use ``cluster_qm`` as we have symmetric hashing on the NIC, ``xdp-mode: driver`` and we will
also use the ``/etc/suricata/ebpf/xdp_filter.bpf`` (in our example TCP offloading/bypass) ::

  - interface: eth3
    threads: 16
    cluster-id: 97
    cluster-type: cluster_qm # symmetric hashing  is a must!
    defrag: yes
    # eBPF file containing a 'loadbalancer' function that will be inserted into the
    # kernel and used as load balancing function
    #ebpf-lb-file:  /etc/suricata/ebpf/lb.bpf
    # eBPF file containing a 'filter' function that will be inserted into the
    # kernel and used as packet filter function
    # eBPF file containing a 'xdp' function that will be inserted into the
    # kernel and used as XDP packet filter function
    #ebpf-filter-file:  /etc/suricata/ebpf/filter.bpf
    # Xdp mode, "soft" for skb based version, "driver" for network card based
    # and "hw" for card supporting eBPF.
    xdp-mode: driver
    xdp-filter-file:  /etc/suricata/ebpf/xdp_filter.bpf
    # if the ebpf filter implements a bypass function, you can set 'bypass' to
    # yes and benefit from these feature
    bypass: yes
    use-mmap: yes
    ring-size: 200000

Also enable "bypass" in the "stream" section ::

 stream:
   bypass: true

If you with you can also bypass encrypted flow by setting no-reassemble to yes
in the app-layer tls section ::

  app-layer:
    protocols:
      tls:
        enabled: yes
        detection-ports:
          dp: 443
  
        # Completely stop processing TLS/SSL session after the handshake
        # completed. If bypass is enabled this will also trigger flow
        # bypass. If disabled (the default), TLS/SSL session is still
        # tracked for Heartbleed and other anomalies.
        no-reassemble: yes


Setup symmetric hashing on the NIC
----------------------------------

Follow these instructions closely for desired result::

 ifconfig eth3 down

Use in tree kernel drivers, XDP support is not available in out of source Intel drivers.

*NOTE:* In this case the kernel and sources used is 4.13.10

Reload the module with updated parameters ::

 cd /lib/modules/4.13.10-amd64/kernel/drivers/net/ethernet/intel/ixgbe
 rmmod ixgbe &&  insmod ixgbe.ko MQ=1,1 RSS=0,0 InterruptThrottleRate=12500,12500 LRO=0,0 vxlan_rx=0,0

Enable symmetric hashing::

 ifconfig eth3 down 
 ethtool -L eth3 combined 16
 ethtool -K eth3 rxhash on 
 ethtool -K eth3 ntuple on
 ifconfig eth3 up
 ./set_irq_affinity 0-15 eth3
 ethtool -X eth3 hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 16
 ethtool -x eth3
 ethtool -n eth3

In the above set up you are free to use any recent ``set_irq_affinity`` script. It is available in any Intel x520/710 NIC sources driver download.

**NOTE:**
We use a special low entropy key for the symmetric hashing. `More info about the research for symmetric hashing set up <http://www.ndsl.kaist.edu/~kyoungsoo/papers/TR-symRSS.pdf>`_

Disable an NIC offloading
-------------------------

Run the following to disable offloading ::

 for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
 	/sbin/ethtool -K eth3 $i off 2>&1 > /dev/null;
 done

Balance as much as you can
--------------------------

Try to use the network's card balancing as much as possible ::
 
 for proto in tcp4 udp4 ah4 esp4 sctp4 tcp6 udp6 ah6 esp6 sctp6; do 
 	/sbin/ethtool -N eth3 rx-flow-hash $proto sdfn
 done

Start Suricata with XDP
-----------------------

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
