.. _dpdk:

DPDK
====

Introduction
-------------

The Data Plane Development Kit (DPDK) is a set of libraries and drivers that
enhance and speed up packet processing in the data plane. Its primary use is to
provide faster packet processing by bypassing the kernel network stack, which
can provide significant performance improvements. For detailed instructions on
how to setup DPDK, please refer to :doc:`../configuration/suricata-yaml` to
learn more about the basic setup for DPDK.
The following sections contain examples of how to set up DPDK and Suricata for
more obscure use-cases.

Bond interface
--------------

Link Bonding Poll Mode Driver (Bond PMD), is a software
mechanism provided by the Data Plane Development Kit (DPDK) for aggregating
multiple physical network interfaces into a single logical interface.
Bonding can be e.g. used to:

* deliver bidirectional flows of tapped interfaces to the same worker,
* establish redundancy by monitoring multiple links,
* improve network performance by load-balancing traffic across multiple links.

Bond PMD is essentially a virtual driver that manipulates with multiple
physical network interfaces. It can operate in multiple modes as described
in the `DPDK docs
<https://doc.dpdk.org/guides/prog_guide/link_bonding_poll_mode_drv_lib.html>`_
The individual bonding modes can accustom user needs.
DPDK Bond PMD has a requirement that the aggregated interfaces must be
the same device types - e.g. both physical ports run on mlx5 PMD.
Bond PMD supports multiple queues and therefore can work in workers runmode.
It should have no effect on traffic distribution of the individual ports and
flows should be distributed by physical ports according to the RSS
configuration the same way as if they would be configured independently.

As an example of Bond PMD, we can setup Suricata to monitor 2 interfaces
that receive TAP traffic from optical interfaces. This means that Suricata
receive one direction of the communication on one interface and the other
direction is received on the other interface.

::

    ...
    dpdk:
      eal-params:
        proc-type: primary
        vdev: 'net_bonding0,mode=0,slave=0000:04:00.0,slave=0000:04:00.1'

      # DPDK capture support
      # RX queues (and TX queues in IPS mode) are assigned to cores in 1:1 ratio
      interfaces:
        - interface: net_bonding0 # PCIe address of the NIC port
          # Threading: possible values are either "auto" or number of threads
          # - auto takes all cores
          # in IPS mode it is required to specify the number of cores and the
          # numbers on both interfaces must match
          threads: 4
    ...

In the DPDK part of suricata.yaml we have added a new parameter to the
eal-params section for virtual devices - `vdev`.
DPDK Environment Abstraction Layer (EAL) can initialize some virtual devices
during the initialization of EAL.
In this case, EAL creates a new device of type `net_bonding`. Suffix of
`net_bonding` signifies the name of the interface (in this case the zero).
Extra arguments are passed after the device name, such as the bonding mode
(`mode=0`). This is the round-robin mode as is described in the DPDK
documentation of Bond PMD.
Members (slaves) of the `net_bonding0` interface are appended after
the bonding mode parameter.

When the device is specified within EAL parameters, it can be used within
Suricata `interfaces` list. Note that the list doesn't contain PCIe addresses
of the physical ports but instead the `net_bonding0` interface.
Threading section is also adjusted according to the items in the interfaces
list by enablign set-cpu-affinity and listing CPUs that should be used in
management and worker CPU set.

::

    ...
    threading:
      set-cpu-affinity: yes
      cpu-affinity:
        - management-cpu-set:
            cpu: [ 0 ]  # include only these CPUs in affinity settings
        - receive-cpu-set:
            cpu: [ 0 ]  # include only these CPUs in affinity settings
        - worker-cpu-set:
            cpu: [ 2,4,6,8 ]
    ...
