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

Hugepage analysis
-----------------

Suricata can analyse utilized hugepages on the system. This can be particularly 
beneficial when there's a potential overallocation of hugepages. 
The hugepage analysis is designed to examine the hugepages in use and 
provide recommendations on an adequate number of hugepages. This then ensures 
Suricata operates optimally while leaving sufficient memory for other 
applications on the system. The analysis works by comparing snapshots of the
hugepages before and after Suricata is initialized. After the initialization,
no more hugepages are allocated by Suricata.
The hugepage analysis can be seen in the Perf log level and is printed out 
during the Suricata start. It is only printed when Suricata detects some 
disrepancies in the system related to hugepage allocation.

It's recommended to perform this analysis from a "clean" state - 
that is a state when all your hugepages are free. It is especially recommended 
when no other hugepage-dependent applications are running on your system.
This can be checked in one of two ways:

.. code-block:: 

  # global check
  cat /proc/meminfo

  HugePages_Total:    1024
  HugePages_Free:     1024

  # per-numa check depends on NUMA node ID, hugepage size, 
  # and nr_hugepages/free_hugepages - e.g.:
  cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages

After the termination of Suricata and other hugepage-related applications, 
if the count of free hugepages is not equal with the total number of hugepages, 
it indicates some hugepages were not freed completely.
This can be fixed by removing DPDK-related files from the hugepage-mounted 
directory (filesystem). 
It's important to exercise caution while removing hugepages, especially when 
other hugepage-dependent applications are in operation, as this action will 
disrupt their memory functionality.
Removing the DPDK files from the hugepage directory can often be done as:

.. code-block:: bash

  sudo rm -rf /dev/hugepages/rtemap_*

  # To check where hugepages are mounted:
  dpdk-hugepages.py -s
  # or 
  mount | grep huge

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

Interrupt (power-saving) mode
-----------------------------

The DPDK is traditionally recognized for its polling mode operation. 
In this mode, CPU cores are continuously querying for packets from 
the Network Interface Card (NIC). While this approach offers benefits like 
reduced latency and improved performance, it might not be the most efficient 
in scenarios with sporadic or low traffic. 
The constant polling can lead to unnecessary CPU consumption. 
To address this, DPDK offers an `interrupt` mode.

The obvious advantage that interrupt mode brings is power efficiency. 
So far in our tests, we haven't observed a decrease in performance. Suricata's
performance has actually seen a slight improvement.
The (IPS runmode) users should be aware that interrupts can 
introduce non-deterministic latency. However, the latency should never be 
higher than in other (e.g. AF_PACKET/AF_XDP/...) capture methods. 

Interrupt mode in DPDK can be configured on a per-interface basis. 
This allows for a hybrid setup where some workers operate in polling mode, 
while others utilize the interrupt mode. 
The configuration for the interrupt mode can be found and modified in the 
DPDK section of the suricata.yaml file.

Below is a sample configuration that demonstrates how to enable the interrupt mode for a specific interface:

::

  ...
  dpdk:
      eal-params:
        proc-type: primary

      interfaces:
        - interface: 0000:3b:00.0
          interrupt-mode: true
          threads: 4

Drop filter
-----------------------------

Drop filter can improve the performance of Suricata by filtering 
used-predefined flows directly in the Network interface card. The user can 
specify unwanted flows before the start of Suricata. These flows are not going to be 
inspected by Suricata and will be ignored for the whole run of the program.
On some PMDs, the statistics of the dropped flows are gathered and stored in eve.json.

The syntax for drop filter in Suricata is similar to the dpdk-testpmd application
rule syntax, although in Suricata, only the "pattern" section is applicable. 
The user can define multiple rules, either to match specific flow 
or a range of flows (e.g. using ip or port masks).

Patterns currently supported by this feature are listed in 
"src/util-dpdk-rte-flow-pattern.c" in "enum index next_item[]" 
and their corresponding attributes in "enum index item_<pattern>[]".

.. code-block:: C

    enum index {
      /* Special tokens. */
      ZERO = 0,
      END,

      /* Create tokens */
      CREATE,

      /* Common tokens. */
      COMMON_UNSIGNED,
      COMMON_MAC_ADDR,
      COMMON_IPV4_ADDR,
      COMMON_IPV6_ADDR,

      /* Validate/create pattern. */
      ITEM_PATTERN,
      ITEM_PARAM_IS,
      ITEM_PARAM_SPEC,
      ITEM_PARAM_LAST,
      ITEM_PARAM_MASK,
      ITEM_NEXT,
      ITEM_END,
      ITEM_VOID,
      ITEM_ANY,
      ITEM_PORT_ID,
      ITEM_ETH,
      ITEM_ETH_DST,
      ITEM_ETH_SRC,
      ITEM_ETH_TYPE,
      ITEM_ETH_HAS_VLAN,
      ITEM_RAW,
      ITEM_VLAN,
      ITEM_IPV4,
      ITEM_IPV4_SRC,
      ITEM_IPV4_DST,
      ITEM_IPV6,
      ITEM_IPV6_SRC,
      ITEM_IPV6_DST,
      ITEM_ICMP,
      ITEM_ICMP_TYPE,
      ITEM_ICMP_CODE,
      ITEM_ICMP_IDENT,
      ITEM_ICMP_SEQ,
      ITEM_ICMP6,
      ITEM_ICMP6_TYPE,
      ITEM_ICMP6_CODE,
      ITEM_UDP,
      ITEM_UDP_SRC,
      ITEM_UDP_DST,
      ITEM_TCP,
      ITEM_TCP_SRC,
      ITEM_TCP_DST,
      ITEM_TCP_FLAGS,
      ITEM_SCTP,
      ITEM_SCTP_SRC,
      ITEM_SCTP_DST,
      ITEM_SCTP_TAG,
      ITEM_SCTP_CKSUM,
      ITEM_VXLAN,
      ITEM_E_TAG,
      ITEM_NVGRE,
      ITEM_MPLS,
      ITEM_GRE,
      ITEM_FUZZY,
      ITEM_GTP,
      ITEM_GTPC,
      ITEM_GTPU,
      ITEM_GENEVE,
      ITEM_VXLAN_GPE,
    };

This feature is supported and tested only on NICs wih mlx5, ice and i40e 
drivers. The level of functionality varies between these cards, 
the most versatile are cards with mlx5 drivers.

ice does not support broad patterns; some pattern item has to have
specification, e.g., ``pattern eth / ipv4 / end`` raises an error but
``pattern eth / ipv4 src is x / end`` or ``pattern eth / ipv4 / tcp src is x`` works fine.

i40e does not support different item sets on the same pattern item type,
e.g., if the first rule is in the form "pattern eth / ipv4 src is x / end",
then if any other rule contains an ipv4 pattern type, it needs to have
exclusively attribute src.

The configuration for the drop filter can be found and modified in the 
DPDK section of the suricata.yaml file.

The statistics can be gathered on mlx5 and ice drivers.
The number of filtered packets is stored in dpdk.rte_flow_filtered field in eve.json.
ice driver gathers statistics only in the case when all of the rules match one specific flow
(e.g. mask can not be used).

Below is a sample configuration that demonstrates how to filter specific flow and a range of flows:

::

  ...
  dpdk:
      eal-params:
        proc-type: primary

      interfaces:
        - interface: 0000:3b:00.0
          drop-filter:
            - rule: "pattern eth / ipv4 src is 192.11.120.50 / tcp / end"
            - rule: "pattern eth / ipv4 src is 170.22.40.0 src mask 255.255.255.0 / tcp / end"
