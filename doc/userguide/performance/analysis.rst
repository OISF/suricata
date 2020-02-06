Performance Analysis
=====================

There are many possibilities that could be the reason for performance issues.
In this section we will guide you through some options.

General
-------

First of all you should check all the log files with a focus on stats.log and
suricata.log if any obvious issues are seen. There are several tools that can
help to find a root cause.

A first step is to run a tool like **htop** to get an overview of the system
load and if there is a bottleneck with the traffic distribution. For example if
you can see that only a small number of cpu cores hit 100% all the time and
others don't, it could be related to a bad traffic distribution or elephant
flows. In the first case try to improve the configuration, in the other case
try to filter or shunt those big flows with either bpf filter, bypass rules or
eBPF/XDP.

Another helpful tool is **perf** which helps to spot performance issues. Make
sure you have it installed and also the debug symbols installed for Suricata or
the output won't be very helpful. This output is also helpful when you report
performance issues as the Suricata Development team can narrow down possible
issues with that.

::

    sudo perf top -p $(pidof suricata)

If you see specific function calls at the top in red it's a hint that those are
the bottlenecks. For example if you see **IPOnlyMatchPacket** it can be either
a result of high drop rates or incomplete flows which result in decreased
performance. To look into the performance issues on a specific thread you can
pass **-t TID** to perf top.

Another recommendation is to run Suricata without any rules to see if it's
mainly related to the traffic. It can also be helpful to use rule-profiling
and/or packet-profiling at this step. This is achieved by compiling Suricata
with **enable-profiling** but keep in mind that this has an impact on
performance and should only be used for troubleshooting.

Traffic
-------

In most cases where the hardware is fast enough to handle the traffic but the
drop rate is still high it's related to specific traffic issues.

First steps to check are:

- Check if the traffic is bidirectional, if it's mostly unidirectional you're missing relevant parts of the flow (see **tshark** example at the bottom). Another indicator could be a big discrepancy between SYN and SYN-ACK as well as RST counter in the Suricata stats.
- Check for encapsulated traffic, while GRE, MPLS etc. are supported they could also lead to performance issues. Especially if there are several layers of encapsulation
- Use tools like **iftop** to spot elephant flows. Flows that have a rate of over 1Gbit/s for a long time can result in one cpu core at 100% all the time and increasing the droprate while it doesn't make sense to dig deep into this traffic.
- If VLAN is used it might help to disable **vlan.use-for-tracking** especially in scenarios where only one direction of the flow has the VLAN tag
- If VLAN QinQ (IEEE 802.1ad) is used be very cautious if you use **cluster_qm** in combinatin with Intel drivers and AF_PACKET runmode. While the RFC expects ethertype 0x8100 and 0x88A8 in this case (see https://en.wikipedia.org/wiki/IEEE_802.1ad) most implementations only add 0x8100 on each layer. If the first seen layer has the same VLAN tag but the inner one has different VLAN tags it will still end up in the same queue in **cluster_qm** mode. This was observed with the i40e driver up to 2.8.20 and the firmare version up to 7.00, feel free to report if newer versions have fixed this.
- Check for other unusual or complex protocols that aren't supported very well. In several cases we've seen that Cisco Fabric Path (ethertype 0x8903) causes performance issues. It's recommended to filter it, one option would be a bpf filter with **not ether proto 0x8903**
- Another approach to narrow down issues is the usage of **bpf filter**. For example filter all HTTPS traffic with **not port 443** to exclude traffic that might be problematic or just look into one specific port **port 25** if you expect some issues with a specific protocol.

Suricata also provides several specific traffic related signatures in the rules
folder that could be enabled for testing to spot specific traffic issues.

If you want to use **tshark** to get an overview of the traffic direction use this command:

::

    sudo tshark -i $INTERFACE -q -z conv,ip -a duration:10

The output will show you all flows within 10s and if you see 0 for one
direction you have unidirectional traffic, thus you don't see the ACK packets
for example.
