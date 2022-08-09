Ignoring Traffic
================

In some cases there are reasons to ignore certain traffic. Certain hosts
may be trusted, or perhaps a backup stream should be ignored.

capture filters (BPF)
---------------------

Through BPFs the capture methods pcap, af-packet, netmap  and pf_ring can be
told what to send to Suricata, and what not. For example a simple
filter 'tcp' will only capture tcp packets.

If some hosts and or nets need to be ignored, use something like "not
(host IP1 or IP2 or IP3 or net NET/24)".

Example::

    not host 1.2.3.4

Capture filters are specified on the command-line after all other options::

    suricata -i eth0 -v not host 1.2.3.4
    suricata -i eno1 -c suricata.yaml tcp or udp

Capture filters can be set per interface in the pcap, af-packet, netmap
and pf_ring sections. It can also be put in a file::

    echo "not host 1.2.3.4" > capture-filter.bpf
    suricata -i ens5f0 -F capture-filter.bpf

Using a capture filter limits what traffic Suricata processes. So the
traffic not seen by Suricata will not be inspected, logged or otherwise
recorded.

BPF and IPS
^^^^^^^^^^^

In case of IPS modes using af-packet and netmap, BPFs affect how traffic
is forwarded. If a capture NIC does not capture a packet because of a BPF,
it will also not be forwarded to the peering NIC.

So in the example of `not host 1.2.3.4`, traffic to and from the IP `1.2.3.4`
is effectively dropped.

pass rules
----------

Pass rules are Suricata rules that if matching, pass the packet and in
case of TCP the rest of the flow. They look like normal rules, except
that instead of `alert` or `drop` they use `pass` as the action.

Example::

  pass ip 1.2.3.4 any <> any any (msg:"pass all traffic from/to 1.2.3.4"; sid:1;)

A big difference with capture filters is that logs such as Eve or http.log
are still generated for this traffic.

suppress
--------

Suppress rules can be used to make sure no alerts are generated for a
host. This is not efficient however, as the suppression is only
considered post-matching. In other words, Suricata first inspects a
rule, and only then will it consider per-host suppressions.

Example::

  suppress gen_id 0, sig_id 0, track by_src, ip 1.2.3.4


encrypted traffic
-----------------

The TLS app layer parser has the ability to stop processing encrypted traffic
after the initial handshake. By setting the `app-layer.protocols.tls.encryption-handling`
option to `bypass` the rest of this flow is ignored. If flow bypass is enabled,
the bypass is done in the kernel or in hardware.

bypassing traffic
-----------------

Aside from using the ``bypass`` keyword in rules, there are three other ways
to bypass traffic.

- Within suricata (local bypass). Suricata reads a packet, decodes it, checks
  it in the flow table. If the corresponding flow is local bypassed then it
  simply skips all streaming, detection and output and the packet goes directly
  out in IDS mode and to verdict in IPS mode.

- Within the kernel (capture bypass). When Suricata decides to bypass it calls
  a function provided by the capture method to declare the bypass in the
  capture. For NFQ this is a simple mark that will be used by the
  iptables/nftablesruleset. For AF_PACKET this will be a call to add an element
  in an eBPF hash table stored in kernel.

- Within the NIC driver. This method relies upon XDP, XDP can process the
  traffic prior to reaching the kernel.

Additional bypass documentation:

https://suricon.net/wp-content/uploads/2017/12/SuriCon17-Manev_Purzynski.pdf
https://www.stamus-networks.com/2016/09/28/suricata-bypass-feature/
