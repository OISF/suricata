Ignoring Traffic
================

In some cases there are reasons to ignore certain traffic. Certain hosts
may be trusted, or perhaps a backup stream should be ignored.

This document lists some strategies for ignoring traffic.

capture filters (BPF)
---------------------

Through BPFs the capture methods pcap, af-packet and pf_ring can be
told what to send to Suricata, and what not. For example a simple
filter 'tcp' will only send tcp packets.

If some hosts and or nets need to be ignored, use something like "not
(host IP1 or IP2 or IP3 or net NET/24)".

Example::

    not host 1.2.3.4

Capture filters are specified on the commandline after all other options::

    suricata -i eth0 -v not host 1.2.3.4
    suricata -i eno1 -c suricata.yaml tcp or udp

Capture filters can be set per interface in the pcap, af-packet, netmap
and pf_ring sections. It can also be put in a file::

    echo "not host 1.2.3.4" > capture-filter.bpf
    suricata -i ens5f0 -F capture-filter.bpf

Using a capture filter limits what traffic Suricata processes. So the
traffic not seen by Suricata will not be inspected, logged or otherwise
recorded.

pass rules
----------

Pass rules are Suricata rules that if matching, pass the packet and in
case of TCP the rest of the flow. They look like normal rules, except
that instead of 'alert' or 'drop' they start with 'pass'.

Example:

::

  pass ip 1.2.3.4 any <> any any (msg:"pass all traffic from/to 1.2.3.4"; sid:1;)

A big difference with capture filters is that logs such as Eve or http.log
are still generated for this traffic.

suppress
--------

Suppress rules can be used to make sure no alerts are generated for a
host. This is not efficient however, as the suppression is only
considered post-matching. In other words, Suricata first inspects a
rule, and only then will it consider per-host suppressions.

Example:

::

  suppress gen_id 0, sig_id 0, track by_src, ip 1.2.3.4
