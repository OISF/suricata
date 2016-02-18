Statistics
==========

The stats.log produces statistics records on a fixed interval, by
default every 8 seconds.

stats.log file
--------------

::

  -------------------------------------------------------------------
  Counter                   | TM Name                   | Value
  -------------------------------------------------------------------
  flow_mgr.closed_pruned    | FlowManagerThread         | 154033
  flow_mgr.new_pruned       | FlowManagerThread         | 67800
  flow_mgr.est_pruned       | FlowManagerThread         | 100921
  flow.memuse               | FlowManagerThread         | 6557568
  flow.spare                | FlowManagerThread         | 10002
  flow.emerg_mode_entered   | FlowManagerThread         | 0
  flow.emerg_mode_over      | FlowManagerThread         | 0
  decoder.pkts              | RxPcapem21                | 450001754
  decoder.bytes             | RxPcapem21                | 409520714250
  decoder.ipv4              | RxPcapem21                | 449584047
  decoder.ipv6              | RxPcapem21                | 9212
  decoder.ethernet          | RxPcapem21                | 450001754
  decoder.raw               | RxPcapem21                | 0
  decoder.sll               | RxPcapem21                | 0
  decoder.tcp               | RxPcapem21                | 448124337
  decoder.udp               | RxPcapem21                | 542040
  decoder.sctp              | RxPcapem21                | 0
  decoder.icmpv4            | RxPcapem21                | 82292
  decoder.icmpv6            | RxPcapem21                | 9164
  decoder.ppp               | RxPcapem21                | 0
  decoder.pppoe             | RxPcapem21                | 0
  decoder.gre               | RxPcapem21                | 0
  decoder.vlan              | RxPcapem21                | 0
  decoder.avg_pkt_size      | RxPcapem21                | 910
  decoder.max_pkt_size      | RxPcapem21                | 1514
  defrag.ipv4.fragments     | RxPcapem21                | 4
  defrag.ipv4.reassembled   | RxPcapem21                | 1
  defrag.ipv4.timeouts      | RxPcapem21                | 0
  defrag.ipv6.fragments     | RxPcapem21                | 0
  defrag.ipv6.reassembled   | RxPcapem21                | 0
  defrag.ipv6.timeouts      | RxPcapem21                | 0
  tcp.sessions              | Detect                    | 41184
  tcp.ssn_memcap_drop       | Detect                    | 0
  tcp.pseudo                | Detect                    | 2087
  tcp.invalid_checksum      | Detect                    | 8358
  tcp.no_flow               | Detect                    | 0
  tcp.reused_ssn            | Detect                    | 11
  tcp.memuse                | Detect                    | 36175872
  tcp.syn                   | Detect                    | 85902
  tcp.synack                | Detect                    | 83385
  tcp.rst                   | Detect                    | 84326
  tcp.segment_memcap_drop   | Detect                    | 0
  tcp.stream_depth_reached  | Detect                    | 109
  tcp.reassembly_memuse     | Detect                    | 67755264
  tcp.reassembly_gap        | Detect                    | 789
  detect.alert              | Detect                    | 14721

Detecting packet loss
~~~~~~~~~~~~~~~~~~~~~

At shut down, Suricata reports the packet loss statistics it gets from
pcap, pfring or afpacket

::

  [18088] 30/5/2012 -- 07:39:18 - (RxPcapem21) Packets 451595939, bytes 410869083410
  [18088] 30/5/2012 -- 07:39:18 - (RxPcapem21) Pcap Total:451674222 Recv:451596129 Drop:78093 (0.0%).

Usually, this is not the complete story though. These are kernel drop
stats, but the NIC may also have dropped packets. Use ethtool to get
to those:

::

  # ethtool -S em2
  NIC statistics:
       rx_packets: 35430208463
       tx_packets: 216072
       rx_bytes: 32454370137414
       tx_bytes: 53624450
       rx_broadcast: 17424355
       tx_broadcast: 133508
       rx_multicast: 5332175
       tx_multicast: 82564
       rx_errors: 47
       tx_errors: 0
       tx_dropped: 0
       multicast: 5332175
       collisions: 0
       rx_length_errors: 0
       rx_over_errors: 0
       rx_crc_errors: 51
       rx_frame_errors: 0
       rx_no_buffer_count: 0
       rx_missed_errors: 0
       tx_aborted_errors: 0
       tx_carrier_errors: 0
       tx_fifo_errors: 0
       tx_heartbeat_errors: 0
       tx_window_errors: 0
       tx_abort_late_coll: 0
       tx_deferred_ok: 0
       tx_single_coll_ok: 0
       tx_multi_coll_ok: 0
       tx_timeout_count: 0
       tx_restart_queue: 0
       rx_long_length_errors: 0
       rx_short_length_errors: 0
       rx_align_errors: 0
       tx_tcp_seg_good: 0
       tx_tcp_seg_failed: 0
       rx_flow_control_xon: 0
       rx_flow_control_xoff: 0
       tx_flow_control_xon: 0
       tx_flow_control_xoff: 0
       rx_long_byte_count: 32454370137414
       rx_csum_offload_good: 35270755306
       rx_csum_offload_errors: 65076
       alloc_rx_buff_failed: 0
       tx_smbus: 0
       rx_smbus: 0
       dropped_smbus: 0

Kernel drops
------------

stats.log contains interesting information in the
capture.kernel_packets and capture.kernel_drops. The meaning of them
is different following the capture mode.

In AF_PACKET mode:

* kernel_packets is the number of packets correctly sent to userspace
* kernel_drops is the number of packets that have been discarded instead of being sent to userspace

In PF_RING mode:

* kernel_packets is the total number of packets seen by pf_ring
* kernel_drops is the number of packets that have been discarded instead of being sent to userspace

In the Suricata stats.log the TCP data gap counter is also an
indicator, as it accounts missing data packets in TCP streams:

::

  tcp.reassembly_gap        | Detect                    | 789

Ideally, this number is 0. Not only pkt loss affects it though, also
bad checksums and stream engine running out of memory.

Tools to plot graphs
--------------------

Some people made nice tools to plot graphs of the statistics file.

* `ipython and matplotlib script <https://github.com/regit/suri-stats>`_
* `Monitoring with Zabbix or other <http://christophe.vandeplas.com/2013/11/suricata-monitoring-with-zabbix-or-other.html>`_ and `Code on Github <https://github.com/cvandeplas/suricata_stats>`_
