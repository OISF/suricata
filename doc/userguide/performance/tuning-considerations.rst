Tuning Considerations
=====================

Settings to check for optimal performance.

max-pending-packets: <number>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This setting controls the number simultaneous packets that the engine
can handle. Setting this higher generally keeps the threads more busy,
but setting it too high will lead to degradation.

Suggested setting: 10000 or higher. Max is ~65000. This setting is per thread. 
The memory is set up at start and the usage is as follows:

::

    number_of.threads X max-pending-packets X (default-packet-size + ~750 bytes)

mpm-algo: <ac|hs|ac-bs|ac-ks>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Controls the pattern matcher algorithm. AC (``Aho–Corasick``) is the default.
On supported platforms, :doc:`hyperscan` is the best option. On commodity 
hardware if Hyperscan is not available the suggested setting is 
``mpm-algo: ac-ks`` (``Aho–Corasick`` Ken Steele variant) as it performs better than
``mpm-algo: ac``

detect.profile: <low|medium|high|custom>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The detection engine tries to split out separate signatures into
groups so that a packet is only inspected against signatures that can
actually match. As in large rule set this would result in way too many
groups and memory usage similar groups are merged together. The
profile setting controls how aggressive this merging is done. The default 
setting of ``high`` usually is good enough.

The "custom" setting allows modification of the group sizes:

::

    custom-values:
      toclient-groups: 100
      toserver-groups: 100

In general, increasing will improve performance. It will lead to minimal 
increase in memory usage. 
The default value for ``toclient-groups`` and ``toserver-groups`` with 
``detect.profile: high`` is 75.

detect.sgh-mpm-context: <auto|single|full>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The multi pattern matcher can have it's context per signature group
(full) or globally (single). Auto selects between single and full
based on the **mpm-algo** selected. ac, ac-bs, ac-ks, hs default to "single". 
Setting this to "full" with ``mpm-algo: ac`` or ``mpm-algo: ac-ks`` offers 
better performance. Setting this to "full" with ``mpm-algo: hs`` is not 
recommended as it leads to much higher startup time. Instead with Hyperscan 
either ``detect.profile: high`` or bigger custom group size settings can be 
used as explained above which offers better performance than ``ac`` and 
``ac-ks`` even with ``detect.sgh-mpm-context: full``.

DPDK
~~~~

Deployment
----------

Runnning Suricata in an optimal environment comes with certain performance 
benefits. Therefore, to squeeze out as much performance as possible, it is 
advised to:

- Run on physical hardware,
- Run each Suricata worker on a separate core,
- Analyze your NUMA-node setup and, if possible, locate the whole deployment 
  on one NUMA node. This includes:
  - Suricata workers (CPU cores),
  - Networks Interface Cards (NICs),
  - hugepages (RAM).
- Adjust Suricata settings to fit your network behavior, but do not necessarily
  overallocate resources,
- When allocating hugepages, it is preferred to allocate bigger hugepages 
  (e.g., 1 GB instead of 2 MB, or in other words the fewer the better) and to 
  allocate them on or right after boot (to ensure successful allocation),
- Isolate CPU cores dedicated to the Suricata workers to prevent interference 
  from other processes (isolcpus),
- Disable power-saving features like C-states and P-states in BIOS to prevent 
  performance fluctuations.

Monitoring performance of DPDK capture module
---------------------------------------------------

To monitor the DPDK performance, watch for the following counters: 

- capture.dpdk.imissed,
- capture.dpdk.no_mbufs,
- capture.dpdk.ierrors.

On Suricata startup, you can also use the `-vvvv` command line parameter to 
enable `extended statistics (xstats) 
<http://doc.dpdk.org/api/structrte__eth__stats.html>`_.
These statistics are displayed on Suricata shutdown. 
They can increase visibility into the problem and be used to identify areas 
for improvement.

In both cases, pay attention to the following counters:

- no_mbufs - If this value is high, it indicates that you should increase 
  the DPDK mempool size. The recommended
  mempool size is specified in the Suricata YAML configuration file.
- rx-missed (imissed) - A high value suggests that you should increase the 
  rx/tx DPDK descriptors.
- rx-errors (ierrors) - This metric does not necessarily indicate a packet 
  receive issue but rather highlights that incoming packets were erroneous. 
  High values in this metric may require further investigation to determine 
  the cause of the errors.

When an increase in the DPDK settings does not help and the aforementioned 
counters are still high, you can add more Suricata workers. As a rule of thumb,
you need 1 Suricata worker per 500 Mbps of network traffic. This, however, 
depends hugely on the traffic that Suricata inspects, rules that Suricata 
uses for inspection, and the depth/complexity of the inspection (what is 
parsed/exported).
In case you cannot add more Suricata workers, you may want to:

- improve the performance of other Suricata modules,
- upgrading the machine,
- reduce the ruleset,
- relax your inspection settings (e.g., lowering the TCP reassembly depth, 
  disabling an export of e.g., TLS certificates or similar).

Please note that the last two suggestions may lead to decreased visibility 
if evaluated incorrectly.

For a high-performance setup, it is possible to use the following settings 
as a starting point:

:: 

  mempool-size: 262143 # 262143 mbufs in the global memory pool
  mempool-cache-size: 511 # 511 mbufs in local lcore memory pool cache
  rx-descriptors: 4096
  tx-descriptors: 4096

af-packet
~~~~~~~~~

If using ``af-packet`` (default on Linux) it is recommended that af-packet v3 
is used for IDS/NSM deployments. For IPS it is recommended af-packet v2. To make
sure af-packet v3 is used it can specifically be enforced it in the 
``af-packet`` config section of suricata.yaml like so:

::

 af-packet:
  - interface: eth0
    ....
    ....
    ....
    use-mmap: yes
    tpacket-v3: yes

ring-size
~~~~~~~~~

Ring-size is another ``af-packet`` variable that can be considered for tuning 
and performance benefits. It basically means the buffer size for packets per 
thread. So if the setting is ``ring-size: 100000`` like below: 

::

 af-packet:
  - interface: eth0
    threads: 5
    ring-size: 100000

it means there will be 100,000 packets allowed in each buffer of the 5 threads. 
If any of the buffers gets filled (for example packet processing can not keep up) 
that will result in packet ``drop`` counters increasing in the stats logs.   

The memory used for those is set up and dedicated at start and is calculated 
as follows: 

::

 af-packet.threads X af-packet.ring-size X (default-packet-size + ~750 bytes)

where ``af-packet.threads``, ``af-packet.ring-size``, ``default-packet-size`` 
are the values set in suricata.yaml. Config values for example for af-packet 
could be quickly displayed with on the command line as well with 
``suricata --dump-config |grep af-packet``.

stream.bypass
~~~~~~~~~~~~~

Another option that can be used to improve performance is ``stream.bypass``. 
In the example below:

::

 stream:
  memcap: 64mb
  checksum-validation: yes      # reject wrong csums
  inline: auto                  # auto will use inline mode in IPS mode, yes or no set it statically
  bypass: yes
  reassembly:
    memcap: 256mb
    depth: 1mb                  # reassemble 1mb into a stream
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes
  
Inspection will be skipped when ``stream.reassembly.depth`` of 1mb is reached for a particular flow.
