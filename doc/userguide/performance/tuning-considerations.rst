Tuning Considerations
=====================

Settings to check for optimal performance.

max-pending-packets: <number>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This setting controls the number simultaneous packets that the engine
can handle. Setting this higher generally keeps the threads more busy,
but setting it too high will lead to degradation.

Suggested setting: 10000 or higher. Max is ~65000. This setting is per thread. The memory is set up at start and the usage is as follows:

::

    number_of.threads X max-pending-packets X (default-packet-size + ~750 bytes)

mpm-algo: <ac|hs|ac-bs|ac-ks>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Controls the pattern matcher algorithm. AC (`Aho–Corasick `) is the default. On supported platforms, :doc:`hyperscan` is the best option. On commodity hardware if Hyperscan is not available the suggested setting is `mpm-algo: ac-ks` (`Aho–Corasick ` Ken Steele variant) as it performs better than `mpm-algo: ac`

detect.profile: <low|medium|high|custom>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The detection engine tries to split out separate signatures into
groups so that a packet is only inspected against signatures that can
actually match. As in large rule set this would result in way too many
groups and memory usage similar groups are merged together. The
profile setting controls how aggressive this merging is done. The default setting of `high` usually is good enough.

The "custom" setting allows modification of the group sizes:

::

    custom-values:
      toclient-groups: 100
      toserver-groups: 100

In general, increasing will improve performance. It will lead to minimal increase in memory usage. 
The default value for `toclient-groups` and `toclient-groups` with `detect.profile: high` is 75.

detect.sgh-mpm-context: <auto|single|full>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The multi pattern matcher can have it's context per signature group
(full) or globally (single). Auto selects between single and full
based on the **mpm-algo** selected. ac, ac-bs, ac-ks, hs default to "single". 
Setting this to "full" with `mpm-algo: ac` or `mpm-algo: ac-ks` offers better performance. Setting this to "full" with `mpm-algo: hs` is not recommended as it leads to much higher startup time. Instead with Hyperscan you can use either `detect.profile: high` or bigger custom group size settings as explained above which offers better performance than `ac` and `ac-ks` even with `detect.sgh-mpm-context: full`.

af-packet
~~~~~~~~~

If you are using `af-packet` (default on Linux) it is recommended that you use af-packet v3 for IDS/NSM deployments. For IPS it is recommended you stay with af-packet v2. To make sure af-packet v3 is used you can specifically enforce it in the `af-packet` config section of suricata.yaml like so:

::

 af-packet:
  - interface: eth0
    ....
    ....
    ....
    # To use the ring feature of AF_PACKET, set 'use-mmap' to yes
    use-mmap: yes
    # Lock memory map to avoid it goes to swap. Be careful that over subscribing could lock
    # your system
    #mmap-locked: yes
    # Use tpacket_v3 capture mode, only active if use-mmap is true
    # Don't use it in IPS or TAP mode as it causes severe latency
    tpacket-v3: yes

af-packet.ring-size
~~~~~~~~~~~~~~~~~~~

Ring-size is another `af-packet` variable that can be considered for tuning and performance benefits. It basically means the buffer size for packets per thread. So if your setting is `ring-size: 100000` like below: 

::

 af-packet:
  - interface: eth0
    # Number of receive threads. "auto" uses the number of cores
    threads: 5
    ....
    ....
    # Ring size will be computed with respect to max_pending_packets and number
    # of threads. You can set manually the ring size in number of packets by setting
    # the following value. If you are using flow cluster-type and have really network
    # intensive single-flow you could want to set the ring-size independently of the number
    # of threads:
    ring-size: 100000

it means there will be 100 000 packets allowed in each buffer of the 5 threads. If any of the buffers gets filled (for example packet processing can not keep up) that will result in packet `drop` counters increasing in the stats logs.   

The memory used for those is set up and dedicated at start and is calculated roughly like so: 

::
 af-packet.threads X af-packet.ring-size X (default-packet-size + ~750 bytes)

where `af-packet.threads`, `af-packet.ring-size`, `default-packet-size` are the values set in suricata.yaml. Config values for example for af-packet could be quickly displayed with on the command line as well with `suricata --dump-config |grep af-packet`.

stream.bypass
~~~~~~~~~~~~~

Another option that can be used to improve performance is `stream.bypass`. 
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
  
inspection will be skipped when `stream.depth` of 1mb is reached for a particular flow.
