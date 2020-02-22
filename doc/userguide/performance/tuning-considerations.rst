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
