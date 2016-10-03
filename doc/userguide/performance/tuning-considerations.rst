Tuning Considerations
=====================

Settings to check for optimal performance.

max-pending-packets: <number>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This setting controls the number simultaneous packets that the engine
can handle. Setting this higher generally keeps the threads more busy,
but setting it too high will lead to degradation.

Suggested setting: 1000 or higher. Max is ~65000.

mpm-algo: <ac|hs|ac-bs|ac-ks>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Controls the pattern matcher algorithm. AC is the default. On supported platforms, :doc:`hyperscan` is the best option.

detect.profile: <low|medium|high|custom>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The detection engine tries to split out separate signatures into
groups so that a packet is only inspected against signatures that can
actually match. As in large rule set this would result in way too many
groups and memory usage similar groups are merged together. The
profile setting controls how aggressive this merging is done. Higher
is better but results in (much) higher memory usage.

The "custom" setting allows modification of the group sizes:

::

    custom-values:
      toclient-groups: 50
      toserver-groups: 50

In general, increasing will improve performance, but will lead to
higher memory usage.

detect.sgh-mpm-context: <auto|single|full>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The multi pattern matcher can have it's context per signature group
(full) or globally (single). Auto selects between single and full
based on the **mpm-algo** selected. ac and ac-bs use "single".
All others "full". Setting this to "full" with AC requires a
lot of memory: 32GB+ for a reasonable rule set.

