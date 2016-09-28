Tuning Considerations
=====================

Settings to check for optimal performance.

max-pending-packets: <number>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This setting controls the number simultaneous packets that the engine
can handle. Setting this higher generally keeps the threads more busy,
but setting it too high will lead to degradation.

Suggested setting: 1000 or higher. Max is ~65000.

mpm-algo: <ac|ac-gfbs|ac-bs|b2g|b3g|wumanber>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Controls the pattern matcher algorithm. AC is the default and best
choice for most if not all cases.

detect-engine.profile: <low|medium|high|custom>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The detection engine tries to split out separate signatures into
groups so that a packet is only inspected against signatures that can
actually match. As in large rule set this would result in way too many
groups and memory usage similar groups are merged together. The
profile setting controls how aggressive this merging is done. Higher
is better but results in (much) higher memory usage.

The "custom" setting allows modification of the group sizes:

::

    - custom-values:
        toclient-src-groups: 2
        toclient-dst-groups: 2
        toclient-sp-groups: 2
        toclient-dp-groups: 3
        toserver-src-groups: 2
        toserver-dst-groups: 4
        toserver-sp-groups: 2
        toserver-dp-groups: 25

In general, increasing will improve performance, but will lead to
higher memory usage.

detect-engine.sgh-mpm-context: <auto|single|full>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The multi pattern matcher can have it's context per signature group
(full) or globally (single). Auto selects between single and full
based on the **mpm-algo** selected. ac, ac-gfbs and ac-bs use
"single". All others "full". Setting this to "full" with AC requires a
lot of memory: 32GB+ for a reasonable rule set.
