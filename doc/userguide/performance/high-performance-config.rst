High Performance Configuration
==============================

If you have enough RAM, consider the following options in suricata.yaml to off-load as much work from the CPU's as possible:

::

  detect:
    profile: custom
    custom-values:
        toclient-groups: 200
        toserver-groups: 200
    sgh-mpm-context: auto
    inspection-recursion-limit: 3000

Be advised, however, that this may require lots of RAM for even modestly sized rule sets.  Also be aware that having additional CPU's available provides a greater performance boost than having more RAM available.  That is, it would be better to spend money on CPU's instead of RAM when configuring a system.

It may also lead to significantly longer rule loading times.

