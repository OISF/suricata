High Performance Configuration
==============================

If you have enough RAM, consider the following options in
suricata.yaml to off-load as much work from the CPU's as possible:
  
::

  detect-engine:
    - profile: custom
    - custom-values:
        toclient-src-groups: 200
        toclient-dst-groups: 200
        toclient-sp-groups: 200
        toclient-dp-groups: 300
        toserver-src-groups: 200
        toserver-dst-groups: 400
        toserver-sp-groups: 200
        toserver-dp-groups: 200
    - sgh-mpm-context: auto
    - inspection-recursion-limit: 3000

Be advised, however, that this will require >= 32 GB of RAM for even
modestly sized rule sets.  Also be aware that having additional CPU's
available provides a greater performance boost than having more RAM
available.  That is, it would be better to spend money on CPU's
instead of RAM when configuring a system.

As a rough benchmark, in an HTTP-rich traffic stream, the full
Emerging Threats rule set will require roughly one CPU per 50 Mb/sec
of traffic when using "low" memory settings and using PF_RING to
ensure there are no traffic drops.

Here are the build in values for LOW/MEDIUM/HIGH profiles:
  
::

  
  ENGINE_PROFILE_LOW:
        toclient-src-groups: 2
        toclient-dst-groups: 2
        toclient-sp-groups: 2
        toclient-dp-groups: 3
        toserver-src-groups: 2
        toserver-dst-groups: 4
        toserver-sp-groups: 2
        toserver-dp-groups: 25
  
  ENGINE_PROFILE_HIGH:
        toclient-src-groups: 15
        toclient-dst-groups: 15
        toclient-sp-groups: 15
        toclient-dp-groups: 20
        toserver-src-groups: 15
        toserver-dst-groups: 15
        toserver-sp-groups: 15
        toserver-dp-groups: 40
  
If not provided:
  
::

  
  default and MEDIUM profiles:
        toclient-src-groups: 4
        toclient-dst-groups: 4
        toclient-sp-groups: 4
        toclient-dp-groups: 6
        toserver-src-groups: 4
        toserver-dst-groups: 8
        toserver-sp-groups: 4
        toserver-dp-groups: 30
  
