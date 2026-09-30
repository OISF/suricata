.. _landlock:

Using Landlock LSM
==================

Landlock is a Linux Security Module that has been introduced in Linux 5.13.
It allows an application to sandbox itself by selecting access right to
directories using a deny by default approach.

Given its nature, Suricata knows where it is going to read files and where
it is going to write them. So it is possible to implement an efficient
Landlock sandboxing policy.

Landlock is not active by default and needs to be activated in the
YAML configuration. Configuration should come with sane default (defined
at build time) and the command line options are used to dynamically add
some permissions.

Please note that Landlock is in blocking mode by default so careful testing
is needed in production.

To enable Landlock, edit the YAML and set ``enabled`` to ``yes``:

::

  landlock:
    enabled: yes
    plugin-setup: false
    directories:
      write:
        - /var/log/suricata/
        - /var/run/
      read:
        - /usr/
        - /etc/
        - /etc/suricata/

Following your running configuration you may have to add some directories.
There are three lists you can use, ``write`` to add directories where write is needed,
``read`` for directories where read access is needed and ``rewrite`` for
directories holding files that are rewritten in place.

``rewrite`` grants read, write *and* truncate on the directory. It is needed
for files that are replaced in place each time they are updated, the previous
content being discarded first -- dataset ``save``/``state`` files are the
typical case. Plain ``write`` deliberately leaves truncation out, since
emptying a file is a classic way to erase traces, so a file that already has
content cannot be rewritten with ``write`` alone::

  landlock:
    enabled: yes
    directories:
      rewrite:
        - /var/lib/mysets/

Built-in outputs (``pcap-log``, ``fast``, ``eve-log`` with ``redis``, ``unix_*``
and custom ``filename`` paths, ...) declare the filesystem and network access
they need on their own. In particular, an absolute ``filename`` on the ``fast``
output is granted per-file, so the common ``filename: /dev/null`` idiom (enable
the module but discard its output) works without opening up write access to the
whole ``/dev`` directory.
Plugins can do the same by implementing the ``LandlockEnable``
callback on ``SCPlugin`` (see :ref:`libsuricata`). The lists above only need to
contain directories that are not covered by these declarations. If ever letting
the plugin set up landlock is not wanted, one can set the `plugin-setup` option
to `false`.

A handful of system pseudo-files are also granted read access automatically:
``/sys/devices/system/cpu`` (online-CPU detection via ``sysconf``), ``/proc/stat``,
``/proc/sys/vm/overcommit_memory`` (allocator tuning) and ``/dev/urandom`` (RNG
seeding fallback). These are probed by glibc, the system allocator and the Rust
standard library during normal startup; granting them avoids spurious ``EACCES``
errors and Landlock audit noise without meaningfully widening the sandbox.
Missing paths are silently skipped.

Rule files passed on the command line are handled too: ``-s``/``-S`` get read
access on the directory holding the rule file, and
``--firewall-rules-exclusive`` gets a per-file read grant. A relative path is
resolved against ``default-rule-path`` (``firewall.rule-path`` for the firewall
rule file), which is granted as a directory.

Lua scripts writing their own files
-----------------------------------

Suricata cannot know in advance which files a Lua output script will open:
the path is chosen by the script at runtime, often built from per-flow data
such as addresses and ports. Such writes are therefore *not* granted
automatically and will fail with ``Permission denied`` once the sandbox is
active, for example::

  Info: output-lua: failed to run script: ./streaming-tcp.lua:25:
  /var/log/suricata/6-10.0.0.1-10.0.0.2-1234-80: Permission denied

When using a Lua script that writes files on its own, add the target
directory to ``security.landlock.directories.write``::

  landlock:
    enabled: yes
    directories:
      write:
        - /var/log/suricata/

Scripts that only write through Suricata's own logging facilities do not
need any extra permission.

Datasets using an absolute path
-------------------------------

Suricata's data directory (``$localstatedir/lib/suricata``, where datasets are
kept by default) is granted read and write access automatically, so rules
whose ``load``, ``save`` or ``state`` file is a plain relative name work out
of the box.

A rule that points at an *absolute* path is different: the file lives outside
the data directory and Suricata cannot guess it, so nothing grants it. Note
that absolute paths are refused outright unless
``datasets.rules.allow-absolute-filenames`` is enabled -- once it is, the
sandbox becomes the next thing in the way and the access has to be declared by
hand.

Which list to use depends on the dataset keyword used in the signature:

``load``
  add its directory to ``security.landlock.directories.read``, otherwise the
  rule fails to load.

``save``
  add its directory to ``security.landlock.directories.rewrite``. Plain
  ``write`` creates the file the first time but cannot replace the content of
  an existing one, so the set would silently stop being updated from the second
  run on. Note that ``rewrite`` also grants read, which a ``save``-only set
  does not need.

``state``
  a shorthand for ``load`` plus ``save`` on the same file, so it needs the
  same ``rewrite`` grant as ``save``.

Note that a denied dataset save is quiet: the set is simply not written and no
error is logged. If a ``save``/``state`` file stops being updated after
enabling Landlock, a missing ``rewrite`` entry is the first thing to check.

For example, with a rule such as::

  alert dns any any -> any any (dns.query; \
      dataset:isnotset,dns-seen,type string,state /var/lib/mysets/dns-seen.txt; \
      sid:1; rev:1;)

the matching configuration is::

  landlock:
    enabled: yes
    directories:
      rewrite:
        - /var/lib/mysets/

The same directories can be passed on the command line instead::

  suricata --set security.landlock.directories.rewrite.0=/var/lib/mysets/

Beware that ``--set`` on a list *replaces* the entry at that index: if the
YAML already defines entries, use the next free index (or add the directory to
the YAML) rather than overwriting index ``0``.

Granting access to network ports
--------------------------------

When a module or plugin cannot declare its needs (for example a third-party
filetype that opens an unknown TCP service), TCP ports can be granted manually
under ``security.landlock.network``. There is no default value: ports listed
here are *added* to whatever the modules and plugins have already declared.

::

  landlock:
    enabled: yes
    network:
      connect:
        tcp:
          - 6379
          - 9092
      bind:
        tcp:
          - 8080

``connect.tcp`` lists ports the process is allowed to connect to (e.g. a Redis
or Kafka broker). ``bind.tcp`` lists ports it is allowed to bind/listen on.
Both options are silently ignored on kernels whose Landlock ABI does not
support network rules (ABI < 4).

Landlock is not active in some distributions and you may need to activate it
at boot by adding ``lsm=landock`` to the Linux command line. For example,
on a Debian distribution with at least a linux 5.13, you can edit ``/etc/default/grub``
and update the ``GRUB_CMDLINE_LINUX_DEFAULT`` option:

::

  GRUB_CMDLINE_LINUX_DEFAULT="quiet lsm=landlock"

Then run ``sudo update-grub`` and reboot.

You can check at boot if it is running by doing:

::

  sudo dmesg | grep landlock || journalctl -kg landlock

If you are interested in reading more about Landlock, you can use https://docs.kernel.org/userspace-api/landlock.html
as entry point.
