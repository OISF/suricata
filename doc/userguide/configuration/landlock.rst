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
    directories:
      write:
        - /var/log/suricata/
        - /var/run/
      read:
        - /usr/
        - /etc/
        - /etc/suricata/

Following your running configuration you may have to add some directories.
There are two lists you can use, ``write`` to add directories where write is needed
and ``read`` for directories where read access is needed.

On Linux 6.10+ (Landlock ABI 5), ``ioctl`` commands on devices are also
restricted. They are allowed on devices in the ``write`` directories. Capture
methods configuring a device after the sandbox is in place, such as DPDK with
VFIO or netmap, need the directory holding the device (for example
``/dev/vfio/``) in the ``write`` list.

On Linux 6.7+ (Landlock ABI 4), TCP ``bind`` and ``connect`` are also
restricted and no port is allowed by default. Ports used to connect to a
remote service, for example the Redis EVE output (``filetype: redis``,
port 6379 by default), or by a plugin, have to be allowed in the
``network`` section:

::

  landlock:
    enabled: yes
    network:
      connect:
        tcp:
          - 6379
      bind:
        tcp:
          - 8080

Values are TCP port numbers between 1 and 65535. Other protocols such as UDP
are not restricted. The section is ignored on kernels without Landlock
network support.

On Linux 7.0+ (Landlock ABI 9), connecting to a pathname Unix socket that was
created outside of Suricata is also restricted. This affects for example EVE
``unix_stream``/``unix_dgram`` outputs and Redis over a Unix socket, which need
to connect or reconnect after the sandbox is in place. List such sockets (or a
directory containing them) in ``unix-sockets``. Listing the directory is
preferred, as a socket recreated by its server, for example on restart, is a
new file that a rule on the old socket doesn't cover:

::

  landlock:
    enabled: yes
    unix-sockets:
      - /run/redis/redis.sock
      - /var/run/eve/

The socket or directory must exist when Suricata starts.

On Linux 6.2+ (Landlock ABI 3), truncating existing files is also restricted,
so files can't be emptied once the sandbox is in place. Truncation is only
allowed on the following files, which Suricata rewrites while running:

- the ``state`` files of datasets defined in the YAML configuration. Datasets
  defined in rules can't rewrite an existing ``state`` or ``save`` file;
- ``rule_group.json`` when ``detect.profiling.grouping.dump-to-disk`` is
  enabled, and ``firewall.json`` in firewall mode;
- in engine analysis mode, ``rules_fast_pattern.txt``, ``rules_analysis.txt``
  and ``flowbits.json`` (without a tenant prefix);
- the Hyperscan MPM cache directory (``sgh-mpm-caching-path``).

Threaded EVE files with ``append: no`` are emptied during startup, before the
sandbox is in place. Leftover temporary files of the file store from a previous
run are also removed during startup.

In unix socket runmode (``--unix-socket``), outputs and datasets are set up
for each pcap file, after the sandbox is in place. As a result, the ``state``
files of YAML datasets can't be rewritten if they already exist, and outputs
with ``append: no`` can't empty an existing file.

Other outputs that write one file per object, such as ``pcap-log``,
``tls-store`` and the file store ``write-fileinfo`` records, can't overwrite a
file left by a previous run. This happens for example when the same pcap file
is processed again with the same output directory. The existing file is kept,
nothing is written to it and a warning is logged.

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
