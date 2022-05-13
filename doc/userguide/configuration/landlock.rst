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
