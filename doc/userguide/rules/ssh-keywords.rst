SSH Keywords
============

Suricata comes with several rule keywords to match on SSH connections.

ssh_proto
---------

Match on the version of the SSH protocol used.

Example::

  alert ssh any any -> any any (msg:"match SSH protocol version"; \
      ssh_proto; content:"2.0"; sid:1000010;)

The example above matches on SSH connections with SSH version 2.

``ssh_proto`` is a 'Sticky buffer'.

``ssh_proto`` can be used as ``fast_pattern``.

ssh_version
-----------

Match on the software string from the SSH banner.

Example::

  alert ssh any any -> any any (msg:"match SSH software string"; \
      ssh_software: content:"openssh"; nocase; sid:1000020;)

The example above matches on SSH connections where the software string contains "openssh".

``ssh_software`` is a 'Sticky buffer'.

``ssh_software`` can be used as ``fast_pattern``.

ssh.protoversion
----------------

This is a legacy keyword. Use ``ssh_proto`` instead!

Match on the version of the SSH protocol used.

Example::

  alert ssh any any -> any any (msg:"match SSH protocol version"; \
      ssh.protoversion:"2.0"; sid:1000030;)

ssh.softwareversion
-------------------

This is a legacy keyword. Use ``ssh_software`` instead!

Match on the software string from the SSH banner.

Example::

  alert ssh any any -> any any (msg:"match SSH software string"; \
      ssh.softwareversion:"OpenSSH"; sid:10000040;)
