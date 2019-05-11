SSH Keywords
============

Suricata comes with several rule keywords to match on SSH connections.

ssh.proto
---------

Match on the version of the SSH protocol used.

Example::

  alert ssh any any -> any any (msg:"match SSH protocol version"; \
      ssh.proto; content:"2.0"; sid:1000010;)

The example above matches on SSH connections with SSH version 2.

``ssh.proto`` is a 'Sticky buffer'.

``ssh.proto`` can be used as ``fast_pattern``.

``ssh.proto`` replaces the previous keyword name: ``ssh_proto``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

ssh.software
------------

Match on the software string from the SSH banner.

Example::

  alert ssh any any -> any any (msg:"match SSH software string"; \
      ssh.software: content:"openssh"; nocase; sid:1000020;)

The example above matches on SSH connections where the software string contains "openssh".

``ssh.software`` is a 'Sticky buffer'.

``ssh.software`` can be used as ``fast_pattern``.

``ssh.software`` replaces the previous keyword name: ``ssh_software``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

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
