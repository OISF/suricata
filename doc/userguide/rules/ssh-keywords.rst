.. role:: example-rule-emphasis

SSH Keywords
============
Suricata has several rule keywords to match on different elements of SSH
connections.


ssh.proto
---------
Match on the version of the SSH protocol used. ``ssh.proto`` is a sticky buffer,
and can be used as a fast pattern. ``ssh.proto`` replaces the previous buffer
name: ``ssh_proto``. You may continue to use the previous name, but it's
recommended that existing rules be converted to use the new name.

Format::

  ssh.proto;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH protocol version"; :example-rule-emphasis:`ssh.proto;` content:"2.0"; sid:1000010;)

The example above matches on SSH connections with SSH version 2.0.


ssh.software
------------
Match on the software string from the SSH banner. ``ssh.software`` is a sticky
buffer, and can be used as fast pattern.

``ssh.software`` replaces the previous keyword names: ``ssh_software`` &
``ssh.softwareversion``. You may continue to use the previous name, but it's
recommended that rules be converted to use the new name.

Format::

  ssh.software;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH software string"; :example-rule-emphasis:`ssh.software;` content:"openssh"; nocase; sid:1000020;)

The example above matches on SSH connections where the software string contains
"openssh".


ssh.protoversion
----------------
Matches on the version of the SSH protocol used. A value of ``2_compat``
includes SSH version 1.99.

Format::

  ssh.protoversion:[0-9](\.[0-9])?|2_compat;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"SSH v2 compatible"; :example-rule-emphasis:`ssh.protoversion:2_compat;` sid:1;)

The example above matches on SSH connections with SSH version 2 or 1.99.

.. container:: example-rule

  alert ssh any any -> any any (msg:"SSH v1.10"; :example-rule-emphasis:`ssh.protoversion:1.10;` sid:1;)

The example above matches on SSH connections with SSH version 1.10 only.


ssh.softwareversion
-------------------
This keyword has been deprecated. Please use ``ssh.software`` instead. Matches
on the software string from the SSH banner.

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH software string"; :example-rule-emphasis:`ssh.softwareversion:"OpenSSH";` sid:10000040;)


Suricata comes with a Hassh integration (https://github.com/salesforce/hassh). Hassh is used to fingerprint ssh clients and servers.

Hassh must be enabled in the Suricata config file (set 'app-layer.protocols.ssh.hassh' to 'yes').

ssh.hassh
---------

Match on hassh (md5 of of hassh algorithms of client).

Example::

  alert ssh any any -> any any (msg:"match hassh"; \
      ssh.hassh; content:"ec7378c1a92f5a8dde7e8b7a1ddf33d1";\
      sid:1000010;)
      
``ssh.hassh`` is a 'sticky buffer'.

``ssh.hassh`` can be used as ``fast_pattern``.

ssh.hassh.string
----------------

Match on Hassh string (hassh algorithms of client).

Example::

  alert ssh any any -> any any (msg:"match hassh-string"; \
      ssh.hassh.string; content:"none,zlib@openssh.com,zlib"; \
      sid:1000030;)

``ssh.hassh.string`` is a 'sticky buffer'.

``ssh.hassh.string`` can be used as ``fast_pattern``.

ssh.hassh.server
----------------

Match on hassh (md5 of hassh algorithms of server).

Example::

  alert ssh any any -> any any (msg:"match SSH hash-server"; \
      ssh.hassh.server; content:"b12d2871a1189eff20364cf5333619ee"; \
      sid:1000020;)

``ssh.hassh.server`` is a 'sticky buffer'.

``ssh.hassh.server`` can be used as ``fast_pattern``.

ssh.hassh.server.string
-----------------------

Match on hassh string (hassh algorithms of server).

Example::
  alert ssh any any -> any any (msg:"match SSH hash-server-string"; \
      ssh.hassh.server.string; content:"umac-64-etm@openssh.com,umac-128-etm@openssh.com"; \
      sid:1000040;)

``ssh.hassh.server.string`` is a 'sticky buffer'.

``ssh.hassh.server.string`` can be used as ``fast_pattern``.
