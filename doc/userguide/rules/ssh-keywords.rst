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


