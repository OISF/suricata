.. role:: example-rule-emphasis

SSH Keywords
============
Suricata has several rule keywords to match on different elements of SSH
connections.

.. _ssh-hooks:

Hooks
-----

The available hooks for SSH are:

Request (``to_server``) side:

* ``request_in_progress``
* ``request_banner_wait_eol``
* ``request_banner_done``
* ``request_finished``

Response (``to_client``) side:

* ``response_in_progress``
* ``response_banner_wait_eol``
* ``response_banner_done``
* ``response_finished``

Frames
------

The SSH parser supports the following frames:

* ssh.record_hdr
* ssh.record_data
* ssh.record_pdu

These are header + data = pdu for SSH records, after the banner and before encryption.
The SSH record header is 6 bytes long : 4 bytes length, 1 byte passing, 1 byte message code.

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"hdr frame new keys"; :example-rule-emphasis:`frame:ssh.record.hdr; content: "|15|"; endswith;` bsize: 6; sid:2;)

This rule matches like Wireshark ``ssh.message_code == 0x15``.

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

Format::

  ssh.software;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH software string"; :example-rule-emphasis:`ssh.software;` content:"openssh"; nocase; sid:1000020;)

The example above matches on SSH connections where the software string contains
"openssh".


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
