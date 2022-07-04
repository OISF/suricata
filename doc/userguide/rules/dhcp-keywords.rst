DHCP keywords
=============

dhcp.leasetime
--------------

DHCP lease time (integer).

Syntax::

 dhcp.leasetime:[op]<number>

The version can be matched exactly, or compared using the _op_ setting::

 dhcp.leasetime:3    # exactly 3
 dhcp.leasetime:<3   # smaller than 3
 dhcp.leasetime:>=2  # greater or equal than 2

Signature example::

 alert dhcp any any -> any any (msg:"small DHCP lease time (<3)"; dhcp.leasetime:<3; sid:1; rev:1;)
