SNMP keywords
=============

snmp_version
------------

SNMP protocol version (integer). Expected values are 1, 2 (for version 2c) or 3.

Syntax::

 snmp_version:[op]<number>

The version can be matched exactly, or compared using the _op_ setting::

 snmp_version:3    # exactly 3
 snmp_version:<3   # smaller than 3
 snmp_version:>=2  # greater or equal than 2

Signature example::

 alert snmp any any -> any any (msg:"old SNMP version (<3)"; snmp_version:<3; sid:1; rev:1;)

snmp_community
--------------

SNMP community strings are like passwords for SNMP messages in version 1 and 2c.
In version 3, the community string is likely to be encrypted. This keyword will not
match if the value is not accessible.

The default value for the read-only community string is often "public", and
"private" for the read-write community string.

Comparison is case-sensitive.

Syntax::

 snmp_community; content:"private";

Signature example::

 alert snmp any any -> any any (msg:"SNMP community private"; snmp_community; content:"private"; sid:2; rev:1;)

``snmp_community`` is a 'sticky buffer'.

``snmp_community`` can be used as ``fast_pattern``.

