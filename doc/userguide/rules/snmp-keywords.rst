SNMP keywords
=============

snmp.version
------------

SNMP protocol version (integer). Expected values are 1, 2 (for version 2c) or 3.

Syntax::

 snmp.version:[op]<number>

The version can be matched exactly, or compared using the _op_ setting::

 snmp.version:3    # exactly 3
 snmp.version:<3   # smaller than 3
 snmp.version:>=2  # greater or equal than 2

Signature example::

 alert snmp any any -> any any (msg:"old SNMP version (<3)"; snmp.version:<3; sid:1; rev:1;)

snmp.community
--------------

SNMP community strings are like passwords for SNMP messages in version 1 and 2c.
In version 3, the community string is likely to be encrypted. This keyword will not
match if the value is not accessible.

The default value for the read-only community string is often "public", and
"private" for the read-write community string.

Comparison is case-sensitive.

Syntax::

 snmp.community; content:"private";

Signature example::

 alert snmp any any -> any any (msg:"SNMP community private"; snmp.community; content:"private"; sid:2; rev:1;)

``snmp.community`` is a 'sticky buffer'.

``snmp.community`` can be used as ``fast_pattern``.

snmp.usm
--------

SNMP User-based Security Model (USM) is used in version 3.
It corresponds to the user name.

Comparison is case-sensitive.

Syntax::

 snmp.usm; content:"admin";

Signature example::

 alert snmp any any -> any any (msg:"SNMP usm admin"; snmp.usm; content:"admin"; sid:2; rev:1;)

``snmp.usm`` is a 'sticky buffer'.

``snmp.usm`` can be used as ``fast_pattern``.

snmp.pdu_type
-------------

SNMP PDU type (integer).

Common values are:

 - 0: GetRequest
 - 1: GetNextRequest
 - 2: Response
 - 3: SetRequest
 - 4: TrapV1 (obsolete, was the old Trap-PDU in SNMPv1)
 - 5: GetBulkRequest
 - 6: InformRequest
 - 7: TrapV2
 - 8: Report

This keyword will not match if the value is not accessible within (for ex, an encrypted
SNMP v3 message).


Syntax::

 snmp.pdu_type:<number>

Signature example::

 alert snmp any any -> any any (msg:"SNMP response"; snmp.pdu_type:2; sid:3; rev:1;)

