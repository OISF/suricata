.. _rules-integer-keywords:

Integer Keywords
================

Many keywords will match on an integer value on the network traffic.
These are unsigned integers that can be 8, 16, 32 or 64 bits.

Simple example::

    bsize:integer value;

The integer value can be written as base-10 like ``100`` or as 
an hexadecimal value like ``0x64``.

The integer value can also have a unit/multiplier as a
case-insensitive suffix:
* kb : 1024
* mb : 1048576
* gb : 1073741824

The most direct example is to match for equality, but there are
different modes.

Comparison modes
----------------

Integers can be matched for
  * Equality
  * Inequality
  * Greater than
  * Less than
  * Range
  * Negated range
  * Bitmask
  * Negated Bitmask

.. note::

    Comparisons are strict by default. Ranges are thus exclusive.
    That means a range between 1 and 4 will match 2 and 3, but neither 1 nor 4.
    Negated range !1-4 will match for 1 or below and for 4 or above.

Examples::

    bsize:19; # equality
    bsize:=0x13; # equality
    bsize:!0x14; # inequality
    bsize:!=20; # inequality
    bsize:>21; # greater than
    bsize:>=21; # greater than or equal
    bsize:<22; # lesser than
    bsize:<=22; # lesser than or equal
    bsize:19-22; # range between value1 and value2
    bsize:!19-22; # negated range between value1 and value2
    bsize:&0xc0=0x80; # bitmask mask is compared to value for equality
    bsize:&0xc0!=0; # bitmask mask is compared to value for inequality

Enumerations
------------

Some integers on the wire represent an enumeration, that is, some values
have a string/meaning associated to it.
Rules can be written using one of these strings to check for equality or inequality.
This is meant to make rules more human-readable and equivalent for matching.

Examples::

    websocket.opcode:text;
    websocket.opcode:1; # behaves the same

    websocket.opcode:!ping;
    websocket.opcode:!9; # behaves the same

Bitmasks
--------

Some integers on the wire represent multiple bits.
Some of these bits have a string/meaning associated to it.
Rules can be written using a list (comma-separated) of these strings,
where each item can be negated.

There is no right shift for trailing zeros applied here (even if there is one
for ``byte_test`` and ``byte_math``). That means a rule with
``websocket.flags:&0xc0=2`` will be rejected as invalid as it can never match.

Examples::

    websocket.flags:fin,!comp;
    websocket.flags:&0xc0=0x80; # behaves the same
