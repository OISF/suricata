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
* kb/kib : 1024
* mb/mib : 1048576
* gb/gib : 1073741824

The most direct example is to match for equality, but there are
different modes.

The list of integer keywords can be found by command
``suricata --list-keywords=csv | grep "uint"``

Some other keywords may use unsigned integers as part of their logic:
* iprep
* stream_size
* flow.pkts
* flow.bytes

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
This list can be prefixed by a modifier:

========  ===================================
Modifier  Description
========  ===================================
``+``     match on all the bits, plus any others
``*``     match if any of the bits are set
``-``     match if not all the bits are set
``=``     match on all the bits, and only them
========  ===================================

There is no right shift for trailing zeros applied here (even if there is one
for ``byte_test`` and ``byte_math``). That means a rule with
``websocket.flags:&0xc0=2`` will be rejected as invalid as it can never match.

Examples::

    websocket.flags:fin,!comp;
    websocket.flags:&0xc0=0x80; # behaves the same

.. _multi-integers:

Multi-integers
--------------

As :ref:`multi-buffers <rules-multi-buffer-matching>` and sticky buffers,
some integer keywords are also multi-integer.

They expand the syntax of a single integer::
 keyword: operation and value[,index,subslice];

.. table:: **Index values for multi-integers keyword**

    ============= ===========================================================
    Value         Description
    ============= ===========================================================
    [default]     Match with any index
    any           Match with any index
    all           Match only if all and at least one indexes match
    all_or_absent Match only if all indexes match or matches on an empty list
    nb x          Matches a number of times
    or_absent     Match with any index or matches on an empty list
    0>=           Match specific index
    0<            Match specific index with back to front indexing
    oob_or x      Match with specific index or index out of bounds
    ============= ===========================================================

**Please note that:**

The index ``all`` will not match if there is no value.

The index ``all_or_absent`` will match if there is no value
and behaves like ``all`` if there is at least one value.

These keywords will wait for transaction completion to run, to
be sure to have the final number of elements.

The index ``nb`` accepts all comparison modes as integer keywords.
For example ``nb>3`` will match only if more than 3 integers in the
array match the value.

The subslice may use positive or negative indexing.
For the array [1,2,3,4,5,6], here are some examples:
* 2:4 will have subslice [3,4]
* -4:-1 will have subslice [3,4,5]
* 3:-1 will have subslice [4,5]
* -4:4 will have subslice [3,4]

If one index is out of bounds, an empty subslice is used.

Count
-----

Multi-integer can also just count the number of occurences
without matching to a specific value.

The syntax is::
 keyword: count [mode] value;

Examples::

    http2.window:count >5;
