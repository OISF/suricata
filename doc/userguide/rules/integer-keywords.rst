.. _rules-integer-keywords:

Integer Keywords
================

Many keywords will match on an integer value on the network traffic.
These are unsigned integers that can be 8, 16, 32 or 64 bits.

Simple example::

    bsize:integer value;

The integer value can be written as base-10 like ``100`` or as 
an hexadecimal value like ``0x64``.

The most direct exemple is to match for equality, but there are
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

Comparisons are strict by default.
That means a range between 1 and 4 will match 2 and 3, but neither 1 nor 4.

Examples::

    bsize:integer value; # equality
    bsize:=integer value; # equality
    bsize:!integer value; # inequality
    bsize:!=integer value; # inequality
    bsize:>integer value; # greater than
    bsize:>=integer value; # greater than or equal
    bsize:<integer value; # lesser than
    bsize:<=integer value; # lesser than or equal
    bsize:integer value1-integer value2; # range between value1 and value2
    bsize:!integer value1-integer value2; # negated range between value1 and value2
    bsize:&mask=value; # bitmask mask is compared to value for equality
    bsize:&mask!=value; # bitmask mask is compared to value for inequality

Enumerations
------------

Some integers on the wire represent an enumeration, that is, some values
have a string/meaning associated to it.
Rules can be written using one of these strings to check for equality.
This is meant to make rules more human-readable and equivalent for matching.

Examples::

    websocker.opcode:text;
    websocker.opcode:1; # behaves the same

Bitmasks
--------

Some integers on the wire represent multiple bits.
Some of these bits have a string/meaning associated to it.
Rules can be written using a list (comma-separated) of these strings,
where each item can be negated.

Examples::

    websocket.flags:fin,!comp;
    websocker.flags:&0xc0=0x80; # behaves the same
