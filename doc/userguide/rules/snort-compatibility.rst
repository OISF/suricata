Snort Compatibility
===================

.. contents::

Keyword: content
----------------

*Versions affected: All versions prior to 3.0.*

Prior to Suricata 3.0, the argument provided to the content keyword
cannot be longer than 255 characters like it can in Snort.

Suricata 3.0 and newer can accept content arguments longer than 255
characters.

See:

* https://redmine.openinfosecfoundation.org/issues/1281
* https://github.com/inliniac/suricata/pull/1475

Keyword: urilen
---------------

*Versions affected: all*

In Snort the urilen range is inclusive, in Suricata it is not.

Example::

  urilen:5<>10

In Snort the above will match URIs that are greater than and equal to
5 and less than and equal to 10. *Note that this is not what is
documented in the Snort manual.*

In Suricata the above will match URIs that are greater than 5 and less
than 10, so it will only mathch URIs that are 6, 7, 8, and 9 bytes
long.

See:

* https://redmine.openinfosecfoundation.org/issues/1416

Keyword: isdataat
-----------------

*Versions affected: all*

``isdataat`` is off by one from Snort. In Snort the offset starts at 0
where Suricata starts at 1.

Keyword: flowbits
-----------------

*Versions affected: all prior to 2.0.9*

Versions of Suricata prior to 2.0.9 treated leading and trailing
whitespace in flowbit names as part of the flowbit name where Snort
does not.

This was fixed in Suricata 2.0.9.

See:

* https://redmine.openinfosecfoundation.org/issues/1481

Keyword: flow:not_established
-----------------------------

*Versions affected: all*

The ``not_established`` argument to the ``flow`` keyword is not supported.
