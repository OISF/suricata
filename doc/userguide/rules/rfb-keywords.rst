RFB Keywords
============

The ``rfb.name`` and ``rfb.sectype`` keywords can be used for matching on various properties of
RFB (Remote Framebuffer, i.e. VNC) handshakes.


rfb.name
--------

Match on the value of the RFB desktop name field.

Examples::

  rfb.name; content:"Alice's desktop";
  rfb.name; pcre:"/.* \(screen [0-9]\)$/";

``rfb.name`` is a 'sticky buffer'.

``rfb.name`` can be used as ``fast_pattern``.


rfb.secresult
-------------

Match on the value of the RFB security result, e.g. ``ok``, ``fail``, ``toomany`` or ``unknown``.

Examples::

  rfb.secresult: ok;
  rfb.secresult: unknown;


rfb.sectype
-----------

Match on the value of the RFB security type field, e.g. ``2`` for VNC challenge-response authentication, ``0`` for no authentication, and ``30`` for Apple's custom Remote Desktop authentication.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)

Examples::

  rfb.sectype:2;
  rfb.sectype:>=3;


Additional information
----------------------

More information on the protocol can be found here:
`<https://tools.ietf.org/html/rfc6143>`_
