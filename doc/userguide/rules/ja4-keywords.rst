JA4 Keywords
============

Suricata comes with a JA4 integration (https://github.com/FoxIO-LLC/ja4). JA4,
as part of the larger JA4+ suite of fingerprints, is used to fingerprint TLS
clients.

JA4 support must be enabled in the Suricata config file (set
``app-layer.protocols.tls.ja4-fingerprints`` to ``yes``). If it is not
explicitly disabled (``no``) , it will enabled if a loaded rule requires it.

ja4.hash
--------

Match on JA4 hash (e.g. ``q13d0310h3_55b375c5d22e_cd85d2d88918``).

Example::

  alert quic any any -> any any (msg:"match JA4 hash"; \
      ja4.hash; content:"q13d0310h3_55b375c5d22e_cd85d2d88918"; \
      sid:100001;)

``ja4.hash`` is a 'sticky buffer'.

``ja4.hash`` can be used as ``fast_pattern``.

