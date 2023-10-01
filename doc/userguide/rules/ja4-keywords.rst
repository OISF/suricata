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


ja4.r
-----

Match on JA4 raw string (e.g. ``t12i1810s1_0004,0005,000a,002f,0032,0033,0035,0039,009c,009e,c007,c009,c00a,c011,c013,c014,c02b,c02f_0005,000a,000b,000d,0012,0023,3374,7550,ff01_0401,0501,0201,0403,0503,0203,0402,0202``).
See https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md#raw-output for more information.

Example::

  alert tls any any -> any any (msg:"match JA4 raw"; \
      ja4.r; content:"t12i1810s1_0004,0005,000a,002f,0032,0033,0035,0039,009c,009e,c007,c009,c00a,c011,c013,c014,c02b,c02f_0005,000a,000b,000d,0012,0023,3374,7550,ff01_0401,0501,0201,0403,0503,0203,0402,0202"; \
      sid:100002;)

``ja4.r`` is a 'sticky buffer'.

``ja4.r`` can be used as ``fast_pattern``.


ja4.ro
------

Match on JA4 raw original order string (e.g. ``t12i1810s1_c02b,c02f,009e,c00a,c009,c013,c014,c007,c011,0033,0032,0039,009c,002f,0035,000a,0005,0004_ff01,000a,000b,0023,3374,0010,7550,0005,0012,000d_0401,0501,0201,0403,0503,0203,0402,0202``).
See https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md#raw-output for more information.

Example::

  alert tls any any -> any any (msg:"match JA4 raw original order string"; \
      ja4.ro; content:"t12i1810s1_c02b,c02f,009e,c00a,c009,c013,c014,c007,c011,0033,0032,0039,009c,002f,0035,000a,0005,0004_ff01,000a,000b,0023,3374,0010,7550,0005,0012,000d_0401,0501,0201,0403,0503,0203,0402,0202"; \
      sid:100003;)

``ja4.ro`` is a 'sticky buffer'.

``ja4.ro`` can be used as ``fast_pattern``.
