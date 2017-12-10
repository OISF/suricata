JA3 Keywords
============

Suricata comes with a JA3 integration (https://github.com/salesforce/ja3). JA3 is used to fingerprint TLS clients.

JA3 must be enabled in the Suricata config file (set 'app-layer.protocols.tls.ja3-fingerprints' to 'yes').

ja3_hash
--------

Match on JA3 hash (md5).

Example::

  alert tls any any -> any any (msg:"match JA3 hash"; \
      ja3_hash; content:"e7eca2baf4458d095b7f45da28c16c34"; \
      sid:100001;)

``ja3_hash`` is a 'Sticky buffer'.

``ja3_hash`` can be used as ``fast_pattern``.

