JA3 Keywords
============

Suricata comes with a JA3 integration (https://github.com/salesforce/ja3). JA3 is used to fingerprint TLS clients.

JA3 must be enabled in the Suricata config file (set 'app-layer.protocols.tls.ja3-fingerprints' to 'yes').

ja3.hash
--------

Match on JA3 hash (md5).

Example::

  alert tls any any -> any any (msg:"match JA3 hash"; \
      ja3.hash; content:"e7eca2baf4458d095b7f45da28c16c34"; \
      sid:100001;)

``ja3.hash`` is a 'sticky buffer'.

``ja3.hash`` can be used as ``fast_pattern``.

``ja3.hash`` replaces the previous keyword name: ``ja3_hash``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

ja3.string
----------

Match on JA3 string.

Example::

  alert tls any any -> any any (msg:"match JA3 string"; \
      ja3.string; content:"19-20-21-22"; \
      sid:100002;)

``ja3.string`` is a 'sticky buffer'.

``ja3.string`` can be used as ``fast_pattern``.

``ja3.string`` replaces the previous keyword name: ``ja3_string``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

ja3s.hash
---------

Match on JA3S hash (md5).

Example::

  alert tls any any -> any any (msg:"match JA3S hash"; \
      ja3s.hash; content:"b26c652e0a402a24b5ca2a660e84f9d5"; \
      sid:100003;)

``ja3s.hash`` is a 'sticky buffer'.

``ja3s.hash`` can be used as ``fast_pattern``.

ja3s.string
-----------

Match on JA3S string.

Example::

  alert tls any any -> any any (msg:"match on JA3S string"; \
      ja3s.string; content:"771,23-35"; sid:100004;)

``ja3s.string`` is a 'sticky buffer'.

``ja3s.string`` can be used as ``fast_pattern``.
