Bypass Keyword
==============

Suricata has a ``bypass`` keyword that can be used in signatures to exclude traffic from further evaluation.

The ``bypass`` keyword is useful in cases where there is a large flow expected (e.g. Netflix, Spotify, Youtube).

The ``bypass`` keyword is considered a post-match keyword.


bypass
------

Bypass a flow on matching http traffic.

Example::

  alert http any any -> any any (content:"suricata.io"; \
      http_host; bypass; sid:10001; rev:1;)
