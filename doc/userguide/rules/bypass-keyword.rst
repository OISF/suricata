Bypass Keyword
==============

.. role:: example-rule-emphasis

Suricata has a ``bypass`` keyword that can be used in signatures to exclude
traffic from further evaluation.

The ``bypass`` keyword is useful in cases where there is a large flow expected
(e.g. Netflix, Spotify, YouTube).

The ``bypass`` keyword is considered a post-match keyword.

bypass
------

Bypass a flow on matching http traffic.

.. container:: example-rule

  alert http any any -> any any (http.host; \
  content:"suricata.io"; :example-rule-emphasis:`bypass;` \
  sid:10001; rev:1;)
