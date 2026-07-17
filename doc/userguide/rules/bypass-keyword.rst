.. _bypass-keyword:

Bypass Keyword
==============

.. role:: example-rule-emphasis

Suricata has a ``bypass`` keyword that can be used in signatures to exclude
traffic from further evaluation.

The ``bypass`` keyword is useful in cases where there is a large flow expected
(e.g. Netflix, Spotify, YouTube).

The ``bypass`` keyword is considered a post-match keyword.

.. note::

   In firewall mode, ``bypass`` can only be used in firewall rules. If a threat
   detection rule uses the ``bypass`` keyword and you want to run Suricata in
   firewall mode, the engine will error out. This is to prevent a threat
   detection rule from bypassing the firewall altogether.

bypass
------

Bypass a flow on matching http traffic.

.. container:: example-rule

  alert http any any -> any any (http.host; \
  content:"suricata.io"; :example-rule-emphasis:`bypass;` \
  sid:10001; rev:1;)

Firewall mode
-------------

``bypass`` is only accepted with a specific combination of `action` and `scope`:
``accept:flow``.

Not accepted:
    - Action: ``config``
    - Action: ``reject``
    - Action: ``drop``
    - Scope: ``packet``
    - Scope: ``tx``
    - Scope: ``hook``

.. attention:: `bypass` on a firewall rule is terminal. Threat detection rules
  are not evaluated for the matching packet, respecting the premise of what would happen if Firewall and IPS were two separate devices.

.. note:: The type of bypass will depend on whether the engine is configured
  for local or capture bypass: offloading is not guaranteed by a firewall
  bypass rule.

.. note:: If `bypass` is used in a rule together with thresholding, the bypass
   could be silent, if the alert is suppressed.

Valid firewall rule with bypass:

.. container:: example-rule

  :example-rule-emphasis:`accept:flow,alert` http1:request_headers any any -> \
  any any (http.host; content:"suricata.io"; :example-rule-emphasis:`bypass;` \
  sid:10001; rev:1;)
