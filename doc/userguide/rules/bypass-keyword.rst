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
    detection rule uses the ``bypass`` keyword and you try to run Suricata in
    firewall mode, the offending rule will produce an error and won't be
    loaded. This is to prevent a threat detection rule from bypassing the
    firewall altogether. (To make the engine error out in such a case, use
    ``--init-errors-fatal``).

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

.. attention:: `bypass` on a firewall rule acts as a terminating action. Threat
  detection verdicts and alerts for the matching packet are discarded, and
  threat detection rules not yet evaluated for that packet are skipped. This
  respects the premise of what would happen if Firewall and IPS were
  two separate devices.

.. note:: The type of bypass will depend on whether the engine is configured
  for local or capture bypass: offloading is not guaranteed by a firewall
  bypass rule.

.. note:: If a firewall ruleset contains a rule using ``bypass``, threat
  detection state changes that outlive the flow are discarded when the firewall
  bypasses the packet, as threat detection is not meant to have seen it.

  ``xbits`` (except with ``track tx``) and ``hostbits`` changes are applied at
  match time, so later rules on the same packet see them, and are undone if the
  packet is bypassed. Until then, they can be seen by other flows.
  ``nfq_set_mark`` is delayed until the firewall verdict for the packet is known.

  Rulesets without a firewall ``bypass`` rule are not affected.

.. note:: dataset's ``set`` and ``unset`` are not delayed: they change the
  dataset while a threat detection rule is being inspected. Once a firewall
  rule bypasses the flow, no further threat detection rules are inspected for
  that packet. A threat detection rule inspected earlier on the same packet,
  such as a packet rule evaluated before an app-layer firewall rule bypasses
  the flow, can still have changed a dataset, and that change remains (see
  https://redmine.openinfosecfoundation.org/issues/5576). Datasets are shared
  between flows and can be saved to disk, so such a change can affect later
  firewall and threat detection decisions.

Valid firewall rule with bypass:

.. container:: example-rule

  :example-rule-emphasis:`accept:flow,alert` http1:request_headers any any -> \
  any any (http.host; content:"suricata.io"; :example-rule-emphasis:`bypass;` \
  sid:10001; rev:1;)


Special hooks
~~~~~~~~~~~~~

``pre_flow`` hook
^^^^^^^^^^^^^^^^^

If the ``bypass`` is applied locally, ``pre_flow`` rules will still be processed
and invoked, due to the fact that the engine can't apply nor control a flow
bypass at a stage where the packet hasn't been tied to its flow yet.

This won't happen in the case of an offloaded bypass, as there won't be
anything for the engine to inspect against.
