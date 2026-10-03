Firewall Mode Banned Rules
==========================

.. note:: In Suricata 8 the firewall mode is experimental and subject to change.

Certain rule keywords are banned in firewall mode, either completely or based
on rulesets.

A rule may be banned from firewall rules, threat detection rules, or from firewall mode altogether.

This is done when there is a chance that the keyword would lead to the firewall
verdict being skipped, or contradicted, or when there could happen inconsistent
states from interactions between firewall and threat detection rules matching.

.. note:: Future support may be added to keywords in upcoming releases, in
    certain cases.

Banned Keywords
---------------

Firewall Mode
~~~~~~~~~~~~~

* Replace

Firewall Rules
~~~~~~~~~~~~~~

* Threshold

``threshold`` is not currently supported for firewall rules: some of its types
withhold a rule's alert while still applying its actions, which would leave the
firewall verdict and the logged record disagreeing. The restriction also covers
the ``threshold.config`` file, whose entries may not name a firewall rule.

``detection_filter`` is not restricted. It either applies a rule or it does not,
so below its rate a firewall rule simply does not take effect and evaluation
continues with the next rule. See :doc:`../rules/thresholding`.

Threat Detection Rules
~~~~~~~~~~~~~~~~~~~~~~

* Bypass
