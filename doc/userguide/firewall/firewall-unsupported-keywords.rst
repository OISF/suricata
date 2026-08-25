Firewall Mode Unsupported Keywords
==================================

Certain rule keywords are not supported in firewall mode, either completely or
based on rulesets.

A keyword may be unsupported in firewall rules, in threat detection rules, or in
firewall mode altogether.

This is done when there is a chance that the keyword would lead to the firewall
verdict being skipped, contradicted, or when there could happen inconsistent
states from interactions between firewall and threat detection rules matching.

.. note:: Future releases may add support for such keywords where it makes sense.

Unsupported Keywords
--------------------

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

``detection_filter`` can't be combined with ``bypass`` in a firewall rule, as
``bypass`` would take effect before the rate is checked. For other cases, it
either applies a rule or it does not, so below its rate a firewall rule simply
does not take effect and evaluation continues with the next rule.
See :doc:`../rules/thresholding`.

Threat Detection Rules
~~~~~~~~~~~~~~~~~~~~~~

* Bypass
* Config (both the ``config`` keyword and the ``config`` action)
