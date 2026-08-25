Firewall Mode Unsupported Keywords
==================================

Certain rule keywords are not supported in firewall mode, either completely or
based on rulesets.

A keyword may be unsupported in firewall rules, in threat detection rules, or in
firewall mode altogether.

This is done when there is a chance that the keyword would lead to the firewall
verdict being skipped, contradicted, or when there could happen inconsistent
states from interactions between firewall and threat detection rules matching.

.. note:: Future support may be added to keywords in upcoming releases, in
    certain cases.

Unsupported Keywords
--------------------

Firewall Mode
~~~~~~~~~~~~~

* Bypass
* Replace

Threat Detection Rules
~~~~~~~~~~~~~~~~~~~~~~

* Config (both the ``config`` keyword and the ``config`` action)
