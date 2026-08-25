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

Threat Detection Rules
~~~~~~~~~~~~~~~~~~~~~~

* Bypass
