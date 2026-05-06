.. _firewall mode stats:

Firewall Mode Stats
*******************

Statistics counters for the firewall mode cover:

    - drop reasons: ``stats.ips.drop_reason.firewall``
    - discarded alerts: ``stats.detect.firewall.discarded_alerts``

Drop reasons
============

If a drop was caused by the firewall, the corresponding counter will be incremented. The existing ones are:

    - ``rules``: a firewall rule triggered the drop
    - ``default_packet_policy``: drop caused by the default fail closed firewall behavior, on the packet hook level
    - ``default_app_policy``: drop caused by the default fail close firewall behavior, on the app-layer hook level
    - ``pre_flow_hook``: drop caused by the pre-flow hook
    - ``pre_stream_hook``: drop caused by the pre-stream hook

Discarded alerts
================

In Firewall mode, alerts generated *after* a drop are discarded these are reported with the counter ``stats.detect.firewall.discarded_alerts``.
