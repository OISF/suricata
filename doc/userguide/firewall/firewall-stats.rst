.. _firewall mode stats:

Firewall Mode Stats
*******************

Statistics counters for the firewall mode cover:

    - drop reasons: ``stats.firewall.drop_reason``
    - discarded alerts: ``stats.firewall.discarded_alerts``
    - blocked packets: ``stats.firewall.blocked``
    - accepted packets: ``stats.firewall.accepted``
    - rejected packets: ``stats.firewall.rejected``

These will be present in the stats logs if the engine is run in firewall mode,
only.

Drop reasons
============

If a drop was caused by the firewall, the corresponding counter will be incremented. The existing ones are:

    - ``rules``: a firewall rule triggered the drop
    - ``default_packet_policy``: drop caused by the default fail closed firewall behavior, on the packet hook level
    - ``default_app_policy``: drop caused by the default fail close firewall behavior, on the app-layer hook level
    - ``pre_flow_hook``: drop caused by the pre-flow hook
    - ``pre_stream_hook``: drop caused by the pre-stream hook
    - ``flow_drop``: the whole flow was dropped after a firewall action.

Discarded alerts
================

In Firewall mode, alerts generated *after* a drop are discarded.
These are reported with the counter ``stats.firewall.discarded_alerts``.
Note that the drop may be caused by non-firewall rules.
