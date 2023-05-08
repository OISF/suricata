.. _exception policies:

Exception Policies
==================

Suricata has a set of configuration variables to indicate what should the engine
do when certain exception conditions, such as hitting a memcap, are reached.

They are called Exception Policies and are configurable via suricata.yaml. If
enabled, the engine will call them when it reaches exception states.

For developers or for researching purposes, there are also simulation options
exposed in debug mode and passed via command-line. These exist to force or
simulate failures or errors and understand Suricata behavior under such conditions.

Exception Policies
------------------

.. _master-switch:

Master Switch
~~~~~~~~~~~~~

It is possible to set all configuration policies via what we call "master
switch". This offers a quick way to define what the engine should do in case of
traffic exceptions, while still allowing for the flexibility of indicating a
different behavior for specific exception policies your setup/environment may
have the need to.

::

   # Define a common behavior for all exception policies.
   # In IPS mode, the default is drop-flow. For cases when that's not possible, the
   # engine will fall to drop-packet. To fallback to old behavior (setting each of
   # them individually, or ignoring all), set this to ignore.
   # All values available for exception policies can be used, and there is one
   # extra option: auto - which means drop-flow or drop-packet (as explained above)
   # in IPS mode, and ignore in IDS mode. Exception policy values are: drop-packet,
   # drop-flow, reject, bypass, pass-packet, pass-flow, ignore (disable).
   exception-policy: auto

This value will be overwritten by specific exception policies whose settings are
also defined in the yaml file.

Auto
''''

**In IPS mode**, the default behavior for all exception policies is to drop
the flow, or the packet, when the flow action is not supported. It is possible
to disable this default, by setting the exception policies' "master switch" yaml
config option to ``ignore``.

**In IDS mode**, setting ``auto`` mode actually means disabling the
``master-switch``, or ignoring the exception policies.

Specific settings
~~~~~~~~~~~~~~~~~

Exception policies are implemented for:

.. list-table:: Exception Policy configuration variables
   :widths: 20, 18, 62
   :header-rows: 1

   * - Config setting
     - Policy variable
     - Expected behavior
   * - stream.memcap
     - memcap-policy
     - If a stream memcap limit is reached, call the memcap policy on the packet
       and flow.
   * - stream.midstream
     - midstream-policy
     - If a session is picked up midstream, call the memcap policy on the packet
       and flow.
   * - stream.reassembly.memcap
     - memcap-policy
     - If stream reassembly reaches memcap limit, call the memcap policy on the
       packet and flow.
   * - flow.memcap
     - memcap-policy
     - Apply policy when the memcap limit for flows is reached and no flow could
       be freed up. Apply policy to the packet.
   * - defrag.memcap
     - memcap-policy
     - Apply policy when the memcap limit for defrag is reached and no tracker
       could be picked up. Apply policy to the packet.
   * - app-layer
     - error-policy
     - Apply policy if a parser reaches an error state. Apply policy to the
       packet and flow.

To change any of these, go to the specific section in the suricata.yaml file
(for more configuration details, check the :doc:`suricata.yaml's<suricata-yaml>`
documentation).

The possible values for the exception policies, and the resulting behaviors,
are:

- ``drop-flow``: disable inspection for the whole flow (packets, payload,
  application layer protocol), drop the packet and all future packets in the
  flow.
- ``drop-packet``: drop the packet.
- ``reject``: same as ``drop-flow``, but reject the current packet as well (see
  ``reject`` action in Rule's :ref:`actions`).
- ``bypass``: bypass the flow. No further inspection is done. :ref:`Bypass
  <bypass>` may be offloaded.
- ``pass-flow``: disable payload and packet detection; stream reassembly,
  app-layer parsing and logging still happen.
- ``pass-packet``: disable detection, still does stream updates and app-layer
  parsing (depending on which policy triggered it).
- ``ignore``: do not apply exception policies (default behavior).

The *drop*, *pass* and *reject* are similar to the rule actions described in :ref:`rule
actions<suricata-yaml-action-order>`.

Command-line Options for Simulating Exceptions
----------------------------------------------

It is also possible to force specific exception scenarios, to check engine
behavior under failure or error conditions.

The available command-line options are:

- ``simulate-applayer-error-at-offset-ts``: force an applayer error in the to
  server direction at the given offset.
- ``simulate-applayer-error-at-offset-tc``: force an applayer error in the to
  client direction at the given offset.
- ``simulate-packet-loss``: simulate that the packet with the given number
  (``pcap_cnt``) from the session was lost.
- ``simulate-packet-tcp-reassembly-memcap``: simulate that the TCP stream
  reassembly reached memcap for the specified packet.
- ``simulate-packet-tcp-ssn-memcap``: simulate that the TCP session hit the
  memcap for the specified packet.
- ``simulate-packet-flow-memcap``: force the engine to assume that flow memcap is
  hit at the given packet.
- ``simulate-packet-defrag-memcap``: force Suricata to assume memcap is hit when
  defragmenting specified packet.
- ``simulate-alert-queue-realloc-failure``: prevent the engine from dynamically
  growing the temporary alert queue, during alerts processing.

Common abbreviations
--------------------

- applayer: application layer protocol
- memcap: (maximum) memory capacity available
- defrag: defragmentation
