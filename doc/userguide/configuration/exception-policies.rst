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

**In IPS mode**, the default behavior for most of the exception policies is to
fail close. This means dropping the flow, or the packet, when the flow action is
not supported. The default policy for the midstream exception will be ignore if
midstream flows are accepted.

It is possible to disable this default, by setting the exception policies'
"master switch" yaml config option to ``ignore``.

**In IDS mode**, setting ``auto`` mode actually means disabling the
``master-switch``, or ignoring the exception policies.

Specific settings
~~~~~~~~~~~~~~~~~

Exception policies are implemented for:

.. list-table:: Exception Policy configuration variables
   :widths: 18, 18, 18, 44
   :header-rows: 1

   * - Config setting
     - Policy variable
     - Affects
     - Expected behavior
   * - stream.memcap
     - memcap-policy
     - Flow or packet
     - If a stream memcap limit is reached, apply the memcap policy to the packet and/or
       flow.
   * - stream.midstream
     - midstream-policy
     - Flow
     - If a session is picked up midstream, apply the midstream policy to the flow.
   * - stream.reassembly.memcap
     - memcap-policy
     - Flow or packet
     - If stream reassembly reaches memcap limit, apply memcap policy to the
       packet and/or flow.
   * - flow.memcap
     - memcap-policy
     - Packet
     - Apply policy when the memcap limit for flows is reached and no flow could
       be freed up. **Policy can only be applied to the packet.**
   * - defrag.memcap
     - memcap-policy
     - Packet
     - Apply policy when the memcap limit for defrag is reached and no tracker
       could be picked up. **Policy can only be applied to the packet.**
   * - app-layer
     - error-policy
     - Flow or packet
     - Apply policy if a parser reaches an error state. Policy can be applied to packet and/or flow.

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

Exception Policies and Midstream Pick-up Sessions
-------------------------------------------------

Suricata behavior can be difficult to track in case of midstream session
pick-ups. Consider this matrix illustrating the different interactions for
midstream pick-ups enabled or not and the various exception policy values:

.. list-table:: **Exception Policy Behaviors - IDS Mode**
   :widths: auto
   :header-rows: 1
   :stub-columns: 1

   * - Exception Policy
     - Midstream pick-up sessions ENABLED (stream.midstream=true)
     - Midstream pick-up sessions DISABLED (stream.midstream=false)
   * - Ignore
     - Session tracked and parsed, inspect and log app-layer traffic, do detection.
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
   * - Drop-flow
     - Not valid.*
     - Not valid.*
   * - Drop-packet
     - Not valid.*
     - Not valid.*
   * - Reject
     - Not valid.*
     - Session not tracked, flow REJECTED.
   * - Pass-flow
     - Track session, inspect and log app-layer traffic, no detection.
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
   * - Pass-packet
     - Not valid.*
     - Not valid.*
   * - Bypass
     - Not valid.*
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
   * - Auto
     - Midstream policy applied: "ignore". Same behavior.
     - Midstream policy applied: "ignore". Same behavior.

The main difference between IDS and IPS scenarios is that in IPS mode flows can
be allowed or blocked (as in with the PASS and DROP rule actions). Packet
actions are not valid, as midstream pick-up is a configuration that affects the
whole flow.

.. list-table:: **Exception Policy Behaviors - IPS Mode**
   :widths: 15 42 43
   :header-rows: 1
   :stub-columns: 1

   * - Exception Policy
     - Midstream pick-up sessions ENABLED (stream.midstream=true)
     - Midstream pick-up sessions DISABLED (stream.midstream=false)
   * - Ignore
     - Session tracked and parsed, inspect and log app-layer traffic, do detection.
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
   * - Drop-flow
     - Not valid.*
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
       Flow DROPPED.
   * - Drop-packet
     - Not valid.*
     - Not valid.*
   * - Reject
     - Not valid.*
     - Session not tracked, flow DROPPED and REJECTED.
   * - Pass-flow
     - Track session, inspect and log app-layer traffic, no detection.
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
   * - Pass-packet
     - Not valid.*
     - Not valid.*
   * - Bypass
     - Not valid.*
     - Session not tracked. No app-layer inspection or logging. No detection. No stream reassembly.
       Packets ALLOWED.
   * - Auto
     - Midstream policy applied: "ignore". Same behavior.
     - Midstream policy applied: "drop-flow". Same behavior.

Notes:

   * Not valid means that Suricata will error out and won't start.
   * ``REJECT`` will make Suricata send a Reset-packet unreach error to the sender of the matching packet.

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
