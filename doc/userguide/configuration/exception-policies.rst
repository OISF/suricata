.. _exception policies:

Exception Policies
==================

Suricata has a set of configuration variables to indicate what should the engine
do when certain exception conditions, such as hitting a memcap, are reached.
There are two categories for such settings:

- exception policies - configurable via suricata.yaml; called when Suricata
  reaches exception states
- simulation options - exposed in debug mode and passed via command-line; used
  to force failures or errors

Exception Policies
------------------

Exception policies are implemented for:

- stream (``stream.memcap``): If stream session or reassembly memcaps are hit, call
  the memcap policy on the packet and flow.
- stream (``stream.midstream``): If a session is picked up midstream, call the
  memcap policy on the packet and flow.
- flow (``flow.memcap``): Apply policy when memcap is reached and no flow could be
  freed up.
- defrag (``defrag.memcap``): Apply policy when no tracker could be picked up.
- app-layer (``app-layer.error-policy``): Apply policy if a parser reaches an error state.

To change any of those, check the corresponding section in the suricata.yaml
file. The possible values, and their resulting behaviors, are:

- ``drop-flow``: disable inspection for the whole flow (packets, payload,
  application layer protocol), and drop the flow.
- ``drop-packet``: disable payload and packet inspection, and drop the packet.
- ``reject``: same as ``drop-flow``, but send reject packets as well.
- ``bypass``: bypass the flow. No further inspection is done.
- ``pass-flow``: disable payload and packet inspection, still log the flow.
- ``pass-packet``: disable payload and packet inspection, still decodes the packet.
- ``ignore``: do not apply exception policies (keeps default behavior).

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
