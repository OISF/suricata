IPS Concept
===========

Intrusion Prevention System mode, or IPS mode, is the Suricata mode that makes Suricata a traffic filter.

It will by default allow all traffic, and will use ``drop`` or ``reject`` rules to block unwanted traffic.

It is generally used ``inline``, where threat detection rules are used to drop known bad traffic.

The ``inline`` operations are either on layer 2 (bridge, for example using AF_PACKET or DPDK) or on layer 3
(routing, for example in NFQueue or IPFW).


Differences from the passive IDS mode
-------------------------------------

TCP stream engine
^^^^^^^^^^^^^^^^^

Where in IDS mode TCP traffic is only inspected after the acknoledgement (ACK) for it has been received, in IPS mode
the default behavior is different: new data is inspected immediately, together with previous data where possible.
The inspection happens in a sliding window. This behavior is controlled by the ``stream.inline`` setting.

In case of overlapping data, the first data Suricata receives is accepted. Follow up data that overlaps with this is
then checked against the first data. If it is different, the traffic on the wire is rewritten to match the first data.

The sliding window inspection::

    Packet 1: [hdr][segment data 1     ]
    Segments: [segment data 1     ]
    Window:   [ inspection window ]

    Packet 2: [hdr][segment data 2]
    Segments: [segment data 1     ][segment data 2]
    Window:   [ inspection window                 ]

    Packet 3: [hdr][segment data 3]
    Segments: [segment data 1     ][segment data 2][segment data 3]
    Window:            [ inspection window                        ]

    Packet 4: [hdr][segment data 4]
    Segments: [segment data 2][segment data 3][segment data 4]
    Window:            [ inspection window                   ]

Each segment's data is inspected together with the other available data. One consequence of this is that there
can be significant rescanning of data, which has a performance impact.

http body inspection
^^^^^^^^^^^^^^^^^^^^

Similar to the sliding window approach in the TCP stream engine, the HTTP body inspection will happen in a
sliding manner by default.

::

    app-layer:
      protocols:
        http:
          libhtp:
             default-config:
               # auto will use http-body-inline mode in IPS mode, yes or no set it statically
               http-body-inline: auto


file.data
^^^^^^^^^

For HTTP, the ``file.data`` logic is the same as the body inspection above.


Exception Policies
------------------

By default, when IPS mode is enabled, the exception policies are set to block (``drop``). This is to make
sure rules cannot be bypassed due to Suricata reaching an error state in parsing, reaching internal resource
limits and other exception conditions.

See :ref:`Exception Polices documentation <exception policies>`.


Differences from firewall mode
------------------------------

The main difference with the firewall mode is the default ``drop`` policy in the firewall mode. This means
that a ruleset will have to be created to allow traffic to be accepted, instead of accepting traffic by
default and filtering out unwanted traffic.

See :ref:`Firewall Mode Design <firewall mode design>`.
