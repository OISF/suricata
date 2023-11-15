Tag
===

The `tag` keyword allows tagging of the current and future packets.

Tagged packets can be logged in `EVE` and conditional PCAP logging.

Tagging is limited to a scope: `host` or `session` (flow). When using `host` a
direction can be specified: `src` or `dst`. Tagging will then occur based on the
`src` or `dst` IP address of the packet generating the alert.

Tagging is further controlled by count: `packets`, `bytes` or `seconds`. If the
count is ommited built-in defaults will be used:

- for `session`: 256 packets
- for `host`: 256 packets for the destination IP of the packet triggering the alert

The `tag` keyword can appear multiple times in a rule.

Syntax
~~~~~~

::

    tag:<scope>[,<count>, <metric>[,<direction>]];

Values for `scope`: `session` and `host`
Values for `metric`: `packets`, `bytes`, `seconds`
Values for `direction`: `src` and `dst`

.. note:: "direction" can only be specified if scope is "host" and both "count"
   and "metric" are also specified.

Examples
~~~~~~~~

Keyword::

    tag:session;                # tags next 256 packets in the flow
    tag:host;                   # tags next 256 packets for the dst ip of the alert
    tag:host,100,packets,src;   # tags next 100 packets for src ip of the alert
    tag:host,3600,seconds,dst;  # tags packets for dst host for the next hour

Full rule examples:

.. container:: example-rule

   alert dns any any -> any any (dns.query; content:"evil"; tag:host,60,seconds,src; sid:1;)

.. container:: example-rule

   alert http any any -> any any (http.method; content:"POST"; tag:session; sid:1;)

How to Use Tags
~~~~~~~~~~~~~~~

EVE
"""

Tags can be set to generate `EVE` `tag` records:

.. code-block:: yaml

    outputs:
      - eve-log:
          enabled: yes
          filename: eve.json
          types:
            - alert:
                tagged-packets: true

The tagged packets will then be logged with `event_type`: `packet`:

.. code-block:: json

    {
      "timestamp": "2020-06-03T10:29:17.850417+0000",
      "flow_id": 1576832511820424,
      "event_type": "packet",
      "src_ip": "192.168.0.27",
      "src_port": 54634,
      "dest_ip": "192.168.0.103",
      "dest_port": 22,
      "proto": "TCP",
      "pkt_src": "wire/pcap",
      "packet": "CAAn6mWJAPSNvfrHCABFAAAogkVAAIAG9rfAqAAbwKgAZ9VqABZvnJXH5Zf6aFAQEAljEwAAAAAAAAAA",
      "packet_info": {
        "linktype": 1
      }
    }

EVE: :ref:`Eve JSON Output <eve-json-output>`

Conditional PCAP Logging
""""""""""""""""""""""""

Using the conditional PCAP logging option the tag keyword can control which
packets are logged by the PCAP logging.

.. code-block:: yaml

    outputs:
      - pcap-log:
          enabled: yes
          filename: log.pcap
          limit: 1000mb
          max-files: 2000
          compression: none
          mode: normal
          use-stream-depth: no #If set to "yes" packets seen after reaching stream inspection depth are ignored. "no" logs all packets
          honor-pass-rules: no # If set to "yes", flows in which a pass rule matched will stop being logged.
          # Use "all" to log all packets or use "alerts" to log only alerted packets and flows or "tag"
          # to log only flow tagged via the "tag" keyword
          conditional: tag

PCAP Logging: :ref:`PCAP log <suricata_yaml_pcap_log>`

Tracking by Host/Flow
~~~~~~~~~~~~~~~~~~~~~

When the tags are using the `session` scope, the tag is added to the
`Flow` structure. If a packet has no flow, no tagging will happen. No
errors/warnings are generated for this.

See :ref:`Flow Settings <suricata-yaml-flow-settings>` for managing flow
limits and resources.

When tags are using the `host` scope, the tag is stored with a `Host`
object in the host table. The Host table size will affect effectiveness
of per host tags.

See :ref:`Host Settings <suricata-yaml-host-settings>` for managing host
table size.
