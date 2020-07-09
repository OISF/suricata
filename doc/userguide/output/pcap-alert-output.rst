Pcap Alert Output
=================

Suricata is able to provide a packet capture output upon the generation of an
alert. This feature makes use of the "tag" keyword in a signature by searching
for and dumping tagged packets that either have generated an alert or belong to
the same session of a packet that has generated an alert. This feature must be
enabled through the suricata.yaml file, but also requires a signature to have
the "tag:session;" keyword for it to perform the capture. Signatures without
"tag:session;" will not trigger a capture.

Additionally, there is an option to enabled a session-dump in the suricata.yaml
file. This causes all available tcp segments in the relevant session at the time
of alert to be dumped to the capture file. This is recommended, as otherwise
often the packet that generates an alert may not be captured due to a lag
between the processing of a packet and the generation of an alert. This
behaviour was only found in tcp based traffic. As a result, the session-dump
option only relates to tcp based traffic.

By default, the stream-pcap-log is not enabled.

YAML
----

::

  - stream-pcap-log:
      enabled: yes/no
      output_directory: /data/pcap# Defaults to default-log-dir
      session-dump: yes/no # Dumps tcp session upon creation of pcap file.

Example Signatures
------------------

.. container:: example-rule

    alert tcp any any -> any any (msg:"Alert on HTTP GET request using content
    match. Capturing session!"; content:"GET"; tag:session; sid:1; rev:1;)

.. container:: example-rule

    alert tcp any any -> any any (msg:"Alert on HTTP Get request using sticky
    buffer. Capturing session!"; http.method; content:"GET"; tag:session; sid:2; rev:1;)

.. container:: example-rule

    alert snmp any any -> any any (msg:"SNMP get request. Capturing Session!";
    snmp.pdu_type:0; tag:session; sid:3; rev:1;)

.. container:: example-rule

    alert udp any any -> any any (msg:"UDP Packet found. Capturing Session.";
    tag:session; sid:4; rev:1;)
