Quic Keywords
=============

Suricata implements initial support for Quic by parsing the Quic version.

Suricata also derives a CYU hash for earlier versions of Quic.

Quic app-layer parsing must be enabled in the Suricata config file (set 'app-layer.protocols.quic.enabled' to 'yes').

quic.cyu.hash
---------------

Match on the CYU hash

Examples::

  alert quic any any -> any any (msg:"QUIC CYU HASH"; \
    quic.cyu.hash; content:"7b3ceb1adc974ad360cfa634e8d0a730"; \
    sid:1;)

quic.cyu.string
---------------

Match on the CYU string

Examples::

  alert quic any any -> any any (msg:"QUIC CYU STRING"; \
    quic.cyu.string; content:"46,PAD-SNI-VER-CCS-UAID-TCID-PDMD-SMHL-ICSL-NONP-MIDS-SCLS-CSCT-COPT-IRTT-CFCW-SFCW"; \
    sid:2;)

quic.version
------------

Sticky buffer for matching on the Quic header version in long headers.

Examples::

  alert quic any any -> any any (msg:"QUIC VERSION"; \
    quic.version; content:"Q046"; \
    sid:3;)

Additional information
----------------------

More information on CYU Hash can be found here:
`<https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f>`_

More information on the protocol can be found here:
`<https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-17>`_
