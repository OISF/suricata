mDNS Keywords
=============

Suricata supports sticky buffers for efficiently matching on specific
fields in mDNS (Multicast DNS) messages.

Note that sticky buffers are expected to be followed by one or more
:doc:`payload-keywords`.

mdns.queries.rrname
-------------------

``mdns.queries.rrname`` is a sticky buffer that is used to look at the
name field in mDNS query resource records.

The buffer being matched on contains the complete re-assembled
resource name, for example "host.local".

``mdns.queries.rrname`` supports :doc:`multi-buffer-matching`.

Example::

  alert udp any any -> any 5353 (msg:"mDNS query for .local domain"; \
      mdns.queries.rrname; content:".local"; sid:1;)

mdns.answers.rrname
-------------------

``mdns.answers.rrname`` is a sticky buffer that is used to look at the
name field in mDNS answer resource records.

The buffer being matched on contains the complete re-assembled
resource name, for example "printer.local".

``mdns.answers.rrname`` supports :doc:`multi-buffer-matching`.

Example::

  alert udp any 5353 -> any any (msg:"mDNS answer for printer.local"; \
      mdns.answers.rrname; content:"printer.local"; sid:2;)

mdns.authorities.rrname
-----------------------

``mdns.authorities.rrname`` is a sticky buffer that is used to look at the
rrname field in mDNS authority resource records.

The buffer being matched on contains the complete re-assembled
resource name, for example "device.local".

``mdns.authorities.rrname`` supports :doc:`multi-buffer-matching`.

Example::

  alert udp any 5353 -> any any (msg:"mDNS authority record check"; \
      mdns.authorities.rrname; content:"auth.local"; sid:3;)

mdns.additionals.rrname
-----------------------

``mdns.additionals.rrname`` is a sticky buffer that is used to look at
the rrname field in mDNS additional resource records.

The buffer being matched on contains the complete re-assembled
resource name, for example "service.local".

``mdns.additionals.rrname`` supports :doc:`multi-buffer-matching`.

Example::

  alert udp any any -> any 5353 (msg:"mDNS additional record check"; \
      mdns.additionals.rrname; content:"_companion-link._tcp.local"; nocase; sid:4;)

mdns.response.rrname
--------------------

``mdns.response.rrname`` is a sticky buffer that is used to inspect
all the rrname fields in a response, in the queries, answers,
additionals and authorities. Additionally it will also inspect rdata
fields that have the same format as an rrname (hostname).

``rdata`` types that will be inspected are:

* CNAME
* PTR
* MX
* NS
* SOA

Example::

  alert udp any 5353 -> any any (msg:"mDNS answer data match"; \
      mdns.response.rrname; content:"Apple TV"; sid:5;)
