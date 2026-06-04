LLMNR Keywords
==============

Suricata supports sticky buffers for matching on specific fields
in LLMNR (Link-Local Multicast Name Resolution) messages.

Note that sticky buffers are expected to be followed by one or more
:doc:`payload-keywords`.

llmnr.queries.rrname
--------------------

``llmnr.queries.rrname`` is a sticky buffer that is used to look at the
name field in LLMNR query resource records.

``llmnr.queries.rrname`` will look at both requests and responses, so
``flow`` is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled
resource name, for example "workstation.local".

``llmnr.queries.rrname`` supports :doc:`multi-buffer-matching`.

.. container:: example-rule

  alert llmnr any any -> any 5355 (msg:"LLMNR query for workstation"; \
      flow:to_server; llmnr.queries.rrname; content:"workstation"; nocase; sid:1;)

llmnr.answers.rrname
--------------------

``llmnr.answers.rrname`` is a sticky buffer that is used to look at the
name field in LLMNR answer resource records.

``llmnr.answers.rrname`` will look at both requests and responses, so
``flow`` is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled
resource name, for example "server.local".

``llmnr.answers.rrname`` supports :doc:`multi-buffer-matching`.

.. container:: example-rule

  alert llmnr any 5355 -> any any (msg:"LLMNR answer for server.local"; \
      flow:to_client; llmnr.answers.rrname; content:"server.local"; sid:2;)

llmnr.authorities.rrname
------------------------

``llmnr.authorities.rrname`` is a sticky buffer that is used to look at the
rrname field in LLMNR authority resource records.

``llmnr.authorities.rrname`` will look at both requests and responses,
so ``flow`` is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled
resource name, for example "local".

``llmnr.authorities.rrname`` supports :doc:`multi-buffer-matching`.

.. container:: example-rule

  alert llmnr any 5355 -> any any (msg:"LLMNR authority record check"; \
      llmnr.authorities.rrname; content:"local"; sid:3;)

llmnr.additionals.rrname
------------------------

``llmnr.additionals.rrname`` is a sticky buffer that is used to look at
the rrname field in LLMNR additional resource records.

``llmnr.additionals.rrname`` will look at both requests and responses,
so ``flow`` is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled
resource name, for example "ns.local".

``llmnr.additionals.rrname`` supports :doc:`multi-buffer-matching`.

.. container:: example-rule

  alert llmnr any any -> any 5355 (msg:"LLMNR additional record check"; \
      llmnr.additionals.rrname; content:"ns.local"; sid:4;)

llmnr.response.rrname
---------------------

``llmnr.response.rrname`` is a sticky buffer that is used to inspect
all the rrname fields in a response, in the queries, answers,
additionals and authorities. Additionally it will also inspect rdata
fields that have the same format as an rrname (hostname).

``rdata`` types that will be inspected are:

* CNAME
* PTR
* MX
* NS
* SOA

.. container:: example-rule

  alert llmnr any 5355 -> any any (msg:"LLMNR response contains suspicious domain"; \
      flow:to_client; llmnr.response.rrname; content:"malicious"; nocase; sid:5;)
