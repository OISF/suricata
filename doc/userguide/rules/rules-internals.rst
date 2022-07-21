Rules Processing
================

.. toctree::

Suricata rules have many elements that influence how they are processed by
Suricata and matched against network traffic.

This section explains some key aspects of how Suricata handles rules internally,
so it can be easier to understand/predict how different rules may interact in
specific scenarios.

**This material is intended for:** rule writers; developers.

Possible questions one should be better equipped to answer after reading this
document:

- What happens if two rules have the same priority value (the keyword)?
- What type of rules will be evaluated first, given a set of rules?
- How does Suricata decide what rule is "more important" when matching traffic?

.. note::

    Throughout this documentation and for Suricata, the terms "rule" and
    "signature" are mainly interchangeable, unless context indicates otherwise.

Overview
--------

Rules are provided to Suricata via rules files. Starting from those, the
Detection Engine loader will:

#. Load all the signatures;
#. Check for validity (non-existing keywords; duplicated sid etc);
#. Report stats on loaded, good and bad signatures;
#. Sort all valid signatures and store them in a list in the Detect Engine
   Context (``DetectEngineCtx``) structure, taking into consideration several
   rule aspects according to their order of relevance to the Detection Engine;
#. Attribute internal rule ids that reflect this `rule prioritization`_;
#. During inspection, match rules against the inspected traffic, according to rule
   and traffic type.

.. _rule prioritization:

Rule Prioritization
-------------------

Suricata registers several different ordering functions (with
``SCSigRegisterSignatureOrderingFuncs()``), which are then used to compare
the rules, sort them, and define their priority. The elements taken into
consideration for such are the signature's:

#. :ref:`Action <action>`
#. Usage of :ref:`flowbits`
#. Usage of :ref:`flowint`
#. Usage of flowvar
#. Usage of pktvar
#. Usage of hostbits
#. Usage of ippair
#. :ref:`Priority <priority>`

In this order. Once signatures are ordered, they are attributed a unique
internal id (``Signature::num``) which symbolizes their priority (the lower the
``num``, the higher the priority). This could mean that a rule with keyword
defined priority 1 could have lower priority than another rule, if the other has
flowbits set and an action with higher priority, for instance.

Example
~~~~~~~

Consider the rules bellow:

.. container:: example-rule

    pass udp any any -> any 6081 (sid:1; gid:10000003;)

.. container:: example-rule

    pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"some.\
    content"; startswith; nocase; endswith; msg:"matching TLS allowed";\
    priority:1; flow:to_server, established; sid:2; rev:1; gid:10000003;)

.. container:: example-rule

    drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"not matching any TLS\
    allowed"; priority:1; flow:to_server, established; sid:3; rev:1; gid:\
    10000003;)

.. container:: example-rule

    pass udp any any -> any 6081 (sid:4; gid:10000003;)

.. container:: example-rule

    pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"some.\
    content"; startswith; nocase; endswith; msg:"matching TLS allowed";\
    priority:1; flow:to_server, established; sid:5; rev:1; gid:10000003;)

.. container:: example-rule

    pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"some.\
    content"; startswith; nocase; endswith; msg:"matching TLS allowed";\
    priority:1; flow:to_server, established; content:"hypothetical"; sid:6;\
    rev:1; gid:10000003;)

With the default `action order configuration <suricata-yaml-action-order>`_
(*pass*, *drop*, *reject*, *alert*), after loading and sorting, their
internal IDs would be:

+--------------------+-------------------+
| Signature ID (sid) | Internal ID (num) |
+====================+===================+
|  1                 |  3                |
+--------------------+-------------------+
|  2                 |  0                |
+--------------------+-------------------+
|  3                 |  5                |
+--------------------+-------------------+
|  4                 |  4                |
+--------------------+-------------------+
|  5                 |  1                |
+--------------------+-------------------+
|  6                 |  2                |
+--------------------+-------------------+


Inspection Flow
---------------

Once it is time to inspect network traffic against the loaded rules, the
Detect Engine will match against - if applicable:

#. IPOnly rules;
#. Packet/payload related rules;
#. Frame keywords;
#. Application layer protocol transactions.

During packet inspection, if the signature uses the last two, inspection is
left to those steps.

Each rule that matches becomes a ``PacketAlert``. These will, after all matches
for the packet have been processed, become the alerts that are seen in Suricata
logs.

Considerations on inspection steps
----------------------------------

IPOnly rules
~~~~~~~~~~~~

Without optimization, IPOnly signatures would match on every packet on a flow.
To improve performance, what Suricata does is to evaluate rules that are ``ip-
only`` only once per flow direction, for the first packet in each direction.

Application layer protocol transactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each parser has its own state machine, where it uses a per direction parsing
state "progress". For each progress value keywords can be registered. So, for
instance, ``http`` has a value "request line available" for which there are
keywords like :ref:`http.uri <rules-http-uri-normalization>`, :ref:`http.method
<http.method>` etc. registered. If in the traffic the Engine reaches this state,
the signatures with those keywords may be already evaluated, even if they have a
lower priority than a body inspecting signature.

Implications
------------

Use-case: action precedence and interaction with ``ip-only`` rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To illustrate what may be counter-intuitive implications of how inspection
steps, action prioritization and rule keywords interact and affect the engine
behavior, we will use a real case example. Consider these three rules:

.. container:: example-rule

    pass tcp 0.0.0.0/0 any <> 0.0.0.0/0 443 (msg:"Allow TCP in port 443"; flow:
    not_established; sid:1; rev:1;)

.. container:: example-rule

    pass tcp 0.0.0.0/0 any <> 0.0.0.0/0 80 (msg:"Allow TCP in port 80"; flow:
    not_established; sid:2; rev:1;)

.. container:: example-rule

    drop ip 0.0.0.0/0 any -> 0.0.0.0/0 any (msg:"No outbound internet access
    from host"; sid:3; rev:1;)

The first two are signatures that analyze individual packets and match only if
the flow has not been established (``flow:not_established``): the rules grant
``PASS`` to the matched packet - but not to its flow.

The third signature is considered ``ip-only``. This means it will be evaluated
for the *first* packet in both directions of a flow, in addition to rules 1 and
2. By extension, **the other packets in the same flow will not be evaluated
against this rule.**

With an action order configuration that prioritizes ``PASS`` over ``DROP``, this
means that rules 1 and 2 will have a higher internal priority over rule 3,
therefore nullifying the ``DROP`` outcome. The result: a flow expected to be
dropped might not be.

If the expected behavior with those three signatures was to allow traffic on
ports 80 and 443 only, while dropping everything else, the simplest way to
achieve this would be to remove the ``flow:not_established`` portion from rules
sid:1 and sid:2. This ensures that the ``PASS`` action would be applied to the
whole flow following the match on the first packet and that all other traffic
would be dropped.

Now, all three rules are evaluated on the same step, and if a flow isn't flagged
with ``pass``, it will be dropped with the third rule.

Alerts not seen
~~~~~~~~~~~~~~~

Another aspect of rule prioritization, combined with the alerts queue size, is
that in corner cases scenarios, if a packet matches against too many rules,
signatures with lower priority could be discarded from the ``PacketAlert`` queue
(see the section on :ref:`alert queue overflow impact` for an elaboration).

