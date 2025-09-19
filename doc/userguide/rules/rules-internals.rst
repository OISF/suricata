Rule Processing
===============

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

.. important:: Rules processing is also heavily affected by rule types, as mentioned
   in this chapter. You may want to read more on :doc:`rule-types`.

.. note::

    Throughout this documentation and for Suricata, the terms "rule" and
    "signature" are mainly interchangeable, unless context indicates otherwise.

Overview
--------

Rules are provided to Suricata via rules files. Starting from those, the
Detection Engine loader will:

#. Load all the signatures;
#. Check for validity (non-existing keywords; duplicated ``sid`` etc);
#. Report stats on loaded, good and bad signatures;
#. Sort all valid signatures and store them in a list in the Detect Engine
   Context (``DetectEngineCtx``) structure, taking into consideration several
   rule aspects according to their order of relevance to the Detection Engine;
#. Attribute internal rule IDs that reflect this `rule prioritization`_;
#. During inspection, match rules against the inspected traffic, according to rule
   and traffic type.

.. _rule prioritization:

Rule Prioritization
-------------------

Suricata registers several different ordering functions (with
``SCSigRegisterSignatureOrderingFuncs()``), which are then used to compare
the rules, sort them, and define their priority. The elements taken into
consideration for such are the signature's:

#. :ref:`Action <actions>`
#. Usage of :ref:`flowbits`
#. Usage of :ref:`flowint`
#. Usage of flowvar
#. Usage of pktvar
#. Usage of hostbits
#. Usage of ippair
#. :ref:`"Priority" keyword<priority>`

In this order. Once signatures are ordered, they are attributed a unique
internal ID (``Signature::iid``) which symbolizes their priority (the lower the
``iid``, the higher the priority). This could mean that a rule with a
keyword-defined priority of 1 could have lower priority than another rule that
had flowbits set and a rule action with higher priority, for instance.

.. note:: this list isn't fully comprehensive, in the sense that each item has
   extra logic for prioritization. For example, considering flowbits, the
   priority is write (highest) > write + read > read (lowest) > no flowbits.

.. note:: it is also possible to have a rule priority set implicitly, through
   the `classtype` keyword. Check :ref:`classtype`.

Another important element when considering rule parsing, processing and matching
is that the ruleset is optimized into signature group heads based on the signature
elements (thus, for instance, a TCP rule and an UDP rule would be loaded into
different groups, and their internal ids will not interfere between one another,
as they're matched against different traffic). For more on this, see
:ref:`detection-engine`.

Inspection Process
------------------

Once it is time to inspect network traffic against the loaded rules, the
Detect Engine will match against - if applicable:

#. IP Only rules;
#. Packet/payload-related rules;
#. Frame keywords;
#. Application layer protocol transaction rules.

During packet inspection, if the signature uses the last two in this list,
inspection is left to those steps.

.. tip::

  With the introduction of :doc:`Firewall mode <../firewall/firewall-design>`,
  it is possible to explicitly control to which step of the detection engine flow
  a rule will be hooked. This is done with :ref:`Explicit rule hooks <rule-hooks>`.

For each rule that is matched, a ``PacketAlert`` is created. After all matches
for a packet have been processed, and the :ref:`alert queue limit <alert queue
overflow impact>` is taken into account, the remaining ``PacketAlerts`` become
the alerts in Suricata logs.

Considerations on Inspection Steps
----------------------------------

IP Only rules
~~~~~~~~~~~~~

Without optimization, IP Only signatures would match on every packet on a flow.
To improve performance, what Suricata does is to evaluate rules that are
``ip-only`` only once per flow direction, for the first packet in each direction.

Application layer protocol transactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each parser has its own state machine, and uses a per-direction parsing state
"progress". Keywords can be registered for each progress value. So, for
instance, ``http`` has a value "request line available" for which there are
keywords like :ref:`http.uri <rules-http-uri-normalization>`, :ref:`http.method
<http.method>` etc. registered. While parsing the traffic, if the engine reaches
this state, the signatures with those keywords may be already evaluated, even if
they have a lower priority than an http body inspecting signature.

Relatedly, a rule with two keywords matching at two different progress stages may
be evaluated against two different packets.

Implications
------------

Action precedence and interaction with ``ip-only`` rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
therefore nullifying the ``DROP`` outcome. The result: a flow for outbound
internet traffic from the host, expected to be dropped, wouldn't be.

If the expected behavior with those three signatures was to allow traffic on
ports 80 and 443 only, while dropping everything else, the simplest way to
achieve this would be to remove the ``flow:not_established`` portion from rules
sid:1 and sid:2. This ensures that the ``PASS`` action would be applied to the
whole flow following the match on the first packet and that all other traffic
would be dropped.

Following that, all three rules will be evaluated on the same step, and if a
flow isn't flagged with ``pass``, it will be dropped with the third rule.

.. Tip::
   A more straightforward way to achieve that in Suricata 8 is using the firewall
   mode. See :doc:`../firewall/firewall-design`.

Alerts not seen
~~~~~~~~~~~~~~~

Another aspect of rule prioritization combined with the alerts queue size is
that, in corner case scenarios, if a packet matches against too many rules,
signatures with lower priority could be discarded from the ``PacketAlert`` queue
(see the section on :ref:`alert queue overflow impact <alert queue overflow impact>`
for more).

The stats counter ``detect.alert_queue_overflow`` will be higher than zero if
an alert was discarded due to ``Alert Queue`` overflow (cf. :ref:`alerts stats`).

