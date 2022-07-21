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

#. load all the signatures;
#. check for validity (non-existing keywords; duplicated sid etc);
#. report stats on loaded, good and bad signatures;
#. sort all valid signatures and store them in a list in the Detection Engine
   Contect (``DetectEngineCtx``) structure, taking into consideration several
   rule aspects according to their order of relevance to the Detection Engine;
#. attribute internal rule ids that reflect this `rule prioritization`_;
#. during inspection, match rules against the inspected traffic, according to rule
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
Detection Engine will match against - if applicable:

#. IPOnly rules (those where packet payload isn't inspected);
#. Packet/payload related rules;
#. Frame keywords;
#. Application layer protocol transactions.

During packet inspection, if the signature uses the last two, inspection is
left to those steps.

Each rule that matches becomes a ``PacketAlert``. These will, after all matches
for the packet have been processed, become the alerts that are seen in Suricata
logs.

Implications
------------

Rule prioritization combined with the alerts queue size may mean that, in corner
cases, if a packet matches against too many rules, signatures with lower
priority could be discarded from the ``PacketAlert`` queue (see the section on
:ref:`alert queue overflow impact` for an elaboration).
