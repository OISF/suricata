Meta Keywords
=============

.. role:: example-rule-emphasis

Meta-settings have no effect on Suricata's inspection; they do have an effect on the way Suricata reports events.

msg (message)
-------------

The keyword msg gives textual information about the signature and the possible alert.

The format of msg is::

  msg: "some description";

Examples::

  msg:"ATTACK-RESPONSES 403 Forbidden";
  msg:"ET EXPLOIT SMB-DS DCERPC PnP bind attempt";

To continue the example of the previous chapter, this is the keyword in action in an actual rule:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (:example-rule-emphasis:`msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)";` flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

.. tip::

   It is convention to make the first part of the signature uppercase and show the class of the signature.

   It is also convention that ``msg`` is made the first keyword in the signature.

.. note:: The following characters must be escaped inside the msg:
	      ``;`` ``\`` ``"``

sid (signature ID)
------------------

The keyword sid gives every signature its own id. This id is stated with a number
greater than zero. The format of sid is::

  sid:123;

Example of sid in a signature:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; :example-rule-emphasis:`sid:2008124;` rev:2;)

.. tip::

   It is convention that the signature ``sid`` is provided as the last keyword (or second-to-last if there is a ``rev``) of the signature.

.. Note::

   This value must be unique for all rules within the same :ref:`rule group
   <gid>` (``gid``).

   As Suricata-update currently considers the rule's ``sid`` only (cf. `Bug#5447
   <https://redmine.openinfosecfoundation.org/issues/5447>`_), it is adviseable
   to opt for a completely unique ``sid`` altogether.

rev (revision)
--------------

The sid keyword is almost every time accompanied by rev. Rev
represents the version of the signature. If a signature is modified,
the number of rev will be incremented by the signature writers.  The
format of rev is::

  rev:123;


Example of rev in a signature:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; :example-rule-emphasis:`rev:2;`)

.. tip::

    It is a convention that sid comes before rev, and both are the last
    of all keywords.

.. _gid:

gid (group ID)
--------------

The gid keyword can be used to give different groups of signatures
another id value (like in sid). Suricata uses by default gid 1. It is
possible to modify this. It is not usual that it will be changed, and
changing it has no technical implications. You can only notice it in
the alert.

Example of gid in an alert of fast.log. In the part [1:2008124:2], 1 is the gid (2008124 is the sid and 2 the rev).

.. container:: example-rule

    10/15/09-03:30:10.219671  [**] [:example-rule-emphasis:`1`:2008124:2] ET TROJAN Likely Bot Nick in IRC (USA +..) [**] [Classification: A Network Trojan was Detected]
    [Priority: 3] {TCP} 192.168.1.42:1028 -> 72.184.196.31:6667


classtype
---------

The classtype keyword gives information about the classification of
rules and alerts. It consists of a short name, a long name and a
priority. It can tell for example whether a rule is just informational
or is about a hack etcetera. For each classtype, the
classification.config has a priority which will be used in the rule.

Example classtype definition::

  config classification: web-application-attack,Web Application Attack,1
  config classification: not-suspicious,Not Suspicious Traffic,3

Now when we have defined this in the configuration, we can use the classtypes
in our rules. A rule with classtype web-application-attack will be assigned
a priority of 1 and the alert will contain 'Web Application Attack':

=======================  ======================  ===========
classtype                Alert                   Priority
=======================  ======================  ===========
web-application-attack   Web Application Attack  1
not-suspicious           Not Suspicious Traffic  3
=======================  ======================  ===========

Our continuing example has also a classtype, this one of trojan-activity:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; :example-rule-emphasis:`classtype:trojan-activity;` sid:2008124; rev:2;)


.. tip::

    It is a convention that classtype comes before sid and rev and after
    the rest of the keywords.

reference
---------

The reference keywords direct to places where information about the
signature and about the problem the signature tries to address, can be
found. The reference keyword can appear multiple times in a signature.
This keyword is meant for signature-writers and analysts who
investigate why a signature has matched. It has the following format::

  reference: type, reference

A typical reference to www.info.com would be::

  reference: url, www.info.com

However, there are also several systems that can be used as a reference. A
commonly known example is the CVE-database, that assigns numbers to
vulnerabilities. To prevent you from typing the same URL over and over
again, you can use something like this::

  reference: cve, CVE-2014-1234

This would make a reference to http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1234.
All reference types are defined in the reference.config configuration file.

Our continuing example also has a reference:

.. container:: example-rule

    drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; :example-rule-emphasis:`reference:url,doc.emergingthreats.net/2008124;` classtype:trojan-activity; sid:2008124; rev:2;)


priority
--------

The priority keyword comes with a mandatory numeric value which can
range from 1 till 255. The numbers 1 to 4 are most often used.
Signatures with a higher priority will be examined first. The highest
priority is 1.  Normally signatures have already a priority through
classtype. This can be overruled with the keyword priority.  The
format of priority is::

  priority:1;

metadata
--------

The metadata keyword allows additional, non-functional information to
be added to the signature. While the format is free-form, it is
recommended to stick to key, value pairs as Suricata can include these
in eve alerts. The format is::

  metadata: key value;
  metadata: key value, key value;

target
------

The target keyword allows the rules writer to specify which side of the
alert is the target of the attack. If specified, the alert event is enhanced
to contain information about source and target.

The format is::

   target:[src_ip|dest_ip]

If the value is src_ip then the source IP in the generated event (src_ip
field in JSON) is the target of the attack. If target is set to dest_ip
then the target is the destination IP in the generated event.
