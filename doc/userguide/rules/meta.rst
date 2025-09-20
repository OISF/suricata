Meta Keywords
=============

.. role:: example-rule-emphasis

Meta keywords have no effect on Suricata's inspection of network traffic;
they do have an effect on the way Suricata reports events/alerts.

msg (message)
-------------

The keyword msg gives contextual information about the signature and the possible alert.

The format of msg is::

  msg: "some description";

Examples::

  msg:"ET MALWARE Win32/RecordBreaker CnC Checkin";
  msg:"ET EXPLOIT SMB-DS DCERPC PnP bind attempt";

To continue the example from the previous chapter, the msg component of the
signature is emphasized below:

.. container:: example-rule

    alert http $HOME_NET any -> $EXTERNAL_NET any (:example-rule-emphasis:`msg:"HTTP GET Request Containing Rule in URI";` flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)

.. tip::

   It is a standard practice in rule writing to make the first part of the
   signature msg uppercase and to indicate the class of the signature.

   It is also standard practice that ``msg`` is the first keyword in the signature.

.. note:: The following characters must be escaped inside the msg:
	      ``;`` ``\`` ``"``

sid (signature ID)
------------------

The keyword sid gives every signature its own id. This id is stated with a number
greater than zero. The format of sid is::

  sid:123;

Example of sid in a signature:

.. container:: example-rule

    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; :example-rule-emphasis:`sid:123;` rev:1;)

.. tip::

   It is a standard practice in rule writing that the signature ``sid`` is
   provided as the last keyword (or second-to-last if there is a ``rev``)
   of the signature.

   There are reserved ranges of sids, the reservations are recorded
   at https://sidallocation.org/ .

.. Note::

   This value must be unique for all rules within the same :ref:`rule group
   <gid>` (``gid``).

   As Suricata-update currently considers the rule's ``sid`` only (cf. `Bug#5447
   <https://redmine.openinfosecfoundation.org/issues/5447>`_), it is advisable
   to opt for a completely unique ``sid`` altogether.

rev (revision)
--------------

The sid keyword is commonly accompanied by the rev keyword. Rev
represents the version of the signature. If a signature is modified,
the number of rev will be incremented by the signature writers. The
format of rev is::

  rev:123;


Example of rev in a signature:

.. container:: example-rule

    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; :example-rule-emphasis:`rev:1;`)

.. tip::

    It is a standard practice in rule writing that the rev keyword
    is expressed after the sid keyword. The sid and rev keywords
    are commonly put as the last two keywords in a signature.

.. _gid:

gid (group ID)
--------------

The gid keyword can be used to give different groups of
signatures another id value (like in sid). Suricata by default uses gid 1.
It is possible to modify the default value. In most cases, it will be
unnecessary to change the default gid value. Changing the gid value
has no technical implications, the value is only noted in alert data.

Example of the gid value in an alert entry in the fast.log file.
In the part [1:123], the first 1 is the gid (123 is the sid and 1 is the rev).

.. container:: example-rule

    07/12/2022-21:59:26.713297  [**] [:example-rule-emphasis:`1`:123:1] HTTP GET Request Containing Rule in URI [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.225.121:12407 -> 172.16.105.84:80

.. _classtype:

classtype
---------

The classtype keyword gives information about the classification of
rules and alerts. It consists of a short name, a long name and a
priority. It can tell for example whether a rule is just informational
or is about a CVE. For each classtype, the classification.config has a
priority that will be used in the rule.

Example classtype definition::

  config classification: web-application-attack,Web Application Attack,1
  config classification: not-suspicious,Not Suspicious Traffic,3

Once we have defined the classification in the configuration file,
we can use the classtypes in our rules. A rule with classtype web-application-attack
will be assigned a priority of 1 and the alert will contain 'Web Application Attack'
in the Suricata logs:

=======================  ======================  ===========
classtype                Alert                   Priority
=======================  ======================  ===========
web-application-attack   Web Application Attack  1
not-suspicious           Not Suspicious Traffic  3
=======================  ======================  ===========

Our continuing example also has a classtype: bad-unknown:

.. container:: example-rule

        alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; :example-rule-emphasis:`classtype:bad-unknown;` sid:123; rev:1;)


.. tip::

    It is a standard practice in rule writing that the classtype keyword comes
    before the sid and rev keywords (as shown in the example rule).

reference
---------
The reference keyword is used to document where information about the
signature and about the problem the signature tries to address can be
found. The reference keyword can appear multiple times in a signature.
This keyword is meant for signature-writers and analysts who
investigate why a signature has matched. It has the following format::

  reference:type,reference

A typical reference to www.info.com would be::

  reference:url,www.info.com

There are several systems that can be used as a reference. A
commonly known example is the CVE-database, which assigns numbers to
vulnerabilities, to prevent having to type the same URL over and over
again. An example reference of a CVE::

  reference:cve,CVE-2014-1234

This would make a reference to http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1234.

All the reference types are defined in the reference.config configuration file.

.. _priority:

priority
--------

The priority keyword comes with a mandatory numeric value which can
range from 1 to 255. The values 1 through 4 are commonly used.
The highest priority is 1. Signatures with a higher priority will
be examined first. Normally signatures have a priority determined through
a classtype definition. The classtype definition can be overridden
by defining the priority keyword in the signature.
The format of priority is::

  priority:1;

metadata
--------
The metadata keyword allows additional, non-functional, information to
be added to the signature. While the format is free-form, it is
recommended to stick to `[key, value]` pairs as Suricata can include these
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

.. _keyword_requires:

requires
--------

The ``requires`` keyword allows a rule to require specific Suricata
features to be enabled, specific keywords to be available, or the
Suricata version to match an expression. Rules that do not meet the
requirements will be ignored, and Suricata will not treat them as
errors.

Requirements that follow the valid format of ``<keyword>
<expression>`` but are not known to Suricata are allowed for future
compatiblity, however unknown requirement expressions will lead to the
requirement not being met, skipping the rule.

When parsing rules, the parser attempts to process the ``requires``
keywords before others. This allows it to occur after keywords that
may only be present in specific versions of Suricata, as specified by
the ``requires`` statement. However, the keywords preceding it must
still adhere to the basic known formats of Suricata rules.

The format is::

   requires: feature geoip, version >= 7.0.0, keyword foobar

To require multiple features, the feature sub-keyword must be
specified multiple times::

   requires: feature geoip, feature lua

Alternatively, *and* expressions may be expressed like::

   requires: version >= 7.0.4 < 8

and *or* expressions may expressed with ``|`` like::

   requires: version >= 7.0.4 < 8 | >= 8.0.3

to express that a rule requires version 7.0.4 or greater, but less
than 8, **OR** greater than or equal to 8.0.3. Which could be useful
if a keyword wasn't added until 7.0.4 and the 8.0.3 patch releases, as
it would not exist in 8.0.1.

This can be extended to multiple release branches::

   requires: version >= 7.0.10 < 8 | >= 8.0.5 < 9 | >= 9.0.3

If no *minor* or *patch* version component is provided, it will
default to 0.

The ``version`` may only be specified once, if specified more than
once the rule will log an error and not be loaded.

The ``requires`` keyword was introduced in Suricata 7.0.3 and 8.0.0.
