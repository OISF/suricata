Global-Thresholds
=================

Thresholds can be configured in the rules themselves, see
:doc:`../rules/thresholding`. They are often set by rule writers based on
their intel for creating a rule combined with a judgement on how often
a rule will alert.

Next to these settings, thresholding can be configured on the sensor
using the threshold.config.

threshold/event_filter
~~~~~~~~~~~~~~~~~~~~~~

Syntax:

::

  threshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, track <by_src|by_dst>, count <N>, seconds <T>

rate_filter
~~~~~~~~~~~

TODO

suppress
~~~~~~~~

Suppressions can be used to suppress alerts for a rule or a
host/network. Actions performed when a rule matches, such as setting a
flowbit, are still performed.

Syntax:

::

  suppress gen_id <gid>, sig_id <sid>
  suppress gen_id <gid>, sig_id <sid>, track <by_src|by_dst>, ip <ip|subnet>

Example:

::

  suppress gen_id 1, sig_id 2002087, track by_src, ip 209.132.180.67

This will make sure the signature 2002087 will never match for src
host 209.132.180.67.

.. _global-thresholds-vs-rule-thresholds:

Global thresholds vs rule thresholds
------------------------------------

**Note: this section applies to 1.4+ In 1.3 and before mixing rule and
global thresholds is not supported.**

When a rule has a threshold/detection_filter set a rule can still be
affected by the global threshold file.

The rule below will only fire if 10 or more emails are being
delivered/sent from a host within 60 seconds.

::

  alert tcp any any -> any 25 (msg:"ET POLICY Inbound Frequent Emails - Possible Spambot Inbound"; \
       flow:established; content:"mail from|3a|"; nocase;                                          \
       threshold: type threshold, track by_src, count 10, seconds 60;                              \
       reference:url,doc.emergingthreats.net/2002087; classtype:misc-activity; sid:2002087; rev:10;)

Next, we'll see how global settings affect this rule.

Suppress
~~~~~~~~

Suppressions can be combined with rules with
thresholds/detection_filters with no exceptions.

::

  suppress gen_id 1, sig_id 2002087, track by_src, ip 209.132.180.67
  suppress gen_id 0, sig_id 0, track by_src, ip 209.132.180.67
  suppress gen_id 1, sig_id 0, track by_src, ip 209.132.180.67

Each of the rules above will make sure 2002087 doesn't alert when the
source of the emails is 209.132.180.67. It **will** alert for all other
hosts.

::

  suppress gen_id 1, sig_id 2002087

This suppression will simply convert the rule to "noalert", meaning it
will never alert in any case. If the rule sets a flowbit, that will
still happen.

Threshold/event_filter
~~~~~~~~~~~~~~~~~~~~~~

When applied to a specific signature, thresholds and event_filters
(threshold from now on) will override the signature setting. This can
be useful for when the default in a signature doesn't suit your
evironment.

::

  threshold gen_id 1, sig_id 2002087, type both, track by_src, count 3, seconds 5
  threshold gen_id 1, sig_id 2002087, type threshold, track by_src, count 10, seconds 60
  threshold gen_id 1, sig_id 2002087, type limit, track by_src, count 1, seconds 15

Each of these will replace the threshold setting for 2002087 by the
new threshold setting.

**Note:** overriding all gids or sids (by using gen_id 0 or sig_id 0)
is not supported. Bug #425.

Rate_filter
~~~~~~~~~~~

TODO
