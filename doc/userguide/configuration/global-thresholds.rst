Global-Thresholds
=================

Thresholds can be configured in the rules themselves, see
:doc:`../rules/thresholding`. They are often set by rule writers based on
their intel for creating a rule combined with a judgement on how often
a rule will alert.

Threshold Config
----------------

Next to rule thresholding more thresholding can be configured on the sensor
using the threshold.config.

threshold/event_filter
~~~~~~~~~~~~~~~~~~~~~~

Syntax:

::

  threshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, \
    track <by_src|by_dst>, count <N>, seconds <T>

rate_filter
~~~~~~~~~~~

Rate filters allow changing of a rule action when a rule matches.

Syntax::

  rate_filter: rate_filter gen_id <gid>, sig_id <sid>, track <tracker>, \
    count <c>, seconds <s>, new_action <action>, timeout <timeout>

Example::

  rate_filter gen_id 1, sig_id 1000, track by_rule, count 100, seconds 60, \
    new_action alert, timeout 30

gen_id
^^^^^^
Generator id. Normally 1, but if a rule uses the ``gid`` keyword to set
another value it has to be matched in the ``gen_id``.

sig_id
^^^^^^

Rule/signature id as set by the rule ``sid`` keyword.

track
^^^^^

Where to track the rule matches. When using by_src/by_dst the tracking is
done per IP-address. The Host table is used for storage. When using by_rule
it's done globally for the rule.

count
^^^^^

Number of rule hits before the ``rate_filter`` is activated.

seconds
^^^^^^^

Time period within which the ``count`` needs to be reached to activate
the ``rate_filter``

new_action
^^^^^^^^^^

New action that is applied to matching traffic when the ``rate_filter``
is in place.

Values::

  <alert|drop|pass|reject>

Note: 'sdrop' and 'log' are supported by the parser but not implemented otherwise.

timeout
^^^^^^^

Time in seconds during which the ``rate_filter`` will remain active.

Example
^^^^^^^

Lets say we want to limit incoming connections to our SSH server. The rule
``888`` below simply alerts on SYN packets to the SSH port of our SSH server.
If an IP-address triggers this more than 10 or more with a minute, the
drop ``rate_filter`` is set with a timeout of 5 minutes.

Rule::

  alert tcp any any -> $MY_SSH_SERVER 22 (msg:"Connection to SSH server"; \
    flow:to_server; flags:S,12; sid:888;)

Rate filter::

  rate_filter gen_id 1, sig_id 888, track by_src, count 10, seconds 60, \
    new_action drop, timeout 300


suppress
~~~~~~~~

Suppressions can be used to suppress alerts for a rule or a
host/network. Actions performed when a rule matches, such as setting a
flowbit, are still performed.

Syntax:

::

  suppress gen_id <gid>, sig_id <sid>
  suppress gen_id <gid>, sig_id <sid>, track <by_src|by_dst>, ip <ip|subnet>

Examples:

::

  suppress gen_id 1, sig_id 2002087, track by_src, ip 209.132.180.67

This will make sure the signature 2002087 will never match for src
host 209.132.180.67.

Other possibilities/examples::

  suppress gen_id 1, sig_id 2003614, track by_src, ip 217.110.97.128/25
  suppress gen_id 1, sig_id 2003614, track by_src, ip [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
  suppress gen_id 1, sig_id 2003614, track by_src, ip $HOME_NET

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
