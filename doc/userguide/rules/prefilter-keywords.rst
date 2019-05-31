=====================
Prefiltering Keywords
=====================

.. _rules-keyword-fast_pattern:

fast_pattern
============
.. toctree::

   fast-pattern-explained

Only one content of a signature will be used in the Multi Pattern
Matcher (MPM). If there are multiple contents, then Suricata uses the
'strongest' content. This means a combination of length, how varied a
content is, and what buffer it is looking in. Generally, the longer
and more varied the better. For full details on how Suricata
determines the fast pattern match, see :doc:`fast-pattern-explained`.

Sometimes a signature writer concludes he wants Suricata to use
another content than it does by default.

For instance::

  User-agent: Mozilla/5.0 Badness;

  content:"User-Agent|3A|";
  content:"Badness"; distance:0;

In this example you see the first content is longer and more varied
than the second one, so you know Suricata will use this content for
the MPM.  Because 'User-Agent:' will be a match very often, and
'Badness' appears less often in network traffic, you can make Suricata
use the second content by using 'fast_pattern'.

::

  content:"User-Agent|3A|";
  content:"Badness"; distance:0; fast_pattern;

The keyword fast_pattern modifies the content previous to it.

.. image:: fast-pattern/fast_pattern.png

Fast-pattern can also be combined with all previous mentioned
keywords, and all mentioned HTTP-modifiers.

fast_pattern:only
~~~~~~~~~~~~~~~~~

Sometimes a signature contains only one content. In that case it is
not necessary Suricata will check it any further after a match has
been found in MPM. If there is only one content, the whole signature
matches. Suricata notices this automatically. In some signatures this
is still indicated with 'fast_pattern:only;'. Although Suricata does
not need fast_pattern:only, it does support it.

fast_pattern:'chop'
~~~~~~~~~~~~~~~~~~~~

If you do not want the MPM to use the whole content, you can use
fast_pattern 'chop'.

For example::

  content: "aaaaaaaaabc"; fast_pattern:8,4;

This way, MPM uses only the last four characters.


prefilter
=========
The prefilter engines for other non-MPM keywords can be enabled in specific rules by using the 'prefilter' keyword.

In the following rule the TTL test will be used in prefiltering instead of the single byte pattern:

::

  alert ip any any -> any any (ttl:123; prefilter; content:"a"; sid:1;)

For more information on how to configure the prefilter engines, see :ref:`suricata-yaml-prefilter`
