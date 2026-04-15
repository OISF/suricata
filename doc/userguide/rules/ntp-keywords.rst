NTP Keywords
############

.. role:: example-rule-options

ntp.stratum
***********

NTP stratum (integer).

``ntp.stratum`` uses an :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

Syntax::

  ntp.stratum:[op]<number>

The stratum can be matched exactly, or compared using the ``op`` setting::

  ntp.stratum:2    # exactly 2
  ntp.stratum:<16  # smaller than 16
  ntp.stratum:>=1  # greater or equal than 1

Signature Example:

.. container:: example-rule

  alert ntp any any -> any any (msg:"NTP stratum 2"; :example-rule-options:`ntp.stratum:2;` sid:1; rev:1;)

ntp.version
***********

NTP protocol version (integer). Expected values are 3 and 4.

``ntp.version`` uses an :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

Syntax::

  ntp.version:[op]<number>

The version can be matched exactly, or compared using the ``op`` setting::

  ntp.version:4    # exactly 4
  ntp.version:<4   # smaller than 4
  ntp.version:>=3  # greater or equal than 3

Signature Example:

.. container:: example-rule

  alert ntp any any -> any any (msg:"NTP version 4"; :example-rule-options:`ntp.version:4;` sid:2; rev:1;)
