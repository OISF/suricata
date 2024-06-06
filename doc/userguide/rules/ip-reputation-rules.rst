IP Reputation Keyword
=====================

IP Reputation can be used in rules through a new rule keyword "iprep".

For more information about IP Reputation see :doc:`/reputation/ipreputation/ip-reputation-config` and :doc:`/reputation/ipreputation/ip-reputation-format`.

iprep
-----

The iprep directive matches on the IP reputation information for a host.

::

  iprep:<side to check>,<category>,<operator>,<reputation score>


side to check: <any|src|dst|both>

``category``: the category short name

``operator``: <, <=, >, >=, =

``reputation score``: 0-127

Example:

::

  alert ip $HOME_NET any -> any any (msg:"IPREP internal host talking to CnC server"; flow:to_server; iprep:dst,CnC,>,30; sid:1; rev:1;)

This rule will alert when a system in ``$HOME_NET`` acts as a client while communicating with any IP in the CnC category that has a reputation score set to greater than 30.

isset and isnotset
~~~~~~~~~~~~~~~~~~

``isset`` and ``isnotset`` can be used to test reputation "membership"

::

    iprep:<side to check>,<category>,<isset|issnotset>


``side to check``: <any|src|dst|both>

``category``: the category short name

To test whether an IP is part of an iprep set at all, the ``isset`` can be used. It acts as a ``>=,0`` statement.

.. container:: example-rule

   drop ip $HOME_NET any -> any any (:example-rule-options:`iprep:src,known-bad-hosts,isset;` sid:1;)

In this example traffic to any IP with a score in ``known-bad-hosts`` would be blocked.

``isnotset`` can be used to test if an IP is not a part of the set.

.. container:: example-rule

   drop ip $HOME_NET any -> any any (:example-rule-options:`iprep:src,trusted-hosts,isnotset;` sid:1;)

In this example traffic for a host w/o a trust score would be blocked.

Compatibility with IP-only
~~~~~~~~~~~~~~~~~~~~~~~~~~

The "iprep" keyword is compatible with "IP-only" rules. This means that a rule like:

::


  alert ip any any -> any any (msg:"IPREP High Value CnC"; iprep:src,CnC,>,100; sid:1; rev:1;)

will only be checked once per flow-direction.
