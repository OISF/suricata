IP Reputation Rules
===================

IP Reputation can be used in rules through a new rule directive "iprep".

iprep
~~~~~

The iprep directive matches on the IP reputation information for a host.

::

  iprep:<side to check>,<category>,<operator>,<reputation score>


side to check: <any|src|dst|both>

category: the category short name

operator: <, >, =

reputation score: 1-127

Example:

::


  alert ip $HOME_NET any -> any any (msg:"IPREP internal host talking to CnC server"; flow:to_server; iprep:dst,CnC,>,30; sid:1; rev:1;)

This rule will alert when a system in $HOME_NET acts as a client while communicating with any IP in the CnC category that has a reputation score set to greater than 30.

IP-only
~~~~~~~

The "iprep" keyword is compatible to "IP-only" rules. This means that a rule like:

::


  alert ip any any -> any any (msg:"IPREP High Value CnC"; iprep:src,CnC,>,100; sid:1; rev:1;)

will only be checked once per flow-direction.

For more information about IP Reputation see :doc:`ip-reputation-config` and :doc:`ip-reputation-format`.
