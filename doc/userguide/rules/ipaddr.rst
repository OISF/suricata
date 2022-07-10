IP Addresses Match
==================

Matching on IP addresses can be done via the IP tuple parameters or via the iprep keywords (see :doc:`/rules/ip-reputation-rules`).
Some keywords providing interaction with dataset are also available.

ip.src
------

The `ip.src` keyword is a sticky buffer to match on source IP address. It is doing a match on the binary representation
and is compatible with the dataset of type `ip` and `ipv4`.

Example:

::

 alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound bad list"; flow:to_server; ip.src; dataset:isset,badips,type ip,load badips.list; sid:1; rev:1;)

ip.dst
------

The `ip.dst` keyword is a sticky buffer to match on destination IP address. It is doing a match on the binary representation
and is compatible with the dataset of type `ip` and `ipv4`.

Example:

::

 alert tcp $HOME_NET any -> any any (msg:"Outbound bad list"; flow:to_server; ip.dst; dataset:isset,badips,type ip,load badips.list; sid:1; rev:1;)
