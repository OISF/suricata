Vlan.id Keyword
==============

Suricata has a ``vlan.id`` keyword that can be used in signatures to identify
and filter network packets based on Virtual Local Area Network IDs.

Syntax::

 vlan.id: id[,layer];

Signature examples::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300; sid:1;)

::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300,1; sid:1;)

::

 alert ip any any -> any any (msg:"Vlan ID is equal to 200"; vlan.id:200,any; sid:1;)