Vlan.id Keyword
===============

Suricata has a ``vlan.id`` keyword that can be used in signatures to identify
and filter network packets based on Virtual Local Area Network IDs. By default,
it matches all layers if a packet contains multiple VLAN layers. However, if a
specific layer is defined, it will only match that layer.

vlan.id uses :ref:`unsigned 16-bit integer <rules-integer-keywords>`.

Syntax::

 vlan.id: [op]id[,layer];

The id can be matched exactly, or compared using the _op_ setting::

 vlan.id:300    # exactly 300
 vlan.id:<300,0   # smaller than 300 at layer 0
 vlan.id:>=200,1  # greater or equal than 200 at layer 1

Signature examples::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300; sid:1;)

::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300,1; sid:1;)

::

 alert ip any any -> any any (msg:"Vlan ID is equal to 400"; vlan.id:400,-1; sid:1;)

In this example, we use the negative value -1 to represent the last layer of the VLAN IDs.