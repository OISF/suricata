VLAN Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

vlan.id
-------

Suricata has a ``vlan.id`` keyword that can be used in signatures to identify
and filter network packets based on Virtual Local Area Network IDs. By default,
it matches all layers if a packet contains multiple VLAN layers. However, if a
specific layer is defined, it will only match that layer.

VLAN id values must be between 1 and 4094. The maximum number of layers
supported per packet is 3, and the vlan.id keyword supports negative index
values to access layers from back to front.

This keyword also supports ``all`` as an argument for ``layer``,
which matches only if all VLAN layers match.


vlan.id uses :ref:`unsigned 16-bit integer <rules-integer-keywords>`.

Syntax::

 vlan.id: [op]id[,layer];

The id can be matched exactly, or compared using the ``op`` setting::

 vlan.id:300    # exactly 300
 vlan.id:<300,0   # smaller than 300 at layer 0
 vlan.id:>=200,1  # greater or equal than 200 at layer 1

Example of a signature that would alert if any of the VLAN IDs is equal to 300:

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 300"; :example-rule-emphasis:`vlan.id:300;` sid:1;)

Example of a signature that would alert if the VLAN ID at layer 1 is equal to 300:

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 300 at layer 1"; :example-rule-emphasis:`vlan.id:300,1;` sid:1;)

Example of a signature that would alert if the VLAN ID at the last layer is equal to 400:

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 400 at the last layer"; :example-rule-emphasis:`vlan.id:400,-1;` sid:1;)

Example of a signature that would alert only if all the VLAN IDs are greater than 100:

.. container:: example-rule

  alert ip any any -> any any (msg:"All Vlan IDs are greater than 100"; :example-rule-emphasis:`vlan.id:>100,all;` sid:1;)

It is also possible to use the vlan.id content as a fast_pattern by using the :example-rule-options:`prefilter` keyword, as shown in the following example.

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 200 at layer 1"; :example-rule-emphasis:`vlan.id:200,1; prefilter;` sid:1;)
