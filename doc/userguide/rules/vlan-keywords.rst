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

Syntax::

 vlan.id: [op]id[,layer];

The id can be matched exactly, or compared using the ``op`` setting::

 vlan.id:300    # exactly 300
 vlan.id:<300,0   # smaller than 300 at layer 0
 vlan.id:>=200,1  # greater or equal than 200 at layer 1

vlan.id uses :ref:`unsigned 16-bit integer <rules-integer-keywords>`.

The valid range for VLAN id values is ``0 - 4095``.

This keyword also supports ``all`` and ``any`` as arguments for ``layer``.
``all`` matches only if all VLAN layers match and ``any`` matches with any layer.

.. table:: **Layer values for vlan.id keyword**

    ===============  ================================================
    Value            Description
    ===============  ================================================
    [default]        Match with any layer
    0 - 2            Match specific layer
    ``-3`` - ``-1``  Match specific layer with back to front indexing
    all              Match only if all layers match
    any              Match with any layer
    ===============  ================================================

This small illustration shows how indexing works for vlan.id::

 [ethernet]
 [vlan 666 (index 0 and -2)]
 [vlan 123 (index 1 and -1)]
 [ipv4]
 [udp]

Examples
^^^^^^^^

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

It is also possible to use the vlan.id content as a fast_pattern by using the ``prefilter`` keyword, as shown in the following example.

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 200 at layer 1"; :example-rule-emphasis:`vlan.id:200,1; prefilter;` sid:1;)

vlan.layers
-----------

Matches based on the number of layers.

Syntax::

 vlan.layers: [op]number;

It can be matched exactly, or compared using the ``op`` setting::

 vlan.layers:3    # exactly 3 vlan layers
 vlan.layers:<3   # less than 3 vlan layers
 vlan.layers:>=2  # more or equal to 2 vlan layers

vlan.layers uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

The minimum and maximum values that vlan.layers can be are ``0`` and ``3``.

Examples
^^^^^^^^

Example of a signature that would alert if a packet has 0 VLAN layers:

.. container:: example-rule

  alert ip any any -> any any (msg:"Packet has 0 vlan layers"; :example-rule-emphasis:`vlan.layers:0;` sid:1;)

Example of a signature that would alert if a packet has more than 1 VLAN layers:

.. container:: example-rule

  alert ip any any -> any any (msg:"Packet has more than 1 vlan layer"; :example-rule-emphasis:`vlan.layers:>1;` sid:1;)

It is also possible to use the vlan.layers content as a fast_pattern by using the ``prefilter`` keyword, as shown in the following example.

.. container:: example-rule

  alert ip any any -> any any (msg:"Packet has 2 vlan layers"; :example-rule-emphasis:`vlan.layers:2; prefilter;` sid:1;)