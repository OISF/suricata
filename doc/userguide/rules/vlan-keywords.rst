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

.. table:: **Id values for vlan.id keyword**

    ========  ================================================
    Value     Description
    ========  ================================================
    1 - 4094  Valid range for vlan id
    0 - 3     Valid range of number of layers (with ``count``)
    ========  ================================================

This keyword also supports ``all`` and ``count`` as arguments for ``layer``.
``all`` matches only if all VLAN layers match and ``count`` matches based on
the number of layers.

.. table:: **Layer values for vlan.id keyword**

    ===============  ================================================
    Value            Description
    ===============  ================================================
    [default]        Match all layers
    0 - 2            Match specific layer
    ``-3`` - ``-1``  Match specific layer with back to front indexing
    all              Match only if all layers match
    count            Match on the number of layers
    any              Match all layers
    ===============  ================================================

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

Example of a signature that would alert if the packet has 3 VLAN layers:

.. container:: example-rule

  alert ip any any -> any any (msg:"Packet has 3 VLAN layers"; :example-rule-emphasis:`vlan.id:3,count;` sid:1;)

It is also possible to use the vlan.id content as a fast_pattern by using the ``prefilter`` keyword, as shown in the following example.

.. container:: example-rule

  alert ip any any -> any any (msg:"Vlan ID is equal to 200 at layer 1"; :example-rule-emphasis:`vlan.id:200,1; prefilter;` sid:1;)
