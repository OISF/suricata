DCERPC Keywords
=============

Following keywords can be used for matching on fields in headers and payloads of DCERPC packets.

dce_iface
----------

Match on the value of the interface UUID in a DCERPC header.

The format of the keyword::

  dce_iface:<uuid>;

Example::

  dce_iface:367abb81-9844-35f1-ad32-98f038001003;


dce_opnum
---------

Match on the operation number within the interface in a DCERPC header.

The format of the keyword::

  dce_opnum:<u16>;

Example::

  dce_opnum:15;


dce_stub_data
-------------

Match on the stub data in a given DCERPC packet. It is a 'sticky buffer'.

Example::

  dce_stub_data; content:"123456";


Additional information
----------------------

More information on the protocol can be found here:

* DCERPC: `<https://pubs.opengroup.org/onlinepubs/9629399/chap1.htm>`_
