DCERPC Keywords
================

Following keywords can be used for matching on fields in headers and payloads
of DCERPC packets over UDP, TCP and SMB.

dcerpc.iface
-------------

Match on the value of the interface UUID in a DCERPC header.

The format of the keyword::

  dcerpc.iface:<uuid>;

Example::

  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003;

ET Open rule example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC WMI Remote Process Execution"; flow:to_server,established; dce_iface:00000143-0000-0000-c000-000000000046; classtype:bad-unknown; sid:2027167; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_04_09, deployment Internal, former_category NETBIOS, signature_severity Informational, updated_at 2019_04_09;)


dcerpc.opnum
-------------

Match on the operation number within the interface in a DCERPC header.

The format of the keyword::

  dcerpc.opnum:<u16>;

Example::

  dcerpc.opnum:15;


dcerpc.stub_data
-----------------

Match on the stub data in a given DCERPC packet. It is a 'sticky buffer'.

Example::

  dcerpc.stub_data; content:"123456";


Additional information
-----------------------

More information on the protocol can be found here:

* DCERPC: `<https://pubs.opengroup.org/onlinepubs/9629399/chap1.htm>`_
