.. _DCERPC Rule Keywords:

DCERPC Keywords
===============

Following keywords can be used for matching on fields in headers and payloads
of DCERPC packets over UDP, TCP and SMB.

dcerpc.iface
------------

Match on the interface UUID of a DCERPC request, as negotiated by the BIND and
accepted by the BIND_ACK. By default only requests with the ``PFC_FIRST_FRAG``
flag set match, i.e. unfragmented requests and first fragments. With the
``any_frag`` option all fragments match. The fragment flags of the BIND are
not considered.

The format of the keyword::

  dcerpc.iface:<uuid>;
  dcerpc.iface:<uuid>,[>,<,!,=]<iface_version>;
  dcerpc.iface:<uuid>,any_frag;
  dcerpc.iface:<uuid>,[>,<,!,=]<iface_version>,any_frag;

Examples::

  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,!10;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,any_frag;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,>1,any_frag;

ET Open rule example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC WMI Remote Process Execution"; flow:to_server,established; dce_iface:00000143-0000-0000-c000-000000000046; classtype:bad-unknown; sid:2027167; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_04_09, deployment Internal, former_category NETBIOS, signature_severity Informational, updated_at 2019_04_09;)


dcerpc.opnum
------------

Match on one or many operation numbers and/or operation number range within the
interface in a DCERPC header.

The format of the keyword::

  dcerpc.opnum:<u16>;
  dcerpc.opnum:[>,<,!,=]<u16>;
  dcerpc.opnum:<u16>,<u16>,<u16>....;
  dcerpc.opnum:<u16>-<u16>;

Examples::

  dcerpc.opnum:15;
  dcerpc.opnum:>10;
  dcerpc.opnum:12,24,62,61;
  dcerpc.opnum:12,18-24,5;
  dcerpc.opnum:12-14,12,121,62-78;

.. note:: earlier versions of the documentation incorrectly stated that greater than, less than, etc. notation was supported. This was added in suricata 9, see ticket `#8179 <https://redmine.openinfosecfoundation.org/issues/8179>`_).

dcerpc.opnum can since suricata 9 use an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

dcerpc.stub_data
----------------

Match on the stub data in a given DCERPC packet. It is a 'sticky buffer'.

Example::

  dcerpc.stub_data; content:"123456";


Additional information
----------------------

More information on the protocol can be found here:

* DCERPC: `<https://pubs.opengroup.org/onlinepubs/9629399/chap1.htm>`_
