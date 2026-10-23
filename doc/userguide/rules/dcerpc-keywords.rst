.. _DCERPC Rule Keywords:

DCERPC Keywords
===============

Following keywords can be used for matching on fields in headers and payloads
of DCERPC packets over UDP, TCP and SMB.

dcerpc.iface
------------

Match on the value of the interface UUID in a DCERPC header. If `any_frag` option
is given, the match shall be done on all fragments. If it's not, the match shall
only happen on the first fragment.

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

dcerpc.ptype
------------

Match on the PDU type of a DCERPC header. On a to_server match the request PDU
type is used, on a to_client match the response PDU type is used.

The format of the keyword::

  dcerpc.ptype:<u8>;
  dcerpc.ptype:[>,<,!,=]<u8>;

The PDU type values are:

===== =====================
Value PDU type
===== =====================
0     request
1     ping
2     response
3     fault
4     working
5     nocall
6     reject
7     ack
8     cl_cancel
9     fack
10    cancel_ack
11    bind
12    bind_ack
13    bind_nak
14    alter_context
15    alter_context_resp
16    auth3
17    shutdown
18    co_cancel
19    orphaned
20    rts
===== =====================

Examples::

  dcerpc.ptype:11;
  dcerpc.ptype:!0;
  dcerpc.ptype:>10;

dcerpc.ptype uses an :ref:`unsigned 8-bits integer <rules-integer-keywords>`.

dcerpc.stub_data
----------------

Match on the stub data in a given DCERPC packet. It is a 'sticky buffer'.

Example::

  dcerpc.stub_data; content:"123456";


Additional information
----------------------

More information on the protocol can be found here:

* DCERPC: `<https://pubs.opengroup.org/onlinepubs/9629399/chap1.htm>`_
