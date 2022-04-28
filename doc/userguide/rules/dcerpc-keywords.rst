DCERPC Keywords
================

Following keywords can be used for matching on fields in headers and payloads
of DCERPC packets over UDP, TCP and SMB.

dcerpc.iface
-------------

Match on the value of the interface UUID in a DCERPC header. If `any_frag` option
is given, the match shall be done on all fragments. If it's not, the match shall
only happen on the first fragment.

The format of the keyword::

  dcerpc.iface:<uuid>;
  dcerpc.iface:<uuid>,[>,<,!,=]<iface_version>;
  dcerpc.iface:<uuid>,any_frag;
  dcerpc.iface:<uuid>,preack;
  dcerpc.iface:<uuid>,[>,<,!,=]<iface_version>,any_frag,preack;

The `preack` option only works on DCERPC over SMB traffic, where some machines
will submit requests before receiving the bind_ack response. If you want that
your request match after the bind is issue without waiting for the bind_ack,
then you can use `preack`. Keep in mind that if the next bind_ack rejects the
bind context you want to match, it will stop matching.

Examples::

  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,!10;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,any_frag;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,preack;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,>1,any_frag;
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003,>1,any_frag,preack;

ET Open rule example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC WMI Remote Process Execution"; flow:to_server,established; dce_iface:00000143-0000-0000-c000-000000000046; classtype:bad-unknown; sid:2027167; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_04_09, deployment Internal, former_category NETBIOS, signature_severity Informational, updated_at 2019_04_09;)


dcerpc.opnum
-------------

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

dcerpc.stub_data
-----------------

Match on the stub data in a given DCERPC packet. It is a 'sticky buffer'.

Example::

  dcerpc.stub_data; content:"123456";


Additional information
-----------------------

More information on the protocol can be found here:

* DCERPC: `<https://pubs.opengroup.org/onlinepubs/9629399/chap1.htm>`_
