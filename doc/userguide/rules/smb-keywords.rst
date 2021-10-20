SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.


dce_iface
-------------

You can use the `dce_iface` keyword to match the DCERPC packets related to an interface
that is transported by SMB.


For example, to match the packets trying to access to the printer service you can use
the following rule::

  alert smb any any -> any any (\
      msg: "SMB-DCE spoolss";\
      dce_iface: 12345678-1234-abcd-ef00-0123456789ab;\
      sid: 1;\
      )


dce_opnum
------------

You can use the `dce_opnum` keyword to match the DCERPC packets that are transported by SMB.

For example, to match packets with opnum 10, you can use the following rule::

    alert smb any any -> any any (\
      msg: "SMB-DCE opnum 10";\
      dce_opnum: 10;\
      sid: 1;\
      )


You can also combine `dce_opnum` and `dce_iface` in a single rule.
The following example will match the `EnumPrinterDrivers` method of printer service::

  alert smb any any -> any any (\
      msg: "SMB-DCE EnumPrinterDrivers";\
      flow: to_server;\
      dce_iface: 12345678-1234-abcd-ef00-0123456789ab;\
      dce_opnum: 10;\
      sid: 1;\
      )
