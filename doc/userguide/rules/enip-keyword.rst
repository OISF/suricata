ENIP/CIP Keywords
=================

enip_command
------------

For the ENIP command, we are matching against the command field found in the ENIP encapsulation.

Examples::

  enip_command:99;
  enip_command:ListIdentity;


cip_service
-----------

For the CIP Service, we use a maximum of 3 comma separated values representing the Service, Class and Attribute.
These values are described in the CIP specification. CIP Classes are associated with their Service, and CIP Attributes
are associated with their Service. If you only need to match up until the Service, then only provide the Service value.
If you want to match to the CIP Attribute, then you must provide all 3 values.

Examples::

  cip_service:75
  cip_service:16,246,6


(cf. http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf)

Information on the protocol can be found here:
`<http://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf>`_
