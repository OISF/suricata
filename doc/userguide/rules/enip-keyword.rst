ENIP/CIP Keywords
=================

The enip_command and cip_service keywords can be used for matching on various properties of
ENIP requests.

There are three ways of using this keyword:

* matching on ENIP command with the setting "enip_command";
* matching on CIP Service with the setting "cip_service".
* matching both the ENIP command and the CIP Service with "enip_command" and "cip_service" together


For the ENIP command, we are matching against the command field found in the ENIP encapsulation.

For the CIP Service, we use a maximum of 3 comma seperated values representing the Service, Class and Attribute.
These values are described in the CIP specification.  CIP Classes are associated with their Service, and CIP Attributes
are associated with their Service.  If you only need to match up until the Service, then only provide the Service value.
If you want to match to the CIP Attribute, then you must provide all 3 values.


Syntax::

  enip_command:<value>
  cip_service:<value(s)>
  enip_command:<value>, cip_service:<value(s)>


Examples::

  enip_command:99
  cip_service:75
  cip_service:16,246,6
  enip_command:111, cip_service:5


(cf. http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf)

Information on the protocol can be found here:
`<http://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf>`_
