ENIP/CIP Keywords
=================

enip_command
------------

For the ENIP command, we are matching against the command field found in the ENIP encapsulation.

Examples::

  enip_command:99;
  enip_command:list_identity;

enip_command uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.
It can also be specified by text from the enumeration.

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

enip.status
-----------

For the ENIP status, we are matching against the status field found in the ENIP encapsulation.
It uses a 32-bit unsigned integer as value.

enip.status uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`.
It can also be specified by text from the enumeration.

Examples::

  enip.status:100;
  enip.status:>106;
  enip.status:invalid_cmd;

enip.protocol_version
---------------------

Match on the protocol version in different messages.
It uses a 16-bit unsigned integer as value.

enip.protocol_version uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.protocol_version:1;
  enip.protocol_version:>1;

enip.cip_attribute
------------------

Match on the cip attribute in different messages.
It uses a 32-bit unsigned integer as value.

This allows to match without needing to match on cip.service.

enip.cip_attribute uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`.

Examples::

  enip.cip_attribute:1;
  enip.cip_attribute:>1;

enip.cip_instance
-----------------

Match on the cip instance in CIP request path.
It uses a 32-bit unsigned integer as value.

enip.cip_instance uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`.

Examples::

  enip.cip_instance:1;
  enip.cip_instance:>1;

enip.cip_class
--------------

Match on the cip class in CIP request path.
It uses a 32-bit unsigned integer as value.

enip.cip_class uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`.

This allows to match without needing to match on cip.service.

Examples::

  enip.cip_class:1;
  enip.cip_class:>1;

enip.cip_extendedstatus
-----------------------

Match on the cip extended status, if any is present.
For multiple service packet, will match on any of the seen statuses.
It uses a 16-bit unsigned integer as value.

enip.cip_extendedstatus uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.cip_extendedstatus:1;
  enip.cip_extendedstatus:>1;

enip.revision
-------------

Match on the revision in identity message.
It uses a 16-bit unsigned integer as value.

enip.revision uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.revision:1;
  enip.revision:>1;

enip.identity_status
--------------------

Match on the status in identity message (not in ENIP header).
It uses a 16-bit unsigned integer as value.

enip.identity_status uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.identity_status:1;
  enip.identity_status:>1;

enip.state
----------

Match on the state in identity message.
It uses an 8-bit unsigned integer as value.

enip.state uses an :ref:`unsigned 8-bits integer <rules-integer-keywords>`.

Examples::

  enip.state:1;
  enip.state:>1;

enip.serial
-----------

Match on the serial in identity message.
It uses a 32-bit unsigned integer as value.

enip.serial uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`.

Examples::

  enip.serial:1;
  enip.serial:>1;

enip.product_code
-----------------

Match on the product code in identity message.
It uses a 16-bit unsigned integer as value.

enip.product_code uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.product_code:1;
  enip.product_code:>1;

enip.device_type
----------------

Match on the device type in identity message.
It uses a 16-bit unsigned integer as value.

enip.device_type uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.device_type:1;
  enip.device_type:>1;

enip.vendor_id
--------------

Match on the vendor id in identity message.
It uses a 16-bit unsigned integer as value.

enip.vendor_id uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.vendor_id:1;
  enip.vendor_id:>1;

enip.product_name
-----------------

Match on the product name in identity message.

Examples::

  enip.product_name; pcre:"/^123[0-9]*/";
  enip.product_name; content:"swordfish";

``enip.product_name`` is a 'sticky buffer' and can be used as ``fast_pattern``.

enip.service_name
-----------------

Match on the service name in list services message.

Examples::

  enip.service_name; pcre:"/^123[0-9]*/";
  enip.service_name; content:"swordfish";

``enip.service_name`` is a 'sticky buffer' and can be used as ``fast_pattern``.

enip.capabilities
-----------------

Match on the capabilities in list services message.
It uses a 16-bit unsigned integer as value.

enip.capabilities uses an :ref:`unsigned 16-bits integer <rules-integer-keywords>`.

Examples::

  enip.capabilities:1;
  enip.capabilities:>1;

enip.cip_status
---------------

Match on the cip status (one of them in case of multiple service packet).
It uses an 8-bit unsigned integer as value.

enip.cip_status uses an :ref:`unsigned 8-bits integer <rules-integer-keywords>`.

Examples::

  enip.cip_status:1;
  enip.cip_status:>1;