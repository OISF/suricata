IKEv1 Keywords
==============

The keywords

* ``ikev1.spi_initiator``
* ``ikev1.spi_responder``
* ``ikev1.chosen_sa_attribute``
* ``ikev1.exchtype``
* ``ikev1.vendor``
* ``ikev1.server_key_exchange_payload``
* ``ikev1.client_key_exchange_payload``
* ``ikev1.key_exchange_payload_length``
* ``ikev1.server_nonce_payload``
* ``ikev1.client_nonce_payload``
* ``ikev1.nonce_payload_length``

can be used for matching on various properties of IKEv1 connections.


ikev1.spi_initiator, ikev1.spi_responder
----------------------------------------

Match on an exact value of the Security Parameter Index (SPI) for the Initiator or Responder.

Examples::

  ikev1.spi_initiator; content:"18fe9b731f9f8034";
  ikev1.spi_responder; pcre:"/.*034$/";

``ikev1.spi_initiator`` and ``ikev1.spi_responder`` are 'sticky buffers'.

``ikev1.spi_initiator`` and ``ikev1.spi_responder`` can be used as ``fast_pattern``.


ikev1.chosen_sa_attribute
-------------------------

Match on an attribute value of the chosen Security Association (SA) by the Responder. Supported are:
``encryption_algorithm``,
``hash_algorithm``,
``authentication_method``,
``group_description``,
``group_type``,
``life_type``,
``life_duration``,
``prf``,
``key_length`` and
``field_size``.

Examples::

    ikev1.chosen_sa_attribute:hash_algorithm=2;
    ikev1.chosen_sa_attribute:key_length=128;


ikev1.exchtype
-------------------------

Match on the value of the Exchange Type.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)

Examples::

    ikev1.exchtype:5;
    ikev1.exchtype:>=2;


ikev1.vendor
------------

Match a vendor ID against the list of collected vendor IDs.

Examples::

    ikev1.vendor:4a131c81070358455c5728f20e95452f;


ikev1.server_key_exchange_payload, ikev1.client_key_exchange_payload
--------------------------------------------------------------------

Match against the public key exchange payload (e.g. Diffie-Hellman) of the Server or Client.

Examples::

    ikev1.server_key_exchange_payload; content:"6d026d5616c45be05e5b898411e9"
    ikev1.client_key_exchange_payload; pcre:"/.*11e9$/";

``ikev1.server_key_exchange_payload`` and ``ikev1.client_key_exchange_payload`` are 'sticky buffers'.

``ikev1.server_key_exchange_payload`` and ``ikev1.client_key_exchange_payload`` can be used as ``fast_pattern``.


ikev1.key_exchange_payload_length
---------------------------------

Match against the length of the public key exchange payload (e.g. Diffie-Hellman) of the Server or Client.

This keyword takes a numeric argument after a colon and the declaration of server or client and supports additional qualifiers, such as:

* ``=`` (equal)
* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)

Examples::

    ikev1.key_exchange_payload_length:server=132
    ikev1.key_exchange_payload_length:client>132


ikev1.server_nonce_payload, ikev1.client_nonce_payload
------------------------------------------------------

Match against the nonce of the Server or Client.

Examples::

    ikev1.server_nonce_payload; content:"6d026d5616c45be05e5b898411e9"
    ikev1.client_nonce_payload; pcre:"/.*11e9$/";

``ikev1.server_nonce_payload`` and ``ikev1.client_nonce_payload`` are 'sticky buffers'.

``ikev1.server_nonce_payload`` and ``ikev1.client_nonce_payload`` can be used as ``fast_pattern``.


ikev1.nonce_payload_length
--------------------------

Match against the length of the nonce of the Server or Client.

This keyword takes a numeric argument after a colon and the declaration of server or client and supports additional qualifiers, such as:

* ``=`` (equal)
* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)

Examples::

    ikev1.nonce_payload_length:server=132
    ikev1.nonce_payload_length:client>132


Additional information
----------------------

More information on the protocol and the data contained in it can be found here:
`<https://tools.ietf.org/html/rfc2409>`_
