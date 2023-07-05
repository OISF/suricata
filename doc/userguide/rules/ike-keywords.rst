IKE Keywords
============

The keywords

* ``ike.init_spi``
* ``ike.resp_spi``
* ``ike.chosen_sa_attribute``
* ``ike.exchtype``
* ``ike.vendor``
* ``ike.key_exchange_payload``
* ``ike.key_exchange_payload_length``
* ``ike.nonce_payload``
* ``ike.nonce_payload_length``

can be used for matching on various properties of IKE connections.


ike.init_spi, ike.resp_spi
--------------------------

Match on an exact value of the Security Parameter Index (SPI) for the Initiator or Responder.

Examples::

  ike.init_spi; content:"18fe9b731f9f8034";
  ike.resp_spi; content:"a00b8ef0902bb8ec";

``ike.init_spi`` and ``ike.resp_spi`` are 'sticky buffer'.

``ike.init_spi`` and ``ike.resp_spi`` can be used as ``fast_pattern``.


ike.chosen_sa_attribute
-----------------------

Match on an attribute value of the chosen Security Association (SA) by the Responder. Supported for IKEv1 are:
``alg_enc``,
``alg_hash``,
``alg_auth``,
``alg_dh``,
``alg_prf``,
``sa_group_type``,
``sa_life_type``,
``sa_life_duration``,
``sa_key_length`` and
``sa_field_size``.
IKEv2 supports ``alg_enc``, ``alg_auth``, ``alg_prf`` and ``alg_dh``.

If there is more than one chosen SA the event ``MultipleServerProposal`` is set. The attributes of the first SA are used for this keyword.


Examples::

    ike.chosen_sa_attribute:alg_hash=2;
    ike.chosen_sa_attribute:sa_key_length=128;


ike.exchtype
------------

Match on the value of the Exchange Type.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)
* ``arg1-arg2`` (range)

Examples::

    ike.exchtype:5;
    ike.exchtype:>=2;


ike.vendor
----------

Match a vendor ID against the list of collected vendor IDs.

Examples::

    ike.vendor:4a131c81070358455c5728f20e95452f;

``ike.vendor`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.


ike.key_exchange_payload
------------------------

Match against the public key exchange payload (e.g. Diffie-Hellman) of the server or client.

Examples::

    ike.key_exchange_payload; content:"|6d026d5616c45be05e5b898411e9|"

``ike.key_exchange_payload`` is a 'sticky buffer'.

``ike.key_exchange_payload`` can be used as ``fast_pattern``.


ike.key_exchange_payload_length
-------------------------------

Match against the length of the public key exchange payload (e.g. Diffie-Hellman) of the server or client.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)
* ``arg1-arg2`` (range)

Examples::

    ike.key_exchange_payload_length:>132


ike.nonce_payload
-----------------

Match against the nonce of the server or client.

Examples::

    ike.nonce_payload; content:"|6d026d5616c45be05e5b898411e9|"

``ike.nonce_payload`` is a 'sticky buffer'.

``ike.nonce_payload`` can be used as ``fast_pattern``.


ike.nonce_payload_length
------------------------

Match against the length of the nonce of the server or client.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)
* ``arg1-arg2`` (range)

Examples::

    ike.nonce_payload_length:132
    ike.nonce_payload_length:>132


Additional information
----------------------

More information on the protocol and the data contained in it can be found here:
`<https://tools.ietf.org/html/rfc2409>`_
