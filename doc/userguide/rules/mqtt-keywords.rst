MQTT Keywords
=============

Various keywords can be used for matching on fields in fixed and variable headers of MQTT messages as well as payload values.

mqtt.protocol_version
---------------------

Match on the value of the MQTT protocol version field in the fixed header.

The format of the keyword::

  mqtt.protocol_version:<min>-<max>;
  mqtt.protocol_version:[<|>]<number>;
  mqtt.protocol_version:<value>;

Examples:

  mqtt.protocol_version:5;


mqtt.type
---------

Match on the MQTT message type (also: control packet type).
Valid values are :

* ``CONNECT``
* ``CONNACK``
* ``PUBLISH``
* ``PUBACK``
* ``PUBREC``
* ``PUBREL``
* ``PUBCOMP``
* ``SUBSCRIBE``
* ``SUBACK``
* ``UNSUBSCRIBE``
* ``UNSUBACK``
* ``PINGREQ``
* ``PINGRESP``
* ``DISCONNECT``
* ``AUTH``
* ``UNASSIGNED``

where ``UNASSIGNED`` refers to message type code 0.

Examples::

  mqtt.type:CONNECT;
  mqtt.type:PUBLISH;


mqtt.flags
----------

Match on a combination of MQTT header flags, separated by commas (``,``). Flags may be prefixed by ``!`` to indicate negation, i.e. a flag prefixed by ``!`` must `not` be set to match.

Valid flags are:

* ``dup`` (duplicate message)
* ``retain`` (message should be retained on the broker)

Examples::

  mqtt.flags:dup,!retain;
  mqtt.flags:retain;


mqtt.qos
--------

Match on the Quality of Service request code in the MQTT fixed header.
Valid values are:

* ``0`` (fire and forget)
* ``1`` (at least one delivery)
* ``2`` (exactly one delivery)

Examples::

  mqtt.qos:0;
  mqtt.qos:2;


mqtt.reason_code
----------------

Match on the numeric value of the reason code that is used in MQTT 5.0 for some message types. Please refer to the specification for the meaning of these values, which are often specific to the message type in question.

Examples::

  # match on attempts to unsubscribe from a non-subscribed topic
  mqtt.type:UNSUBACK; mqtt.reason_code:17;

  # match on publications that were accepted but there were no subscribers
  mqtt.type:PUBACK; mqtt.reason_code:16;

  # match on connection attempts by banned clients
  mqtt.CONNACK; mqtt.reason_code:138;

  # match on failed connection attempts due to bad credentials
  mqtt.CONNACK; mqtt.reason_code:134;

  # match on connections terminated by server shutdowns
  mqtt.DISCONNECT; mqtt.reason_code:139;

This keyword is also available under the alias ``mqtt.connack.return_code`` for completeness.


mqtt.connack.session_present
----------------------------

Match on the MQTT CONNACK ``session_present`` flag. Values can be ``yes``, ``true``, ``no`` or ``false``.

Examples::

  mqtt.CONNACK; mqtt.connack.session_present:true;


mqtt.connect.clientid
---------------------

Match on the self-assigned client ID in the MQTT CONNECT message.

Examples::

  mqtt.connect.clientid; pcre:"/^mosq.*/";
  mqtt.connect.clientid; content:"myclient";

``mqtt.connect.clientid`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.connect.flags
------------------

Match on a combination of MQTT CONNECT flags, separated by commas (``,``). Flags may be prefixed by ``!`` to indicate negation, i.e. a flag prefixed by ``!`` must `not` be set to match.

Valid flags are:

* ``username`` (message contains a username)
* ``password`` (message contains a password)
* ``will`` (message contains a will definition)
* ``will_retain`` (will should be retained on broker)
* ``clean_session`` (start with a clean session)

Examples::

  mqtt.connect.flags:username,password,!will;
  mqtt.connect.flags:username,!password;
  mqtt.connect.flags:clean_session;


mqtt.connect.password
---------------------

Match on the password credential in the MQTT CONNECT message.

Examples::

  mqtt.connect.password; pcre:"/^123[0-9]*/";
  mqtt.connect.password; content:"swordfish";

``mqtt.connect.password`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.connect.username
---------------------

Match on the username credential in the MQTT CONNECT message.

Examples::

  mqtt.connect.username; content:"benson";

``mqtt.connect.username`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.connect.willmessage
------------------------

Match on the will message in the MQTT CONNECT message, if a will is defined.

Examples::

  mqtt.connect.willmessage; pcre:"/^fooba[rz]/";
  mqtt.connect.willmessage; content:"hunter2";

``mqtt.connect.willmessage`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.connect.willtopic
----------------------

Match on the will topic in the MQTT CONNECT message, if a will is defined.

Examples::

  mqtt.connect.willtopic; pcre:"/^hunter[0-9]/";

``mqtt.connect.willtopic`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.publish.message
--------------------

Match on the payload to be published in the MQTT PUBLISH message.

Examples::

  mqtt.type:PUBLISH; mqtt.publish.message; pcre:"/uid=[0-9]+/";
  # match on published JPEG images
  mqtt.type:PUBLISH; mqtt.publish.message; content:"|FF D8 FF E0|"; startswith;

``mqtt.publish.message`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.publish.topic
------------------

Match on the topic to be published to in the MQTT PUBLISH message.

Examples::

  mqtt.publish.topic; content:"mytopic";

``mqtt.publish.topic`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.subscribe.topic
--------------------

Match on any of the topics subscribed to in a MQTT SUBSCRIBE message.

Examples::

  mqtt.subscribe.topic; content:"mytopic";

``mqtt.subscribe.topic`` is a 'sticky buffer' and can be used as ``fast_pattern``.


mqtt.unsubscribe.topic
----------------------

Match on any of the topics unsubscribed from in a MQTT UNSUBSCRIBE message.

Examples::

  mqtt.unsubscribe.topic; content:"mytopic";

``mqtt.unsubscribe.topic`` is a 'sticky buffer' and can be used as ``fast_pattern``.


Additional information
----------------------

More information on the protocol can be found here:

* MQTT 3.1: `<https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html>`_
* MQTT 3.1.1: `<https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>`_
* MQTT 5.0: `<https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html>`_
