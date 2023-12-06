WebSocket Keywords
==================

websocket.payload
-----------------

A sticky buffer on the unmasked payload,
limited by suricata.yaml config value ``websocket.max-payload-size``.

Examples::

  websocket.payload; pcre:"/^123[0-9]*/";
  websocket.payload content:"swordfish";

``websocket.payload`` is a 'sticky buffer' and can be used as ``fast_pattern``.

websocket.fin
-------------

A boolean to tell if the payload is complete.

Examples::

  websocket.fin:true;
  websocket.fin:false;

websocket.mask
--------------

Matches on the websocket mask if any.
It uses a 32-bit unsigned integer as value (big-endian).

Examples::

  websocket.mask:123456;
  websocket.mask:>0;

websocket.opcode
----------------

Matches on the websocket opcode.
It uses a 8-bit unsigned integer as value.
Only 16 values are relevant.
It can also be specified by text from the enumeration

Examples::

  websocket.opcode:1;
  websocket.opcode:>8;
  websocket.opcode:ping;
