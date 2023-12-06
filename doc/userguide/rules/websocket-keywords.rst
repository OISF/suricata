WebSocket Keywords
==================

websocket.mask
--------------

A boolean to tell if the payload is masked.

Examples::

  websocket.mask:true;
  websocket.mask:false;

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
