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

websocket.flags
---------------

Matches on the websocket flags.
It uses a 8-bit unsigned integer as value.
Only the four upper bits are used.

The value can also be a list of strings (comma-separated),
where each string is the name of a specific bit like `fin` and `comp`,
and can be prefixed by `!` for negation.

websocket.flags uses an :ref:`unsigned 8-bits integer <rules-integer-keywords>`

Examples::

  websocket.flags:128;
  websocket.flags:&0x40=0x40;
  websocket.flags:fin,!comp;

websocket.mask
--------------

Matches on the websocket mask if any.
It uses a 32-bit unsigned integer as value (big-endian).

websocket.mask uses an :ref:`unsigned 32-bits integer <rules-integer-keywords>`

Examples::

  websocket.mask:123456;
  websocket.mask:>0;

websocket.opcode
----------------

Matches on the websocket opcode.
It uses a 8-bit unsigned integer as value.
Only 16 values are relevant.
It can also be specified by text from the enumeration

websocket.opcode uses an :ref:`unsigned 8-bits integer <rules-integer-keywords>`

Examples::

  websocket.opcode:1;
  websocket.opcode:>8;
  websocket.opcode:ping;
