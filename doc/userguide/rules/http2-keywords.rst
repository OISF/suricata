HTTP2 Keywords
==============

HTTP2 frames are grouped into transactions based on the stream identifier it it is not 0.
For frames with stream identifier 0, whose effects are global for the connection, a transaction is created for each frame.


http2.frametype
---------------

Match on the frame type present in a transaction.

Examples::

  http2.frametype:GOAWAY;


http2.errorcode
---------------

Match on the error code in a GOWAY or RST_STREAM frame

Examples::

  http2.errorcode: NO_ERROR;
  http2.errorcode: INADEQUATE_SECURITY;


http2.priority
--------------

Match on the value of the HTTP2 priority field present in a PRIORITY or HEADERS frame.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``x-y`` (range between values x and y)

Examples::

  http2.priority:2;
  http2.priority:>100;
  http2.priority:32-64;


http2.window
------------

Match on the value of the HTTP2 value field present in a WINDOWUPDATE frame.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``x-y`` (range between values x and y)

Examples::

  http2.window:1;
  http2.window:<100000;


http2.size_update
-----------------

Match on the size of the HTTP2 Dynamic Headers Table.
More information on the protocol can be found here:
`<https://tools.ietf.org/html/rfc7541#section-6.3>`_

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``x-y`` (range between values x and y)

Examples::

  http2.size_update:1234;
  http2.size_update:>4096;


http2.settings
--------------

Match on the name and value of a HTTP2 setting from a SETTINGS frame.

This keyword takes a numeric argument after a colon and supports additional qualifiers, such as:

* ``>`` (greater than)
* ``<`` (less than)
* ``x-y`` (range between values x and y)

Examples::

  http2.settings:SETTINGS_ENABLE_PUSH=0;
  http2.settings:SETTINGS_HEADER_TABLE_SIZE>4096;

http2.header_name
-----------------

Match on the name of a HTTP2 header from a HEADER frame (or PUSH_PROMISE or CONTINUATION).

Examples::

  http2.header_name; content:"agent";

``http2.header_name`` is a 'sticky buffer'.

``http2.header_name`` can be used as ``fast_pattern``.


http2.header
-----------------

Match on the name and value of a HTTP2 header from a HEADER frame (or PUSH_PROMISE or CONTINUATION).
Name and value get concatenated by ": ", colon and space.
Each colon in the name or the value should be escaped as a double colon "::" for detection

Examples::

  http2.header; content:"agent: nghttp2";
  http2.header; content:"custom-header: I love::colons";

``http2.header`` is a 'sticky buffer'.

``http2.header`` can be used as ``fast_pattern``.


Additional information
----------------------

More information on the protocol can be found here:
`<https://tools.ietf.org/html/rfc7540>`_
