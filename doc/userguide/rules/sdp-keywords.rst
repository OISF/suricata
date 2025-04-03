SDP Keywords
============

The SDP keywords are implemented as sticky buffers and can be used to match on fields in SDP messages.

======================================== ==================
Keyword                                  Direction
======================================== ==================
sdp.origin                               Both
sdp.session_name                         Both
sdp.session_info                         Both
sdp.uri                                  Both
sdp.email                                Both
sdp.connection_data                      Both
sdp.bandwidth                            Both
sdp.time                                 Both
sdp.repeat_time                          Both
sdp.timezone                             Both
sdp.encryption_key                       Both
sdp.attribute                            Both
sdp.media.media                          Both
sdp.media.session_info                   Both
sdp.media.connection_data                Both
sdp.media.encryption_key                 Both
======================================== ==================

sdp.origin
----------

This keyword matches on the originator found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.origin; content:<origin>;

Where <origin> is an originator that follows the SDP Origin (o=) scheme.

Examples
~~~~~~~~

::

  sdp.origin; content:"SIPPS 105015165 105015162 IN IP4 192.168.1.2";

sdp.session_name
----------------

This keyword matches on the session name found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.session_name; content:<session_name>;

Where <session_name> is a name that follows the SDP Session name (s=) scheme.

Examples
~~~~~~~~

::

  sdp.session_name; content:"SIP call";

sdp.session_info
----------------

This keyword matches on the session information found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.session_info; content:<session_info>;

Where <session_info> is a description that follows the SDP Session information (i=) scheme.

Examples
~~~~~~~~

::

  sdp.session_info; content:"Session Description Protocol";

sdp.uri
-------

This keyword matches on the URI found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.uri; content:<uri>;

Where <uri> is a URI (u=) that the follows the SDP scheme.

Examples
~~~~~~~~

::

  sdp.uri; content:"https://www.sdp.proto"

sdp.email
---------

This keyword matches on the email found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.email; content:<email>

Where <email> is an email address (e=) that follows the SDP scheme.

Examples
~~~~~~~~

::

  sdp.email; content:"j.doe@example.com (Jane Doe)";

sdp.phone_number
----------------

This keyword matches on the phone number found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.phone_number; content:<phone_number>

Where <phone_number> is a phone number (p=) that follows the SDP scheme.

Examples
~~~~~~~~

::

  sdp.phone_number; content:"+1 617 555-6011 (Jane Doe)";

sdp.connection_data
-------------------

This keyword matches on the connection found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.connection_data; content:<connection_data>;

Where <connection_data> is a connection (c=) that follows the SDP scheme.

Examples
~~~~~~~~

::

  sdp.connection_data; content:"IN IP4 192.168.1.2"

sdp.bandwidth
-------------

This keyword matches on the bandwidths found in an SDP request or response. 

Syntax
~~~~~~

::

  sdp.bandwidth; content:<bandwidth>

Where <bandwidth> is a bandwidth (b=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.bandwidth; content:"AS:64"

sdp.time
--------

This keyword matches on the time found in an SDP request or response. 

Syntax
~~~~~~

::

  sdp.time; content:<time>

Where <time> is a time (t=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.time; content:"3034423619 3042462419"

sdp.repeat_time
---------------

This keyword matches on the repeat time found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.repeat_time; content:<repeat_time>

Where <repeat_time> is a repeat time (r=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.repeat_time; content:"604800 3600 0 90000"

sdp.timezone
------------

This keyword matches on the timezone found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.timezone; content:<timezone>

Where <timezone> is a timezone (z=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.timezone; content:"2882844526 -1h 2898848070 0"

sdp.encryption_key
------------------

This keyword matches on the encryption key found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.encryption_key; content:<encryption_key>

Where <encryption_key> is a key (k=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.encryption_key; content:"prompt"

sdp.attribute
----------------

This keyword matches on the attributes found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.attribute; content:<attribute>

Where <attribute> is an attribute (a=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.attribute; content:"sendrecv"

sdp.media.media
---------------

This keyword matches on the Media subfield of a Media description field found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.media.media; content:<media>

Where <media> is a media (m=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.media.media; content:"audio 30000 RTP/AVP 0 8 97 2 3"

sdp.media.session_info
----------------------

This keyword matches on the Session information subfield of a Media description field found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.media.session_info; content:<session_info>

Where <session_info> is a description (i=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.media.session_info; content:"Session Description Protocol"

sdp.media.connection_data
-------------------------

This keyword matches on the Connection data subfield of a Media description field found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.media.connection_data; content:<connection_data>

Where <connection_data> is a connection (c=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.media.connection_data; content:"IN IP4 192.168.1.2"

sdp.media.encryption_key
------------------------

This keyword matches on the Encryption key subfield of a Media description field found in an SDP request or response.

Syntax
~~~~~~

::

  sdp.media.encryption_key; content:<encryption_key>

Where <encryption_key> is a key (k=) that follows the SDP scheme.

Example
~~~~~~~

::

  sdp.media.encryption_key; content:"prompt"
