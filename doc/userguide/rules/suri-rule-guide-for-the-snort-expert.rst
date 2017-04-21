====================================================
The Suricata Rule Writing Guide For The Snort Expert
====================================================

Overview
--------

Suricata is a modern and powerful IDS/IPS engine that supports the
popular Snort rule syntax.  However, there are some important
differences and capabilities between how the engines work and how rules
are applied that need to be taken into consideration when attempting to
craft the best Suricata rule(s) possible.  This guide is intended to
highlight the major differences between Snort and Suricata that the rule
writer needs to be aware of when converting Snort rules to Suricata
and/or writing Suricata rules.  The target audience for this document is
people who are very familiar with the Snort engine and rules, who want
to write superlative rules for Suricata.

Where not specified, the statements below apply to Suricata.

In general, references to Snort refer to the version 2.9 branch and
references to Suricata apply to version 3.1 and before (where noted).

Contents
--------

.. contents::

Other References
----------------

Suricata Documentation:

-  :doc:`index`
-  :doc:`../index`
-  :doc:`snort-compatibility`

Automatic Protocol Detection
----------------------------

-  Suricata does automatic protocol detection of the following
   application layer protocols:

   -  dcerpc
   -  dns
   -  http
   -  imap (detection only by default; no parsing)
   -  ftp
   -  modbus (Suricata v3 and later; disabled by default; minimalist probe parser; can lead to false positives)
   -  msn (detection only by default; no parsing)
   -  smb
   -  smb2 (disabled internally inside the engine)
   -  smtp
   -  ssh
   -  tls (SSLv2, SSLv3 & TLSv1)
   
-  In Suricata, protocol detection is port agnostic (in most cases). In
   Snort, in order for the ``http_inspect`` and other preprocessors to be
   applied to traffic, it has to be over a configured port.

   -  Some configurations for app-layer in the Suricata yaml can/do by default
      specify specific destination ports (e.g. DNS)
   -  **You can look on 'any' port without worrying about the
      performance impact that you would have to be concerned about with
      Snort.**

-  If the traffic is detected as HTTP by Suricata, the ``http_*``
   buffers are populated and can be used, regardless of port(s)
   specified in the rule.

-  You don't have to check for the http protocol (i.e.
   ``alert http ...``) to use the ``http_*`` buffers although it
   is recommended.

-  If you are trying to detect legitimate (supported) application layer
   protocol traffic and don't want to look on specific port(s), the rule
   should be written as ``alert <protocol> ...`` with ``any`` in
   place of the usual protocol port(s).  For example, when you want to
   detect HTTP traffic and don't want to limit detection to a particular
   port or list of ports, the rules should be written as
   ``alert http ...`` with ``any`` in place of
   ``$HTTP_PORTS``.
   
   -  You can also do ``app-layer-protocol:<protocol>;`` inside the rule.
   
   So, instead of this Snort rule::
     
      alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ...

   Do this for Suricata::
    
      alert http $HOME_NET -> $EXTERNAL_NET any ...

   Or::
    
      alert tcp $HOME_NET any -> $EXTERNAL_NET any (app-layer-protocol:http; ...

``content`` Keyword
-------------------

-  *Older* versions of Suricata (before 3.0) cannot have a ``content`` whose 
   length greater than 255 characters.

  -  Split up longer content matches if you are running a version of Suricata before 3.0.

-  :doc:`snort-compatibility`
-  `https://redmine.openinfosecfoundation.org/issues/1281 <https://redmine.openinfosecfoundation.org/issues/1281>`_

``flow`` Keyword
-------------------

-  Suricata does not support ``not_established`` for the ``flow`` keyword.
-  :doc:`snort-compatibility`

``urilen`` Keyword
------------------

-  Ranges given in the ``urilen`` keyword are inclusive for Snort
   but not inclusive for Suricata.

   Example: ``urilen:2<>10``

      -  Snort interprets this as, "the URI length must be **greater than
         or equal to** 2, and **less than or equal to** 10".
      -  Suricata interprets this as "the URI length must be **greater
         than** 2 and **less than** 10".

   -  There is a request to have Suricata behave like Snort in future
      versions –
      `https://redmine.openinfosecfoundation.org/issues/1416 <https://redmine.openinfosecfoundation.org/issues/1416>`_

      -  Currently on hold

-  By default, with *Suricata*, ``urilen`` applies to the
   **normalized** buffer

   -  Use ``,raw`` for raw buffer
   -  e.g. ``urilen:>20,raw;``

-  By default, with *Snort*, ``urilen`` applies to the **raw**
   buffer

   -  Use ``,norm`` for normalized buffer
   -  e.g. ``urilen:>20,norm;``

``http_uri`` Buffer
-------------------

-  In Snort, the ``http_uri`` buffer normalizes '+' characters
   (0x2B) to spaces (0x20).  Suricata does this as well **BUT**:

   - Only in Suricata version 2.0 (libhtp 0.5) or later **AND**
   - You have to set ``query-plusspace-decode: yes`` in the ``libhtp`` section of Suricata's yaml file.

-  `https://redmine.openinfosecfoundation.org/issues/1035 <https://redmine.openinfosecfoundation.org/issues/1035>`_
-  `https://github.com/inliniac/suricata/pull/620 <https://github.com/inliniac/suricata/pull/620>`_

``http_header`` Buffer
----------------------

-  In Snort, the ``http_header`` buffer includes the CRLF CRLF (0x0D
   0x0A 0x0D 0x0A) that separates the end of the last HTTP header from
   the beginning of the HTTP body.  Suricata includes a CRLF after the
   last header in the ``http_header`` buffer but not an extra one
   like Snort does.  If you want to match the end of the buffer, use
   either the ``http_raw_header`` buffer, a relative
   ``isdataat`` (e.g. ``isdataat:!1,relative``) or a PCRE
   (although PCRE will be worse on performance).

-  Suricata *will* include CRLF CRLF at the end of the ``http_raw_header``
   buffer like Snort does (this is not true for older Suricata versions
   such as 1.3.4).

-  Snort will include a *leading* CRLF in the ``http_header`` buffer of
   *server responses* (but not client requests).  Suricata does not have
   the leading CRLF in the ``http_header`` buffer of the server response
   or client request.

-  When there are duplicate HTTP headers (referring to the header name
   only, not the value), the normalized buffer (``http_header``)
   will concatenate the values in the order seen (from top to
   bottom), with a comma and space (", ") between each of them.  If this
   hinders detection, use the ``http_raw_header`` buffer instead.
   
   Example request::

        GET /test.html HTTP/1.1
        Content-Length: 44
        Accept: */*
        Content-Length: 55

   The Content-Length header line becomes this in the ``http_header`` buffer::

        Content-Length: 44, 55

-  The HTTP 'Cookie' and 'Set-Cookie' headers are **NOT** included in
   the ``http_header`` buffer; instead they are extracted and put into
   their own buffer – ``http_cookie``. See the `http_cookie Buffer`_ 
   section.

-  The HTTP 'Cookie' and 'Set-Cookie' headers **ARE** included in the
   ``http_raw_header`` buffer so if you are trying to match on
   something like particular header ordering involving (or not
   involving) the HTTP Cookie headers, use the ``http_raw_header``
   buffer.

-  If 'enable\_cookie' is set for Snort, the HTTP Cookie header names
   and trailing CRLF (i.e. "Cookie: \\r\\n" and "Set-Cooke \\r\\n") are
   kept in the ``http_header`` buffer.  This is not the case for
   Suricata which removes the entire "Cookie" or "Set-Cookie" line from
   the ``http_header`` buffer.

-  Other HTTP headers that have their own buffer
   (``http_user_agent``, ``http_host``) are not removed from the
   ``http_header`` buffer like the Cookie headers are.

-  When inspecting server responses and ``file_data`` is used,
   content matches in ``http_*`` buffers should come before
   ``file_data`` unless you use ``pkt_data`` to reset the cursor
   before matching in ``http_*`` buffers.  Snort will not complain if
   you use ``http_*`` buffers after ``file_data`` is set.

``http_cookie`` Buffer
----------------------

-  The ``http_cookie`` buffer will NOT include the header name,
   colon, or leading whitespace.  i.e. it will not include "Cookie: " or "Set-Cookie: ".

-  The ``http_cookie`` buffer does not include a CRLF (0x0D 0x0A) at
   the end.  If you want to match the end of the buffer, use a relative
   ``isdataat`` or a PCRE (although PCRE will be worse on
   performance).

-  There is no ``http_raw_cookie`` buffer in Suricata.  Use
   ``http_raw_header`` instead.

-  You do not have to configure anything special to use the
   'http\_cookie' buffer in Suricata.  This is different from Snort
   where you have to set ``enable_cookie`` in the
   ``http_inspect_server`` preprocessor config in order to have the
   ``http_cookie`` buffer treated separate from the
   ``http_header`` buffer.

-  If Snort has 'enable\_cookie' set and multiple "Cookie" or
   "Set-Cookie" headers are seen, it will concatenate them together
   (with no separator between them) in the order seen from top to
   bottom.
   
-  If a request contains multiple "Cookie" or "Set-Cookie" headers, the
   values will be concatenated in the Suricata ``http_cookie``
   buffer, in the order seen from top to bottom, with a comma and space
   (", ") between each of them.

   Example request::

        GET /test.html HTTP/1.1
        Cookie: monster
        Accept: */*
        Cookie: elmo

   Suricata ``http_cookie`` buffer contents::

        monster, elmo
        
   Snort ``http_cookie`` buffer contents::

        monsterelmo

-  Corresponding PCRE modifier: ``C`` (same as Snort)

``http_user_agent`` Buffer
--------------------------

-  Suricata has a ``http_user_agent`` buffer, Snort does not.

-  Support added in Suricata version 1.3.

-  The ``http_user_agent`` buffer will NOT include the header name,
   colon, or leading whitespace.  i.e. it will not include
   "User-Agent: ".

-  The ``http_user_agent`` buffer does not include a CRLF (0x0D
   0x0A) at the end.  If you want to match the end of the buffer, use a
   relative ``isdataat`` or a PCRE (although PCRE will be worse on
   performance).

-  If a request contains multiple "User-Agent" headers, the values will
   be concatenated in the ``http_user_agent`` buffer, in the order
   seen from top to bottom, with a comma and space (", ") between each
   of them.

   Example request::

          GET /test.html HTTP/1.1 
          User-Agent: SuriTester/0.8 
          User-Agent: GGGG

   ``http_user_agent`` buffer contents::
   
          SuriTester/0.8, GGGG

-  Corresponding PCRE modifier: ``V``

-  Using the ``http_user_agent`` buffer is more efficient when it
   comes to performance than using the ``http_header`` buffer (~10%
   better).

-  `http://blog.inliniac.net/2012/07/09/suricata-http\_user\_agent-vs-http\_header/ <http://blog.inliniac.net/2012/07/09/suricata-http_user_agent-vs-http_header/>`_

``http_host`` and ``http_raw_host`` Buffers
-------------------------------------------

-  Suricata has ``http_host`` and ``http_raw_host`` buffers,
   Snort does not.
   
-  Support added in Suricata version 1.4.1.

-  The ``http_host`` and ``http_raw_host`` buffers are populated
   from either the URI (if the full URI is present in the request like
   in a proxy request) or the HTTP Host header. If both are present, the
   URI is used.
   
-  The ``http_host`` and ``http_raw_host`` buffers will NOT
   include the header name, colon, or leading whitespace if populated
   from the Host header.  i.e. they will not include "Host: ".
-  The ``http_host`` and ``http_raw_host`` buffers do not
   include a CRLF (0x0D 0x0A) at the end.  If you want to match the end
   of the buffer, use a relative 'isdataat' or a PCRE (although PCRE
   will be worse on performance).
   
-  The ``http_host`` buffer is normalized to be all lower case.

-  The content match that ``http_host`` applies to must be all lower
   case or have the ``nocase`` flag set.
   
-  ``http_raw_host`` matches the unnormalized buffer so matching
   will be case-sensitive (unless ``nocase`` is set).
   
-  If a request contains multiple "Host" headers, the values will be
   concatenated in the ``http_host`` and ``http_raw_host``
   buffers, in the order seen from top to bottom, with a comma and space
   (", ") between each of them.

   Example request::

          GET /test.html HTTP/1.1 
          Host: ABC.com 
          Accept: */* 
          Host: efg.net

   ``http_host`` buffer contents::

          abc.com, efg.net

   ``http_raw_host`` buffer contents::

          ABC.com, efg.net

-  Corresponding PCRE modifier (``http_host``): ``W``
-  Corresponding PCRE modifier (``http_raw_host``): ``Z``

``http_server_body`` Buffer
---------------------------

-  Suricata has the ``http_server_body`` buffer, Snort does not.

-  Support added in Suricata version 1.2.

-  This tells Suricata to match in the HTTP server response body.

-  Using ``http_server_body`` is similar to having content matches
   that come after ``file_data`` except that it doesn't permanently
   (unless reset) set the detection pointer to the beginning of the
   server response body. i.e. it is not a sticky buffer.

-  ``http_server_body`` will match on gzip decoded data just like
   ``file_data`` does.

-  Since ``http_server_body`` matches on a server response, it
   can't be used with the ``to_server`` or ``from_client`` flow
   directives.

-  Corresponding PCRE modifier: ``Q``

``byte_extract`` Keyword
------------------------

-  Older versions of Suricata (e.g. version 1.3.4) do not support
   ``byte_extract`` from ``http_*`` buffers.

-  Later versions of Suricata (tested on version 2.07) do support
   ``byte_extract`` from ``http_*`` buffers, including
   ``http_header`` which does not always work as expected in Snort.

-  In Suricata, variables extracted using ``byte_extract`` must be used
   in the same buffer, otherwise they will have the value "0" (zero). 
   Snort does allow cross-buffer byte extraction and usage.

-  Be sure to always positively and negatively test Suricata rules that
   use ``byte_extract`` and ``byte_test`` to verify that they
   work as expected.

-  Support added in Suricata 1.4.

``isdataat`` Keyword
--------------------

-  The ``rawbytes`` keyword is supported in the Suricata syntax but
   doesn't actually do anything.

-  Absolute ``isdataat`` checks will succeed if the offset used is
   **less than** the size of the inspection buffer.  This is true for
   Suricata and Snort.

-  For *relative* ``isdataat`` checks, there is a **1 byte difference**
   in the way Snort and Suricata do the comparisons.

   -  Suricata will succeed if the relative offset is **less than or
      equal to** the size of the inspection buffer. This is different
      from absolute ``isdataat`` checks.
   -  Snort will succeed if the relative offset is **less than** the
      size of the inspection buffer, just like absolute ``isdataat``
      checks.
   -  Example - to check that there is no data in the inspection buffer
      after the last content match:

      -  Snort:        ``isdataat:!0,relative;``
      -  Suricata:     ``isdataat:!1,relative;``

-  With Snort, the "inspection buffer" used when checking an
   ``isdataat`` keyword is generally the packet/segment with some
   exceptions:

   -  With PAF enabled the PDU is examined instead of the
      packet/segment.  When ``file_data`` or ``base64_data`` has
      been set, it is those buffers (unless ``rawbytes`` is set).
   -  With some preprocessors - modbus, gtp, sip, dce2, and dnp3 - the
      buffer can be particular portions of those protocols (unless
      ``rawbytes`` is set).
   -  With some preprocessors - rpc\_decode, ftp\_telnet, smtp, and dnp3
      - the buffer can be particular *decoded* portions of those
      protocols (unless ``rawbytes`` is set).

-  With Suricata, the "inspection buffer" used when checking an absolute
   ``isdataat`` keyword is the packet/segment if looking at a packet
   (e.g. ``alert tcp-pkt...``) or the reassembled stream segments.

-  In Suricata, a *relative* ``isdataat`` keyword **will apply to the
   buffer of the previous content match**.  So if the previous content
   match is a ``http_*`` buffer, the relative ``isdataat``
   applies to that buffer, starting from the end of the previous content
   match in that buffer.  *Snort does not behave like this!*

-  For example, this Suricata rule looks for the string ".exe" at the
   end of the URI; to do the same thing in the normalized URI buffer in
   Snort you would have to use a PCRE – ``pcre:"/\x2Eexe$/U";``

   ::

       alert http $HOME_NET any -> $EXTERNAL_NET any (msg:".EXE File Download Request"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; isdataat:!1,relative; priority:3; sid:18332111;)

-  If you are unclear about behavior in a particular instance, you are
   encouraged to positively and negatively test your rules that use an
   ``isdataat`` keyword.

Relative PCRE
-------------

-  You can do relative PCRE matches in normalized/special buffers with Suricata.  Example::

     content:".php?sign="; http_uri; pcre:"/^[a-zA-Z0-9]{8}$/UR";
     
-  With Snort you can't combine the “relative” PCRE option ('R') with other buffer options like normalized URI ('U') – you get a syntax error.

``tls.*`` Keywords
------------------

In addition to TLS protocol identification, Suricata supports matching
on certain TLS/SSL certificate fields including the following:

-  ``tls.version`` - negotiated TLS/SSL version.

   -  Example: ``tls.version:"1.0";``
   -  Can't negate (e.g. ``tls.version:!"1.0";`` is not valid)
   -  Support added in Suricata version 1.3.

-  ``tls.subject`` - TLS/SSL certificate Subject field.

   -  Example: ``tls.subject:"CN=*.googleusercontent.com";``
   -  Support added in Suricata version 1.3.
   -  Case sensitve, can't use 'nocase'.

-  ``tls.issuerdn`` - TLS/SSL certificate IssuerDN field.

   -  Example: ``tls.issuerdn:!"CN=Google-Internet-Authority";``
   -  Support added in Suricata version 1.3.
   -  Case sensitve, can't use 'nocase'.

-  ``tls.fingerprint`` - TLS/SSL certificate SHA1 fingerprint.

   -  Example: ``tls.fingerprint:!"f3:40:21:48:70:2c:31:bc:b5:aa:22:ad:63:d6:bc:2e:b3:46:e2:5a"``
   -  Support added in Suricata version 1.4.
   -  Case sensitive, can't use 'nocase'.
   -  The ``tls.fingerprint`` buffer is lower case so you must use lower
      case letters for this to match.

-  ``tls.store`` - tells Suricata to store the TLS/SSL certificate on disk.

   -  Example: ``tls.store;``
   -  Support added in Suricata version 1.4.

-  :doc:`tls-keywords`


``tls_sni`` Keyword
-------------------

-  Sets the detection pointer to the TLS Sever Name Indication ("SNI")
   buffer.
   
-  Works like ``file_data`` does ("sticky buffer") but for SNI.

-  Use ``pkt_data`` to reset the detection pointer to the beginning of
   the packet payload.
   
-  Can use ``fast_pattern`` for content matches that apply to the
   ``tls_sni`` buffer.
   
  -  But will error on Suricata version 3.1.x if 'fast_pattern' is explicitly set.
  -  https://redmine.openinfosecfoundation.org/issues/1936

-  Support added in Suricata 3.1.

``dns_query`` Keyword
---------------------

-  Sets the detection pointer to the DNS query.

-  Works like ``file_data`` does ("sticky buffer") but for DNS
   request query.

-  Use ``pkt_data`` to reset the detection pointer to the beginning of
   the packet payload.

-  **Buffer is normalized!**

   -  Contains literal domain name

      -  <length> values are literal '.' characters
      -  no leading <length> value
      -  No terminating NULL (0x00) byte (use negated ``isdataat``
         to match the end)

      Example DNS request for "mail.google.com" (for readability, hex
      values are encoded between pipes):

      DNS query on the wire (snippet)::
      
             |04|mail|06|google|03|com|00|
             
      ``dns_query`` buffer::
      
             mail.google.com

-  Support added in Suricata 2.0.

-  :doc:`dns-keywords`

``geoip`` Keyword
-----------------

-  Suricata has the ``geoip`` keyword, Snort does not.

-  Support added in Suricata  version 1.4.1.
-  Only supports IPv4
-  Uses GeoIP API of Maxmind

  -  libgeoip
  -  Must be compiled in.

-  See :doc:`header-keywords`, "Geoip" section

IP Reputation and ``iprep`` Keyword
-----------------------------------

-  Snort has the "reputation" preprocessor that can be used to define
   whitelist and blacklist files of IPs which are used generate GID 136
   alerts as well as block/drop/pass traffic from listed IPs depending
   on how it is configured.

-  Suricata also has the concept of files with IPs in them but provides
   the ability to assign them:
   
   -  Categories
   -  Reputation score

-  Suricata rules can leverage these IP lists with the ``iprep``
   keyword that can be configured to match on:
   
   -  Direction
   -  Category
   -  Value (reputation score)

-  Added in Suricata version 1.4.

-  :doc:`../reputation/index`
-  :doc:`../reputation/ipreputation/ip-reputation-config`
-  :doc:`../reputation/ipreputation/ip-reputation-rules`
-  :doc:`../reputation/ipreputation/ip-reputation-format`
-  `http://blog.inliniac.net/2012/11/21/ip-reputation-in-suricata/ <http://blog.inliniac.net/2012/11/21/ip-reputation-in-suricata/>`_

``xbits``
---------

-  Suricata supports ``xbits`` which are like ``flowbits`` but
   can apply to disparate streams – "global flowbits"
-  Can track by ``ip_src``, ``ip_dst``, or ``ip_pair``

   -  No difference between using ``hostbits`` and ``xbits``
      with ``track ip_<src|dst>``

   -  If you ``set`` on a client request and use
      ``track ip_dst``, if you want to match on the server response,
      you check it (``isset``) with ``track ip_src``.

   -  ``track ip_pair`` has to have the same src and dst IPs on the
      setter and checker

-  To not alert, use ``flowbits:noalert;``  -- 
   there is no such thing as ``xbits:noalert;``

-  Support added in Suricata version 3.0

-  See also:

   -  `https://blog.inliniac.net/2014/12/21/crossing-the-streams-in-suricata/ <https://blog.inliniac.net/2014/12/21/crossing-the-streams-in-suricata/>`_
   -  `http://www.cipherdyne.org/blog/2013/07/crossing-the-streams-in-ids-signature-languages.html <http://www.cipherdyne.org/blog/2013/07/crossing-the-streams-in-ids-signature-languages.html>`_

Flowbits
--------

-  Suricata fully supports the setting and checking of flowbits
   (including the same flowbit) on the same packet/stream.  Snort does
   not always allow for this.

-  In Suricata, ``flowbits:isset`` is checked after the fast pattern
   match but before other ``content`` matches. In Snort,
   ``flowbits:isset`` is checked in the order they appear in the
   rule, from left to right.

-  If there is a chain of flowbits where multiple rules set flowbits and
   they are dependent on each other, then the order of the rules or the
   ``sid`` values (depending on Suricata version) can make a
   difference in the rules being evaluated in the proper order and
   generating alerts as expected.  See bug 1399 -
   `https://redmine.openinfosecfoundation.org/issues/1399 <https://redmine.openinfosecfoundation.org/issues/1399>`_.

-  Leading whitespace in flowbits variable names matters in older
   version of Suricata.  If you set a
   flowbit like this: ``flowbits:set, jpg.cats;``, the check has to
   include the leading whitespace for it to work:
   ``flowbits:isset, jpg.cats;``.  Checking it like this will NOT
   work in Suricata but will in Snort since Snort ignores leading
   whitespace in the name of flowbits variables:
   ``flowbits:isset,jpg.cats;``.  Trailing whitespace in variable
   names is ignored in Suricata and Snort.  See also
   `https://redmine.openinfosecfoundation.org/issues/1481 <https://redmine.openinfosecfoundation.org/issues/1481>`_.

   -  Fixed in Suricata 3.0RC1 (2015-11-25)

-  :doc:`flow-keywords`

Negated Content Match Special Case
----------------------------------

-  For Snort, a *negated* content match where the starting point for
   searching is at or beyond the end of the inspection buffer will never
   return true.
   
   -  For negated matches, you want it to return true if the content is
      not found.
   -  This is believed to be a Snort bug rather than an engine difference
      but it was reported to Sourcefire and acknowledged many years ago
      indicating that perhaps it is by design.
   -  This is not the case for Suricata which behaves as
      expected.

     Example HTTP request::

       POST /test.php HTTP/1.1
       Content-Length: 9

       user=suri

     This rule snippet will never return true in Snort but will in
     Suricata::

       content:!"snort"; offset:10; http_client_body;

File Extraction
---------------

-  Suricata has the ability to match on files from HTTP streams and log
   them to disk. Snort does not.
   
-  Added in Suricata version 1.2.

-  Files can be matched on using these keywords:

   -  ``filename`` - matches against the full filename
   -  ``fileext`` - matches against the file extension
   -  ``filemagic`` - matches against the magic output of the file
   -  ``filesize`` - matches against the file size

-  The ``filestore`` keyword tells Suricata to save the file to
   disk.
   
-  Extracted files are logged to disk with meta data that includes
   things like timestamp, src/dst IP, protocol, src/dst port, HTTP URI,
   HTTP Host, HTTP Referer, filename, file magic, md5sum, size, etc.

-  There are a number of configuration options and considerations (such
   as stream reassembly depth and libhtp body-limit) that should be
   understood if you want fully utilize file extraction in Suricata.

-  SMTP file extraction available in Suricata version 3.0.

-  :doc:`file-keywords`
-  :doc:`../file-extraction/file-extraction`
-  `http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/ <http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/>`_
-  `http://blog.inliniac.net/2014/11/11/smtp-file-extraction-in-suricata/ <http://blog.inliniac.net/2014/11/11/smtp-file-extraction-in-suricata/>`_

Lua Scripting
-------------

-  Suricata has the ``luajit`` keyword allows for a rule to reference a Lua 
   script that can access the packet, payload, HTTP buffers, etc.
-  Provides powerful flexability and capabilities that Snort does
   not have.
-  Added in Suricata version 1.4.
-  :doc:`rule-lua-scripting`

Fast Pattern
------------

-  Snort's fast pattern matcher is always case insensitive; Suricata's
   is case sensitive unless 'nocase' is set on the content match used by
   the fast pattern matcher.

-  Snort will truncate fast pattern matches based on the
   ``max-pattern-len`` config (default no limit) unless
   ``fast_pattern:only`` is used in the rule. Suricata does not do any
   automatic fast pattern truncation cannot be configured to do so.

-  Just like in Snort, in Suricata you can specify a substring of the
   content string to be use as the fast pattern match. e.g.
   ``fast_pattern:5,20;``

-  In Snort, leading NULL bytes (0x00) will be removed from content
   matches when determining/using the longest content match unless
   ``fast_pattern`` is explicitly set. Suricata does not truncate
   anything, including NULL bytes.

-  Snort does not allow for all ``http_*`` buffers to be used for
   the fast pattern match (e.g. ``http_raw_*``, ``http_method``,
   ``http_cookie``, etc.).  Suricata lets you use any 'http\_\*'
   buffer you want for the fast pattern match, including
   ``http_raw_*' and ``http_cookie`` buffers.

-  Suricata supports the ``fast_pattern:only`` syntax but
   technically it is not really implemented; the ``only`` is
   silently ignored when encountered in a rule.  It is still recommended
   that you use ``fast_pattern:only`` where appropriate in case this
   gets implemented in the future and/or if the rule will be used by
   Snort as well.

-  With Snort, unless ``fast_pattern`` is explicitly set, content
   matches in normalized HTTP Inspect buffers (e.g. http content
   modifiers such ``http_uri``, ``http_header``, etc.) take
   precedence over non-HTTP Inspect content matches, even if they are
   shorter.  Suricata does the same thing and gives a higher 'priority'
   (precedence) to ``http_*`` buffers (except for ``http_method``,
   ``http_stat_code``, and ``http_stat_msg``\ ``)``. This is for
   Suricata 2.0 and later; previous versions don't prioritize buffers,
   they just use the longest content match, followed by character
   diversity score.

-  See :doc:`fast-pattern-explained` for full details on how Suricata
   versions 2.0.x and later automatically determine which content to 
   use as the fast pattern match.

-  When in doubt about what is going to be use as the fast pattern match
   by Suricata, set ``fast_pattern`` explicitly in the rule and/or
   run Suricata with the ``--engine-analysis`` switch and view the
   generated file (``rules_fast_pattern.txt``).

-  Like Snort, the fast pattern match is checked before ``flowbits``
   in Suricata.
   
-  :doc:`fast-pattern`

Don't Cross The Streams
-----------------------

Suricata will examine network traffic as individual packets and, in the
case of TCP, as part of a (reassembled) stream.  However, there are
certain rule keywords that only apply to packets only (``dsize``,
``flags``, ``ttl``) and certain ones that only apply to streams
only (``http_*``) and you can't mix packet and stream keywords. 
Rules that use packet keywords will inspect individual packets only and
rules that use stream keywords will inspect streams only.  Snort is a
little more forgiving when you mix these – for example, in Snort you can
use ``dsize`` (a packet keyword) with ``http_*`` (stream
keywords) and Snort will allow it although because of ``dsize`` it
will only apply detection to individual packets (unless PAF is enabled
then it will apply it to the PDU).

If ``dsize`` is in a rule that also looks for a stream-based
application layer protocol (e.g. ``http``), Suricata will not match on
the *first application layer packet* since ``dsize`` make Suricata
evaluate the packet and protocol detection doesn't happen until after
the protocol is checked for that packet; *subsequent* packets in that
flow should have the application protocol set appropriately and will
match rules using ``dsize`` and a stream-based application layer
protocol.

If you need to check sizes on a stream in a rule that uses a stream
keyword, or in a rule looking for a stream-based application layer
protocol, consider using the ``stream_size`` keyword and/or
``isdataat``.

Suricata also supports these protocol values being used in rules and
Snort does not:

-  ``tcp-pkt`` – example:

   -  ``alert tcp-pkt ...``
   -  This tells Suricata to only apply the rule to TCP packets and not
      the (reassembled) stream.

-  ``tcp-stream`` – example:

   -  ``alert tcp-stream ...``
   -  This tells Suricata to inspect the (reassembled) TCP stream only.

Alerts
------

-  In Snort, the number of alerts generated for a packet/stream can be
   limited by the ``event_queue`` configuration.

-  Suricata does not limit the number of alerts per packet/stream (and
   this cannot be configured); all rules that match on the traffic being
   analyzed will fire.

-  Sometimes Suricata will generate what appears to be two alerts for
   the same TCP packet.  This happens when Suricata evaluates the packet
   by itself and as part of a (reassembled) stream.

Buffer Reference Chart
----------------------

+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| Buffer                | Snort 2.9.x                              | Suricata                                  | PCRE   | Can be used as | Suricata 2.0+    |
|                       | Support?                                 | Support?                                  | flag   | Fast Pattern?  | Fast Pattern     |
|                       |                                          |                                           |        |                | Priority (lower  |
|                       |                                          |                                           |        |                | number is        |
|                       |                                          |                                           |        |                | higher priority) |
+=======================+==========================================+===========================================+========+================+==================+
| content (no modifier) | YES                                      | YES                                       | <none> | YES            | 3                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_method           | YES                                      | YES                                       | M      | Suricata only  | 3                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_stat_code        | YES                                      | YES                                       | S      | Suricata only  | 3                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_stat_msg         | YES                                      | YES                                       | Y      | Suricata only  | 3                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| uricontent            | YES but deprecated, use http_uri instead | YES but deprecated, use http_uri instead  | U      | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_uri              | YES                                      | YES                                       | U      | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_raw_uri          | YES                                      | YES                                       | I      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_header           | YES                                      | YES                                       | H      | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_raw_header       | YES                                      | YES                                       | D      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_cookie           | YES                                      | YES                                       | C      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_raw_cookie       | YES                                      | NO (use http_raw_header instead)          | K      | NO             | n/a              |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_host             | NO                                       | YES (version 1.4.1 and later)             | W      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_raw_host         | NO                                       | YES (version 1.4.1 and later)             | Z      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_client_body      | YES                                      | YES                                       | P      | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_server_body      | NO                                       | YES (version 1.2 and later)               | Q      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_user_agent       | NO                                       | YES (version 1.3 and later)               | V      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| dns_query             | NO                                       | YES (version 2.0 and later)               | <none> | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| tls_sni               | NO                                       | YES (version 3.1 and later)               | <none> | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+

