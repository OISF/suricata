======================
Differences From Snort
======================

Overview
--------
This document is intended to highlight the major differences between Suricata
and Snort that apply to rules and rule writing.

Where not specified, the statements below apply to Suricata.  In general,
references to Snort refer to the version 2.9 branch.

Contents
--------

.. contents::

Automatic Protocol Detection
----------------------------

-  Suricata does automatic protocol detection of the following
   application layer protocols:

   -  dcerpc
   -  dnp3
   -  dns
   -  http
   -  imap (detection only by default; no parsing)
   -  ftp
   -  modbus (disabled by default; minimalist probe parser; can lead to false positives)
   -  msn (detection only by default; no parsing)
   -  smb
   -  smb2 (disabled internally inside the engine)
   -  smtp
   -  ssh
   -  tls (SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2)

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

   -  You can also use ``app-layer-protocol:<protocol>;`` inside the rule instead.

   So, instead of this Snort rule::

      alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ...

   Do this for Suricata::

      alert http $HOME_NET -> $EXTERNAL_NET any ...

   Or::

      alert tcp $HOME_NET any -> $EXTERNAL_NET any (app-layer-protocol:http; ...

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
   (0x2B) to spaces (0x20).

   -  Suricata can do this as well but you have to explicitly
      set ``query-plusspace-decode: yes`` in the ``libhtp`` section of Suricata's yaml file.

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
   buffer like Snort does.

-  Snort will include a *leading* CRLF in the ``http_header`` buffer of
   *server responses* (but not client requests).  Suricata does not have
   the leading CRLF in the ``http_header`` buffer of the server response
   or client request.

-  In the ``http_header`` buffer, Suricata will normalize HTTP header lines
   such that there is a single space (0x20) after the colon (':') that
   separates the header name from the header value; this single space
   replaces zero or more whitespace characters (including tabs) that may be
   present in the raw HTTP header line immediately after the colon.  If the
   extra whitespace (or lack thereof) is important for matching, use
   the ``http_raw_header`` buffer instead of the ``http_header`` buffer.

-  Snort will also normalize superfluous whitespace between the header name
   and header value like Suricata does but only if there is at least one space
   character (0x20 only so not 0x90) immediately after the colon.  This means
   that, unlike Suricata, if there is no space (or if there is a tab)
   immediately after the colon before the header value, the content of the
   header line will remain unchanged in the ``http_header`` buffer.

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

New HTTP keywords
-----------------

Suricata supports several HTTP keywords that Snort doesn't have.

Examples are ``http_user_agent``, ``http_host`` and ``http_content_type``.

See :doc:`http-keywords` for all HTTP keywords.


``byte_extract`` Keyword
------------------------

-  Suricata supports
   ``byte_extract`` from ``http_*`` buffers, including
   ``http_header`` which does not always work as expected in Snort.

-  In Suricata, variables extracted using ``byte_extract`` must be used
   in the same buffer, otherwise they will have the value "0" (zero). Snort
   does allow cross-buffer byte extraction and usage.

-  Be sure to always positively and negatively test Suricata rules that
   use ``byte_extract`` and ``byte_test`` to verify that they
   work as expected.

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

``tls*`` Keywords
------------------

In addition to TLS protocol identification, Suricata supports the storing of
certificates to disk, verifying the validity dates on certificates, matching
against the calculated SHA1 fingerprint of certificates, and
matching on certain TLS/SSL certificate fields including the following:

-  Negotiated TLS/SSL version.
-  Certificate Subject field.
-  Certificate Issuer field.
-  Certificate SNI Field

For details see :doc:`tls-keywords`.

``dns_query`` Keyword
---------------------

-  Sets the detection pointer to the DNS query.

-  Works like ``file_data`` does ("sticky buffer") but for a DNS
   request query.

-  Use ``pkt_data`` to reset the detection pointer to the beginning of
   the packet payload.

-  See :doc:`dns-keywords` for details.

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

-  :doc:`../reputation/index`
-  :doc:`../reputation/ipreputation/ip-reputation-config`
-  :doc:`../reputation/ipreputation/ip-reputation-rules`
-  :doc:`../reputation/ipreputation/ip-reputation-format`
-  `http://blog.inliniac.net/2012/11/21/ip-reputation-in-suricata/ <http://blog.inliniac.net/2012/11/21/ip-reputation-in-suricata/>`_

Flowbits
--------

-  Suricata fully supports the setting and checking of flowbits
   (including the same flowbit) on the same packet/stream.  Snort does
   not always allow for this.

-  In Suricata, ``flowbits:isset`` is checked after the fast pattern
   match but before other ``content`` matches. In Snort,
   ``flowbits:isset`` is checked in the order it appears in the
   rule, from left to right.

-  If there is a chain of flowbits where multiple rules set flowbits and
   they are dependent on each other, then the order of the rules or the
   ``sid`` values can make a
   difference in the rules being evaluated in the proper order and
   generating alerts as expected.  See bug 1399 -
   `https://redmine.openinfosecfoundation.org/issues/1399 <https://redmine.openinfosecfoundation.org/issues/1399>`_.

-  :doc:`flow-keywords`

flowbits:noalert;
-----------------

A common pattern in existing rules is to use ``flowbits:noalert;`` to make
sure a rule doesn't generate an alert if it matches.

Suricata allows using just ``noalert;`` as well. Both have an identical meaning
in Suricata.

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

-  Suricata has the ability to match on files from HTTP and SMTP streams and
   log them to disk.

-  Snort has the "file" preprocessor that can do something similar
   but it is experimental, development of it
   has been stagnant for years, and it is not something that should be used
   in a production environment.

-  Files can be matched on using a number of keywords including:

   -  ``filename``
   -  ``fileext``
   -  ``filemagic``
   -  ``filesize``
   -  ``filemd5``
   -  ``filesha1``
   -  ``filesha256``
   -  ``filesize``
   - See :doc:`file-keywords` for a full list.

-  The ``filestore`` keyword tells Suricata to save the file to
   disk.

-  Extracted files are logged to disk with meta data that includes
   things like timestamp, src/dst IP, protocol, src/dst port, HTTP URI,
   HTTP Host, HTTP Referer, filename, file magic, md5sum, size, etc.

-  There are a number of configuration options and considerations (such
   as stream reassembly depth and libhtp body-limit) that should be
   understood if you want fully utilize file extraction in Suricata.

-  :doc:`file-keywords`
-  :doc:`../file-extraction/file-extraction`
-  `http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/ <http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/>`_
-  `http://blog.inliniac.net/2014/11/11/smtp-file-extraction-in-suricata/ <http://blog.inliniac.net/2014/11/11/smtp-file-extraction-in-suricata/>`_

Lua Scripting
-------------

-  Suricata has the ``lua`` (or ``luajit``) keyword which allows for a
   rule to reference a Lua script that can access the packet, payload,
   HTTP buffers, etc.
-  Provides powerful flexibility and capabilities that Snort does
   not have.
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
   ``http_stat_code``, and ``http_stat_msg``).

-  See :doc:`fast-pattern-explained` for full details on how Suricata
   automatically determines which content to use as the fast pattern match.

-  When in doubt about what is going to be use as the fast pattern match
   by Suricata, set ``fast_pattern`` explicitly in the rule and/or
   run Suricata with the ``--engine-analysis`` switch and view the
   generated file (``rules_fast_pattern.txt``).

-  Like Snort, the fast pattern match is checked before ``flowbits``
   in Suricata.

-  Using Hyperscan as the MPM matcher (``mpm-algo`` setting) for Suricata
   can greatly improve performance, especially when it comes to fast pattern
   matching.  Hyperscan will also take in to account depth and offset
   when doing fast pattern matching, something the other algorithims and
   Snort do not do.

-  :doc:`fast-pattern`

Don't Cross The Streams
-----------------------

Suricata will examine network traffic as individual packets and, in the
case of TCP, as part of a (reassembled) stream.  However, there are
certain rule keywords that only apply to packets only (``dsize``,
``flags``, ``ttl``) and certain ones that only apply to streams
only (``http_*``) and you can't mix packet and stream keywords. Rules
that use packet keywords will inspect individual packets only and
rules that use stream keywords will inspect streams only.  Snort is a
little more forgiving when you mix these – for example, in Snort you can
use ``dsize`` (a packet keyword) with ``http_*`` (stream
keywords) and Snort will allow it although, because of ``dsize``, it
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

-  Suricata has an internal hard-coded limit of 15 alerts per packet/stream (and
   this cannot be configured); all rules that match on the traffic being
   analyzed will fire up to that limit.

-  Sometimes Suricata will generate what appears to be two alerts for
   the same TCP packet.  This happens when Suricata evaluates the packet
   by itself and as part of a (reassembled) stream.

Buffer Reference Chart
----------------------

+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| Buffer                | Snort 2.9.x                              | Suricata                                  | PCRE   | Can be used as | Suricata Fast    |
|                       | Support?                                 | Support?                                  | flag   | Fast Pattern?  | Pattern Priority |
|                       |                                          |                                           |        |                | (lower number is |
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
| http_host             | NO                                       | YES                                       | W      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_raw_host         | NO                                       | YES                                       | Z      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_client_body      | YES                                      | YES                                       | P      | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_server_body      | NO                                       | YES                                       | Q      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| http_user_agent       | NO                                       | YES                                       | V      | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| dns_query             | NO                                       | YES                                       | n/a\*  | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| tls_sni               | NO                                       | YES                                       | n/a\*  | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| tls_cert_issuer       | NO                                       | YES                                       | n/a\*  | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| tls_cert_subject      | NO                                       | YES                                       | n/a\*  | Suricata only  | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+
| file_data             | YES                                      | YES                                       | n/a\*  | YES            | 2                |
+-----------------------+------------------------------------------+-------------------------------------------+--------+----------------+------------------+

\* Sticky buffer
