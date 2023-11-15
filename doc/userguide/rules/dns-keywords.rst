DNS Keywords
============

Suricata supports sticky buffers as well as keywords for efficiently
matching on specific fields in DNS messages.

Note that sticky buffers are expected to be followed by one or more
:doc:`payload-keywords`.

dns.answer.name
---------------

``dns.answer.name`` is a sticky buffer that is used to look at the
name field in DNS answer resource records.

``dns.answer.name`` will look at both requests and responses, so
``flow`` is recommended to confine to a specific direction.

.. note:: At this time ``dns.answer.name`` is only supported for
          responses, but supporting it in requests is planned.

The buffer being matched on contains the complete re-assembled
resource name, for example "www.suricata.io".

``dns.answer.name`` supports :doc:`multi-buffer-matching`.

dns.opcode
----------

This keyword matches on the **opcode** found in the DNS header flags.

Syntax
~~~~~~

::

   dns.opcode:[!]<number>

Examples
~~~~~~~~

Match on DNS requests and responses with **opcode** 4::

  dns.opcode:4;

Match on DNS requests where the **opcode** is NOT 0::

  dns.opcode:!0;

dns.query
---------

With **dns.query** the DNS request query names are inspected. The
dns.query keyword works a bit different from the normal content
modifiers. When used in a rule all contents following it are affected
by it.  Example:

  alert dns any any -> any any (msg:"Test dns.query option";
  dns.query; content:"google"; nocase; sid:1;)

.. image:: dns-keywords/dns_query.png

The **dns.query** keyword affects all following contents, until pkt_data
is used or it reaches the end of the rule.

.. note:: **dns.query** is equivalent to the older **dns_query**.

.. note:: **dns.query** will only match on DNS request messages, to
          also match on DNS response message, see
          `dns.query.name`_.

Normalized Buffer
~~~~~~~~~~~~~~~~~

Buffer contains literal domain name

-  <length> values (as seen in a raw DNS request)
   are literal '.' characters
-  no leading <length> value
-  No terminating NULL (0x00) byte (use a negated relative ``isdataat``
   to match the end)

Example DNS request for "mail.google.com" (for readability, hex
values are encoded between pipes):

DNS query on the wire (snippet)::

    |04|mail|06|google|03|com|00|

``dns.query`` buffer::

    mail.google.com

Multiple Buffer Matching
~~~~~~~~~~~~~~~~~~~~~~~~

``dns.query`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

dns.query.name
---------------

``dns.query.name`` is a sticky buffer that is used to look at the name
field in DNS query (question) resource records. It is nearly identical
to ``dns.query`` but supports both DNS requests and responses.

``dns.query.name`` will look at both requests and responses, so
``flow`` is recommended to confine to a specific direction.

The buffer being matched on contains the complete re-assembled
resource name, for example "www.suricata.io".

``dns.query.name`` supports :doc:`multi-buffer-matching`.
