DNS Keywords
============

There are some more content modifiers (If you are unfamiliar with
content modifiers, please visit the page :doc:`payload-keywords` These
ones make sure the signature checks a specific part of the
network-traffic.

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

With **dns.query** the DNS request queries are inspected. The dns.query
keyword works a bit different from the normal content modifiers. When
used in a rule all contents following it are affected by it.  Example:

  alert dns any any -> any any (msg:"Test dns.query option";
  dns.query; content:"google"; nocase; sid:1;)

.. image:: dns-keywords/dns_query.png

The **dns.query** keyword affects all following contents, until pkt_data
is used or it reaches the end of the rule.

.. note:: **dns.query** is equivalent to the older **dns_query**.

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
