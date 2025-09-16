EVE JSON Schema
###############

The Suricata source distribution contains a JSON schema for the EVE
log files. This schema follows the `JSON Schema
<https://json-schema.org/>`_ specification and can be found in
``etc/schema.json``. If your distribution does not contain this file,
it can be viewed online at
https://github.com/OISF/suricata/blob/main/etc/schema.json, but note
that it is version-specific and may change between major versions of
Suricata.

This schema attempts to log all possible fields that may be seen in
Suricata's **EVE** output, including their datatype. It also includes
extensions to help map log fields to related detection keywords.

Suricata Schema Extensions
^^^^^^^^^^^^^^^^^^^^^^^^^^

We have extended JSON schema with a ``suricata`` object to add extra
Suricata context such as detection keywords related to a log field,
for example:

.. code-block:: json

   "rrname": {
       "type": "string",
       "suricata": {
           "keywords": [
               "dns.answers.rrname",
               "dns.response.rrname"
           ]
       }
   }

The above shows that a field named ``rrname`` has 2 keywords that are
related. Please refer to the keyword documentation to see precisely
how they are used and related to the field being logged.

Extension Reference
===================

The ``suricata`` extension object is valid on objects inside the
``properties`` object. The ``suricata`` object may accept the
following fields:

``keywords``
------------

**Type:** ``array`` or ``boolean``

* **When an array:** Contains keyword names that are related to this
  JSON property. Each keyword in the array represents a detection rule
  keyword that can be used to match against the corresponding field
  value.

* **When ``false``:** Indicates that this JSON property has no
  applicable keyword. This is used for metadata fields that don't
  correspond to actual network data. For example, the ``version``
  field inside a DNS object denotes the version of the log format and
  is unrelated to any aspect of a DNS message, therefore no keyword is
  applicable.

.. note:: As of Suricata 8.0, mapping log fields to detection keywords
          is a work in progress. Any field that does not have a
          ``suricata.keywords`` value still needs to be evaluated.

Schema Tooling
^^^^^^^^^^^^^^

* `Suricata-Verify <https://github.com/OISF/suricata-verify>`_: Our
  own tool for verifying every Suricata pull request, validates all
  EVE logs generated against the schema.

* ``./scripts/eve-parity.py``: Found inside the Suricata source code
  when checked out with ``git``, is a tool to provide information on
  how log fields map to keywords, or how keywords map to log entries.

* ``./scripts/evedoc.py``: Generate documentation from the schema,
  such as the :doc:`eve-index` included in this documentation.
