LDAP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

LDAP Request and Response operations
------------------------------------

.. table:: **Operation values for ldap.request.operation and ldap.responses.operation keywords**

    ====  ================================================
    Code  Operation
    ====  ================================================
    0     bind_request
    1     bind_response
    2     unbind_request
    3     search_request
    4     search_result_entry
    5     search_result_done
    6     modify_request
    7     modify_response
    8     add_request
    9     add_response
    10    del_request
    11    del_response
    12    mod_dn_request
    13    mod_dn_response
    14    compare_request
    15    compare_response
    16    abandon_request
    19    search_result_reference
    23    extended_request
    24    extended_response
    25    intermediate_response
    ====  ================================================

The keywords ldap.request.operation and ldap.responses.operation
accept both the operation code and the operation name as arguments.

ldap.request.operation
----------------------

Suricata has a ``ldap.request.operation`` keyword that can be used in signatures to identify
and filter network packets based on Lightweight Directory Access Protocol request operations.

Syntax::

 ldap.request.operation: operation;

ldap.request.operation uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

This keyword maps to the EVE field  ``ldap.request.operation``

Examples
^^^^^^^^

Example of a signatures that would alert if the packet has an LDAP bind request operation:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:0;` sid:1;)

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:bind_request;` sid:1;)

ldap.responses.operation
------------------------

Suricata has a ``ldap.responses.operation`` keyword that can be used in signatures to identify
and filter network packets based on Lightweight Directory Access Protocol response operations.

Syntax::

 ldap.responses.operation: operation[,index];

ldap.responses.operation uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

This keyword maps to the EVE field ``ldap.responses[].operation``

An LDAP request operation can receive multiple responses. By default, the ldap.responses.operation
keyword matches all indices, but it is possible to specify a particular index for matching
and also use flags such as ``all`` and ``any``.

.. table:: **Index values for ldap.responses.operation keyword**

    =========  ================================================
    Value      Description
    =========  ================================================
    [default]  Match with any index
    all        Match only if all indexes match
    any        Match with any index
    0>=        Match specific index
    0<         Match specific index with back to front indexing
    =========  ================================================

Examples
^^^^^^^^

Example of a signatures that would alert if the packet has an LDAP bind response operation:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP bind response"; :example-rule-emphasis:`ldap.responses.operation:1;` sid:1;)

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP bind response"; :example-rule-emphasis:`ldap.responses.operation:bind_response;` sid:1;)

Example of a signature that would alert if the packet has an LDAP search_result_done response operation at index 1:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP search response"; :example-rule-emphasis:`ldap.responses.operation:search_result_done,1;` sid:1;)

Example of a signature that would alert if all the responses are of type search_result_entry:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP search response"; :example-rule-emphasis:`ldap.responses.operation:search_result_entry,all;` sid:1;)

The keyword ldap.responses.operation supports back to front indexing with negative numbers,
this means that -1 will represent the last index, -2 the second to last index, and so on.
This is an example of a signature that would alert if a search_result_entry response is found at the last index:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP search response"; :example-rule-emphasis:`ldap.responses.operation:search_result_entry,-1;` sid:1;)

ldap.responses.count
--------------------

Matches based on the number of responses.

Syntax::

 ldap.responses.count: [op]number;

It can be matched exactly, or compared using the ``op`` setting::

 ldap.responses.count:3    # exactly 3 responses
 ldap.responses.count:<3   # less than 3 responses
 ldap.responses.count:>=2  # more or equal to 2 responses

ldap.responses.count uses :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

This keyword maps to the EVE field ``len(ldap.responses[])``

Examples
^^^^^^^^

Example of a signature that would alert if a packet has 0 LDAP responses:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Packet has 0 LDAP responses"; :example-rule-emphasis:`ldap.responses.count:0;` sid:1;)

Example of a signature that would alert if a packet has more than 2 LDAP responses:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Packet has more than 2 LDAP responses"; :example-rule-emphasis:`ldap.responses.count:>2;` sid:1;)

ldap.request.dn
---------------

Matches on LDAP distinguished names from request operations.

Comparison is case-sensitive.

Syntax::

 ldap.request.dn; content:"<content to match against>";

``ldap.request.dn`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE fields:

   - ``ldap.request.bind_request.name``
   - ``ldap.request.add_request.entry``
   - ``ldap.request.search_request.base_object``
   - ``ldap.request.modify_request.object``
   - ``ldap.request.del_request.dn``
   - ``ldap.request.mod_dn_request.entry``
   - ``ldap.request.compare_request.entry``

Example
^^^^^^^

Example of a signature that would alert if a packet has the LDAP distinguished name ``uid=jdoe,ou=People,dc=example,dc=com``:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAPDN"; :example-rule-emphasis:`ldap.request.dn; content:"uid=jdoe,ou=People,dc=example,dc=com";` sid:1;)

It is possible to use the keyword ``ldap.request.operation`` in the same rule to
specify the operation to match.

Here is an example of a signature that would alert if a packet has an LDAP
search request operation and contains the LDAP distinguished name
``dc=example,dc=com``.

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAPDN and operation"; :example-rule-emphasis:`ldap.request.operation:search_request; ldap.request.dn; content:"dc=example,dc=com";` sid:1;)

ldap.responses.dn
-----------------

Matches on LDAP distinguished names from response operations.

Comparison is case-sensitive.

Syntax::

 ldap.responses.dn; content:"<content to match against>";

``ldap.responses.dn`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``ldap.responses.dn`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE fields:

   - ``ldap.responses[].search_result_entry.base_object``
   - ``ldap.responses[].bind_response.matched_dn``
   - ``ldap.responses[].search_result_done.matched_dn``
   - ``ldap.responses[].modify_response.matched_dn``
   - ``ldap.responses[].add_response.matched_dn``
   - ``ldap.responses[].del_response.matched_dn``
   - ``ldap.responses[].mod_dn_response.matched_dn``
   - ``ldap.responses[].compare_response.matched_dn``
   - ``ldap.responses[].extended_response.matched_dn``

Example
^^^^^^^

Example of a signature that would alert if a packet has the LDAP distinguished name ``dc=example,dc=com``:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAPDN"; :example-rule-emphasis:`ldap.responses.dn; content:"dc=example,dc=com";` sid:1;)

It is possible to use the keyword ``ldap.responses.operation`` in the same rule to
specify the operation to match.

Here is an example of a signature that would alert if a packet has an LDAP
search result entry operation at index 1 on the responses array,
and contains the LDAP distinguished name ``dc=example,dc=com``.

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAPDN and operation"; :example-rule-emphasis:`ldap.responses.operation:search_result_entry,1; ldap.responses.dn; content:"dc=example,dc=com";` sid:1;)
