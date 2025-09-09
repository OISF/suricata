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

ldap.responses.operation is also a :ref:`multi-integer <multi-integers>`.

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

.. note::

    If a response within the array does not contain the
    distinguished name field, this field will be interpreted
    as an empty buffer.

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

ldap.responses.result_code
--------------------------

Suricata has a ``ldap.responses.result_code`` keyword that can be used in signatures to identify
and filter network packets based on their LDAP result code.

Syntax::

 ldap.responses.result_code: code[,index];

ldap.responses.result_code uses :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

ldap.responses.result_code is also a :ref:`multi-integer <multi-integers>`.

This keyword maps to the following eve fields:

   - ``ldap.responses[].bind_response.result_code``
   - ``ldap.responses[].search_result_done.result_code``
   - ``ldap.responses[].modify_response.result_code``
   - ``ldap.responses[].add_response.result_code``
   - ``ldap.responses[].del_response.result_code``
   - ``ldap.responses[].mod_dn_response.result_code``
   - ``ldap.responses[].compare_response.result_code``
   - ``ldap.responses[].extended_response.result_code``

.. table:: **Result code values for ldap.responses.result_code**

    =========  ================================================
    Code       Name
    =========  ================================================
    0          success
    1          operations_error
    2          protocol_error
    3          time_limit_exceeded
    4          size_limit_exceeded
    5          compare_false
    6          compare_true
    7          auth_method_not_supported
    8          stronger_auth_required
    10         referral
    11         admin_limit_exceeded
    12         unavailable_critical_extension
    13         confidentiality_required
    14         sasl_bind_in_progress
    16         no_such_attribute
    17         undefined_attribute_type
    18         inappropriate_matching
    19         constraint_violation
    20         attribute_or_value_exists
    21         invalid_attribute_syntax
    32         no_such_object
    33         alias_problem
    34         invalid_dns_syntax
    35         is_leaf
    36         alias_dereferencing_problem
    48         inappropriate_authentication
    49         invalid_credentials
    50         insufficient_access_rights
    51         busy
    52         unavailable
    53         unwilling_to_perform
    54         loop_detect
    60         sort_control_missing
    61         offset_range_error
    64         naming_violation
    65         object_class_violation
    66         not_allowed_on_non_leaf
    67         not_allowed_on_rdn
    68         entry_already_exists
    69         object_class_mods_prohibited
    70         results_too_large
    71         affects_multiple_dsas
    76         control_error
    80         other
    81         server_down
    82         local_error
    83         encoding_error
    84         decoding_error
    85         timeout
    86         auth_unknown
    87         filter_error
    88         user_canceled
    89         param_error
    90         no_memory
    91         connect_error
    92         not_supported
    93         control_not_found
    94         no_results_returned
    95         more_results_to_return
    96         client_loop
    97         referral_limit_exceeded
    100        invalid_response
    101        ambiguous_response
    112        tls_not_supported
    113        intermediate_response
    114        unknown_type
    118        canceled
    119        no_such_operation
    120        too_late
    121        cannot_cancel
    122        assertion_failed
    123        authorization_denied
    4096       e_sync_refresh_required
    16654      no_operation
    =========  ================================================

More information about LDAP result code values can be found here:
https://ldap.com/ldap-result-code-reference/

An LDAP request operation can receive multiple responses. By default, the ldap.responses.result_code
keyword matches with any indices, but it is possible to specify a particular index for matching
and also use flags such as ``all`` and ``any``.

.. table:: **Index values for ldap.responses.result_code keyword**

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

Example of signatures that would alert if the packet has a ``success`` LDAP result code at any index:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP result code"; :example-rule-emphasis:`ldap.responses.result_code:0;` sid:1;)

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP result code"; :example-rule-emphasis:`ldap.responses.result_code:success,any;` sid:1;)

Example of a signature that would alert if the packet has an ``unavailable`` LDAP result code at index 1:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP result code at index 1"; :example-rule-emphasis:`ldap.responses.result_code:unavailable,1;` sid:1;)

Example of a signature that would alert if all the responses have a ``success`` LDAP result code:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test all LDAP responses have success result code"; :example-rule-emphasis:`ldap.responses.result_code:success,all;` sid:1;)

The keyword ldap.responses.result_code supports back to front indexing with negative numbers,
this means that -1 will represent the last index, -2 the second to last index, and so on.
This is an example of a signature that would alert if a ``success`` result code is found at the last index:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP success at last index"; :example-rule-emphasis:`ldap.responses.result_code:success,-1;` sid:1;)

ldap.responses.message
----------------------

Matches on LDAP error messages from response operations.

Comparison is case-sensitive.

Syntax::

 ldap.responses.message; content:"<content to match against>";

``ldap.responses.message`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``ldap.responses.message`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE fields:

   - ``ldap.responses[].bind_response.message``
   - ``ldap.responses[].search_result_done.message``
   - ``ldap.responses[].modify_response.message``
   - ``ldap.responses[].add_response.message``
   - ``ldap.responses[].del_response.message``
   - ``ldap.responses[].mod_dn_response.message``
   - ``ldap.responses[].compare_response.message``
   - ``ldap.responses[].extended_response.message``

.. note::

    If a response within the array does not contain the
    error message field, this field will be interpreted
    as an empty buffer.

Example
^^^^^^^

Example of a signature that would alert if a packet has the LDAP error message ``Size limit exceeded``:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test LDAP error message"; ldap.responses.message; content:"Size limit exceeded"; sid:1;)

ldap.request.attribute_type
---------------------------

Matches on LDAP attribute type from request operations.

Comparison is case-sensitive.

Syntax::

 ldap.request.attribute_type; content:"<content to match against>";

``ldap.request.attribute_type`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``ldap.request.attribute_type`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE fields:

   - ``ldap.request.search_request.attributes[]``
   - ``ldap.request.modify_request.changes[].modification.attribute_type``
   - ``ldap.request.add_request.attributes[].name``
   - ``ldap.request.compare_request.attribute_value_assertion.description``

Example
^^^^^^^

Example of a signature that would alert if a packet has the LDAP attribute type ``objectClass``:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test attribute type"; :example-rule-emphasis:`ldap.request.attribute_type; content:"objectClass";` sid:1;)

It is possible to use the keyword ``ldap.request.operation`` in the same rule to
specify the operation to match.

Here is an example of a signature that would alert if a packet has an LDAP
add request operation and contains the LDAP attribute type
``objectClass``.

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test attribute type and operation"; :example-rule-emphasis:`ldap.request.operation:add_request; ldap.request.attribute_type; content:"objectClass";` sid:1;)

ldap.responses.attribute_type
-----------------------------

Matches on LDAP attribute type from response operations.

Comparison is case-sensitive.

Syntax::

 ldap.responses.attribute_type; content:"<content to match against>";

``ldap.responses.attribute_type`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``ldap.responses.attribute_type`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``ldap.responses[].search_result_entry.attributes[].type``

Example
^^^^^^^

Example of a signature that would alert if a packet has the LDAP attribute type ``dc``:

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test responses attribute type"; :example-rule-emphasis:`ldap.responses.attribute_type; content:"dc";` sid:1;)

It is possible to use the keyword ``ldap.responses.operation`` in the same rule to
specify the operation to match.

Here is an example of a signature that would alert if a packet has an LDAP
search result entry operation at index 1 on the responses array,
and contains the LDAP attribute type ``dc``.

.. container:: example-rule

  alert ldap any any -> any any (msg:"Test attribute type and operation"; :example-rule-emphasis:`ldap.responses.operation:search_result_entry,1; ldap.responses.attribute_type; content:"dc";` sid:1;)
