LDAP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

LDAP Request and Response operations
------------------------------------

.. table:: **Operation values for ldap.request.operation and ldap.response.operation keywords**

    ====  ================================================
    Code  Operation
    ====  ================================================
    0     bind_request
    1     bind_response
    2     unbind_request
    3     search_request
    4     search_result_entry
    5     search_result_done
    19    search_result_reference
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
    23    extended_request
    24    extended_response
    25    intermediate_response
    ====  ================================================

ldap.request.operation
~~~~~~~~~~~~~~~~~~~~~~

Suricata has a ``ldap.request.operation`` keyword that can be used in signatures to identify
and filter network packets based on Lightweight Directory Access Protocol request operations.

Syntax::

 ldap.request.operation: operation;

ldap.request.operation uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

Example
^^^^^^^^

Example of a signature that would alert if the packet has an LDAP bind request operation:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:0;` sid:1;)


ldap.responses.operation
~~~~~~~~~~~~~~~~~~~~~~~~

Suricata has a ``ldap.responses.operation`` keyword that can be used in signatures to identify
and filter network packets based on Lightweight Directory Access Protocol response operations.

Syntax::

 ldap.responses.operation: operation[,index];

ldap.responses.operation uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

An LDAP request operation can receive multiple responses. By default, the ldap.responses.operation
keyword matches all indices, but it is possible to specify a particular index for matching
and also use flags such as ``all`` and ``any``.

.. table:: **Index values for ldap.responses.operation keyword**

    =========  ================================================
    Value      Description
    =========  ================================================
    [default]  Match all indexes
    all        Match only if all indexes match
    any        Match all indexes
    0>=        Match specific index
    =========  ================================================

Examples
^^^^^^^^

Example of a signature that would alert if the packet has an LDAP bind response operation:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP bind response"; :example-rule-emphasis:`ldap.responses.operation:1;` sid:1;)

Example of a signature that would alert if the packet has an LDAP search_result_done response operation at index 1:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP search response"; :example-rule-emphasis:`ldap.responses.operation:search_result_done,1;` sid:1;)

Example of a signature that would alert if all the responses are of type search_result_entry:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP search response"; :example-rule-emphasis:`ldap.responses.operation:search_result_entry,all;` sid:1;)