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

This keyword maps to the eve field  ``ldap.request.operation``

Examples
^^^^^^^^

Example of a signatures that would alert if the packet has an LDAP bind request operation:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:0;` sid:1;)

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:bind_request;` sid:1;)
