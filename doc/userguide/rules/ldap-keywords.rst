LDAP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

ldap.request.operation
----------------------

Suricata has a ``ldap.request.operation`` keyword that can be used in signatures to identify
and filter network packets based on Lightweight Directory Access Protocol request operations.

Syntax::

 ldap.request.operation: operation;

ldap.request.operation uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

.. table:: **Operation values for ldap.request.operation keyword**

    ====  ================================================
    Code  Request Operation
    ====  ================================================
    0     BindRequest
    2     UnbindRequest
    3     SearchRequest
    6     ModifyRequest
    8     AddRequest
    10    DelRequest
    12    ModDnRequest
    14    CompareRequest
    23    ExtendedRequest
    ====  ================================================

Example
^^^^^^^^

Example of a signature that would alert if the packet has an LDAP bind request operation:

.. container:: example-rule

  alert tcp any any -> any any (msg:"Test LDAP bind request"; :example-rule-emphasis:`ldap.request.operation:0;` sid:1;)