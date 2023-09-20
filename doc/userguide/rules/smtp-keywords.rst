SMTP Keywords
=============

.. role:: example-rule-options

file.name
---------

The ``file.name`` keyword can be used at the SMTP application level. 

Signature Example:

.. container:: example-rule

  alert smtp any any -> any any (msg:"SMTP file.name usage"; \
  :example-rule-options:`file.name; content:"winmail.dat";` \
  classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.