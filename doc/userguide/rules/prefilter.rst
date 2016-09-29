Prefilter
=========

The prefilter engines for other non-MPM keywords can be enabled in specific rules by using the 'prefilter' keyword.

In the following rule the TTL test will be used in prefiltering instead of the single byte pattern:

::

  alert ip any any -> any any (ttl:123; prefilter; content:"a"; sid:1;)

For more information on how to configure the prefilter engines, see :ref:`suricata-yaml-prefilter`

