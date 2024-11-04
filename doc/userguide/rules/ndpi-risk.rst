nDPI Risk Keyword
=================

ndpi-risk
---------

Match on the flow risks detected by nDPI. Risks are potential issues detected
by nDPI during the packet dissection and include:

- Known Proto on Non Std Port
- Binary App Transfer
- Self-signed Certificate
- Susp DGA Domain name
- Malware host contacted
- and many other...

Suricata should be compiled with the nDPI support and the ``ndpi`` 
plugin must be loaded before it can be used. 

Example of configuring Suricata to be compiled with nDPI support:

.. code-block:: console

    ./configure --enable-ndpi --with-ndpi=/home/user/nDPI

Example of suricata.yaml configuration file to load the ``ndpi`` plugin::

  plugins:
    - /usr/lib/suricata/ndpi.so

Syntax::

    ndpi-risk:[!]<risk>;

Where risk is one (or multiple comma-separated) of the risk codes supported by
nDPI (e.g. NDPI_BINARY_APPLICATION_TRANSFER). Please check ndpiReader -H for the
full list.

Examples::

    ndpi-risk:NDPI_BINARY_APPLICATION_TRANSFER;
    ndpi-risk:NDPI_TLS_OBSOLETE_VERSION,NDPI_TLS_WEAK_CIPHER;

Here is an example of a rule matching HTTP traffic transferring a binary application:

.. container:: example-rule

    alert tcp any any -> any any (msg:"Binary application transfer over HTTP"; ndpi-protocol:HTTP; ndpi-risk:NDPI_BINARY_APPLICATION_TRANSFER; sid:1;)

