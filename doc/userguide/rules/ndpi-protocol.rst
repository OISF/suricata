nDPI Protocol Keyword
=====================

ndpi-protocol
-------------

Match on the Layer-7 protocol detected by nDPI.

Suricata should be compiled with the nDPI support and the ``ndpi``
plugin must be loaded before it can be used.

Example of configuring Suricata to be compiled with nDPI support:

.. code-block:: console

    ./configure --enable-ndpi --with-ndpi=/home/user/nDPI

Example of suricata.yaml configuration file to load the ``ndpi`` plugin::

  plugins:
    - /usr/lib/suricata/ndpi.so

Syntax::

    ndpi-protocol:[!]<protocol>;

Where protocol is one of the application protocols detected by nDPI.
Plase check ndpiReader -H for the full list.
It is possible to specify the transport protocol, the application
protocol, or both (dot-separated).

Examples::

    ndpi-protocol:HTTP;
    ndpi-protocol:!TLS;
    ndpi-protocol:TLS.YouTube;

Here is an example of a rule matching TLS traffic on port 53:

.. container:: example-rule

    alert tcp any any -> any 53 (msg:"TLS traffic over DNS standard port"; ndpi-protocol:TLS; sid:1;)

