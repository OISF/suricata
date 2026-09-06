.. role:: example-rule-emphasis

nDPI
####

Installation
************

This plugin requires nDPI 6.0 or later: earlier releases expose a
different API and will not build.

Before using nDPI, Suricata must be built with nDPI support, for
example:

.. code-block:: console

  ./configure --enable-ndpi --with-ndpi=/home/user/src/nDPI

Then make sure the plugin is loaded in your ``suricata.yaml``:

.. code-block:: yaml

  plugins:
    - /usr/lib/suricata/ndpi.so

Which should also be present in the default configuration file after
building Suricata with nDPI support.

For more information on nDPI, see
https://www.ntop.org/products/deep-packet-inspection/ndpi/.

Configuration
*************

Starting with nDPI 6.0, the library has to be told under which license it
is being used, as some of its dissectors are dual-licensed by ntop. The
plugin exposes this through the optional ``ndpi`` section:

.. code-block:: yaml

  ndpi:
    license: not-for-profit

Accepted values:

``not-for-profit``
  Not-for-profit use. Every dissector is enabled. This is the default when
  the option is absent.

``for-profit``
  For-profit use without a license agreement with ntop. nDPI refuses to load
  its dual-licensed dissectors, which currently include DHCP, DNS, QUIC and
  TLS, so rules matching on those protocols will never fire. The plugin logs
  a warning at startup when this value is selected.

``for-profit-dual``
  For-profit use with a license agreement signed with ntop covering the
  dual-licensed components. Every dissector is enabled.

See https://www.ntop.org/announcing-ndpi-dual-license-change/ for the
licensing terms themselves.

Keywords
********

Once the nDPI plugin is loaded, the following keyword are available:

- ``ndpi-protocol``
- ``ndpi-risk``

``ndpi-protocol``
=================

Match on the Layer-7 protocol detected by nDPI.

Note that rules using the ``ndpi-protocol`` should check if the
``ndpi-protocol`` keyword exists with ``requires``, for example::

  requires: keyword ndpi-protocol

Syntax::

    ndpi-protocol:[!]<protocol>;

Where `<protocol>` is one of the application protocols detected by
nDPI.  Plase check `ndpiReader -H` for the full list.  It is possible
to specify the transport protocol, the application protocol, or both
(dot-separated).

Examples::

    ndpi-protocol:HTTP;
    ndpi-protocol:!TLS;
    ndpi-protocol:TLS.YouTube;

Here is an example of a rule matching TLS traffic on port 53:

.. container:: example-rule

    alert tcp any any -> any 53 (msg:"TLS traffic over DNS standard port"; :example-rule-emphasis:`requires:keyword ndpi-protocol; ndpi-protocol:TLS;` sid:1;)

``ndpi-risk``
=============

Match on the flow risks detected by nDPI. Risks are potential issues
detected by nDPI during the packet dissection and include:

- Known protocol on non-standard port
- Binary application transfer
- Self-signed certificate
- Suspected DGA Domain name
- Malware host contacted
- and many others...

Additionally, rules using the ``ndpi-risk`` keyword should check if
the keyword exists using the ``requires`` keyword, for example::

  requires: keyword ndpi-risk

Syntax::

    ndpi-risk:[!]<risk>;

Where risk is one (or multiple comma-separated) of the risk codes
supported by nDPI (e.g. NDPI_BINARY_APPLICATION_TRANSFER). Please
check ``ndpiReader -H`` for the full list.

Examples::

    ndpi-risk:NDPI_BINARY_APPLICATION_TRANSFER;
    ndpi-risk:NDPI_TLS_OBSOLETE_VERSION,NDPI_TLS_WEAK_CIPHER;

Here is an example of a rule matching HTTP traffic transferring a binary application:

.. container:: example-rule

    alert tcp any any -> any any (msg:"Binary application transfer over HTTP"; :example-rule-emphasis:`requires:keyword ndpi-protocol, keyword ndpi-risk; ndpi-protocol:HTTP; ndpi-risk:NDPI_BINARY_APPLICATION_TRANSFER;` sid:1;)
