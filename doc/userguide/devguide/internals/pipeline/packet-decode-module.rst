.. _DEV-PPL packet-decode:

====================
Pacote Decode Module
====================

This module is responsible for decoding the packet. This comprises using a capture
method specific decoder, then calling into the generic Suricata packet decoders,
like `decode-ethernet.c <https://doxygen.openinfosecfoundation.org/decode-ethernet_8c.html>`_
and `decode-ipv4.c <https://doxygen.openinfosecfoundation.org/decode-ipv4_8c.html>`_.
