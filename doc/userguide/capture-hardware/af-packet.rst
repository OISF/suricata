.. _afpacket:

AF_PACKET
#########

Introduction
************

AF_PACKET is a capture interface to the Linux Kernel.

Config Options
**************

enable-hwtimestamp
==================

Boolean option to enable hardware timestamping on an interface.

By default the hardware timestamping support is disabled.

Hardware timestamping can lead to issue of the NIC and kernel getting out of sync. See 
`ticket 7585 <https://redmine.openinfosecfoundation.org/issues/7585>`_.

::

    af-packet:
      - interface: eth0
        cluster-id: 99
        enable-hwtimestamp: true
        cluster-type: cluster_flow

