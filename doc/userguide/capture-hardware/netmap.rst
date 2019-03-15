Netmap
======

Netmap is a high speed capture framework for Linux and FreeBSD. In Linux it
is available as an external module, while in FreeBSD 11+ it is available by
default.


Compiling Suricata
------------------

FreeBSD
~~~~~~~

On FreeBSD 11 and up, NETMAP is included and enabled by default in the kernel.

To build Suricata with NETMAP, add ``--enable-netmap`` to the configure line.
The location of the NETMAP includes (/usr/src/sys/net/) does not have to be
specified.

Linux
~~~~~

On Linux, NETMAP is not included by default. It can be pulled from github.
Follow the instructions on installation included in the NETMAP repository.

When NETMAP is installed, add ``--enable-netmap`` to the configure line.
If the includes are not added to a standard location, the location can
be specified on the Suricata configure commandline.

Example::

    ./configure --enable-netmap --with-netmap-includes=/usr/local/include/netmap/

Starting Suricata
-----------------

When opening an interface, netmap can take various special characters as
options in the interface string.

.. warning:: the interface that netmap reads from will become unavailable
             for normal network operations. You can lock yourself out of
             your system.

IDS
~~~

Suricata can be started in 2 ways to use netmap:

::

    suricata --netmap=<interface>
    suricata --netmap=igb0

In the above example Suricata will start reading from igb0. The number of
threads created depends on the number of RSS queues available on the NIC.

::

    suricata --netmap

In the above example Suricata will take the ``netmap`` block from the yaml
and open each of the interfaces listed.

::

    netmap:
      - interface: igb0
        threads: 2
      - interface: igb1
        threads: 4

For the above configuration, both igb0 and igb1 would be opened. With 2
threads for igb0 and 4 capture threads for igb1.

.. warning:: This multi threaded setup only works correctly if the NIC
             has symmetric RSS hashing. If this is not the case, consider
             using the the 'lb' method below.

IPS
~~~

Suricata's Netmap based IPS mode is based on the concept of creating
a layer 2 software bridge between 2 interfaces. Suricata reads packets on
one interface and transmits them on another.

Packets that are blocked by the IPS policy, are simply not transmitted.

::

    netmap:
      - interface: igb0
        copy-mode: ips
        copy-iface: igb1
      - interface: igb1
        copy-mode: ips
        copy-iface: igb0

Advanced setups
---------------

lb (load balance)
-----------------

"lb" is a tool written by Seth Hall to allow for load balancing for single
or multiple tools. One common use case is being able to run Suricata and
Zeek together on the same traffic.

starting lb::

    lb -i eth0 -p suricata:6 -p zeek:6

.. note:: On FreeBSD 11, the named prefix doesn't work.

yaml::

    netmap:
      - interface: suricata
        threads: 6

startup::

    suricata --netmap=netmap:suricata

The interface name as passed to Suricata includes a 'netmap:' prefix. This
tells Suricata that it's going to read from netmap pipes instead of a real
interface.

Then Zeek (formerly Bro) can be configured to load 6 instances. Both will
get a copy of the same traffic. The number of netmap pipes does not have
to be equal for both tools.

FreeBSD 11
~~~~~~~~~~

On FreeBSD 11 the named pipe is not available.

starting lb::

    lb -i eth0 -p 6

yaml::

    netmap:
      - interface: netmap:eth0
        threads: 6

startup::

    suricata --netmap


.. note:: "lb" is bundled with netmap.

Single NIC
~~~~~~~~~~

When an interface enters NETMAP mode, it is no longer available to
the OS for other operations. This can be undesirable in certain
cases, but there is a workaround.

By running Suricata in a special inline mode, the interface will
show it's traffic to the OS.

::

    netmap:
      - interface: igb0
        copy-mode: tap
        copy-iface: igb0^
      - interface: igb0^
        copy-mode: tap
        copy-iface: igb0

The copy-mode can be both 'tap' and 'ips', where the former never
drops packets based on the policies in use, and the latter may drop
packets.

.. warning:: Misconfiguration can lead to connectivity loss. Use
             with care.

.. note:: This set up can also be used to mix NETMAP with firewall
          setups like pf or ipfw.

VALE switches
~~~~~~~~~~~~~

VALE is a virtual switch that can be used to create an all virtual
network or a mix of virtual and real nics.

A simple all virtual setup::

    vale-ctl -n vi0
    vale-ctl -a vale0:vi0
    vale-ctl -n vi1
    vale-ctl -a vale0:vi1

We now have a virtual switch "vale0" with 2 ports "vi0" and "vi1".

We can start Suricata to listen on one of the ports::

    suricata --netmap=vale0:vi1

Then we can

Inline IDS
----------

The inline IDS is almost the same as the IPS setup above, but it will not
enfore ``drop`` policies.

::

    netmap:
      - interface: igb0
        copy-mode: tap
        copy-iface: igb1
      - interface: igb1
        copy-mode: tap
        copy-iface: igb0

The only difference with the IPS mode is that the ``copy-mode`` setting is
set to ``tap``.
