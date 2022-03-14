Runmodes
========

Suricata consists of several 'building blocks' called threads,
thread-modules and queues.  A thread is like a process that runs on a
computer. Suricata is multi-threaded, so multiple threads are active
at once.  A thread-module is a part of a functionality. One module is
for example for decoding a packet, another is the detect-module and
another one the output-module.  A packet can be processed by more than
one thread. The packet will then be passed on to the next thread through
a queue. Packets will be processed by one thread at a time, but there
can be multiple packets being processed at a time by the engine (see
:ref:`suricata-yaml-max-pending-packets`). A thread can have one or
more thread-modules. If they have more modules, they can only be
active one a a time.  The way threads, modules and queues are arranged
together is called the "Runmode".

Different runmodes
~~~~~~~~~~~~~~~~~~

You can choose a runmode out of several predefined runmodes. The
command line option ``--list-runmodes`` shows all available runmodes. All
runmodes have a name: single, workers, autofp.

Generally, the ``workers`` runmode performs the best. In this mode the
NIC/driver makes sure packets are properly balanced over Suricata's
processing threads. Each packet processing thread then contains the
full packet pipeline.

.. image:: runmodes/workers.png

For processing PCAP files, or in case of certain IPS setups (like NFQ),
``autofp`` is used. Here there are one or more capture threads, that
capture the packet and do the packet decoding, after which it is passed
on to the ``flow worker`` threads.

.. image:: runmodes/autofp1.png

.. image:: runmodes/autofp2.png

Finally, the ``single`` runmode is the same as the ``workers`` mode,
however there is only a single packet processing thread. This is mostly
useful during development.

.. image:: runmodes/single.png

For more information about the command line options concerning the
runmode, see :doc:`../command-line-options`.

Load balancing
~~~~~~~~~~~~~~

Suricata may use different ways to load balance the packets to process
between different threads with the configuration option `autofp-scheduler`.

The default value is `hash`, which means the packet is assigned to threads
using the 5-7 tuple hash, which is also used anyways to store the flows
in memory.

This option can also be set to
- `ippair` : packets are assigned to threads using addresses only.
- `ftp-hash` : same as `hash` except for flows that may be ftp or ftp-data
so that these flows get processed by the same thread. Like so, there is no
concurrency issue in recognizing ftp-data flows due to processing them
before the ftp flow got processed. In case of such a flow, a variant of the
hash is used.
