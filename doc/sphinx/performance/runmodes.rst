Runmodes
========

Suricata consists of several 'building blocks' called threads,
thread-modules and queues.  A thread is like a process that runs on a
computer. Suricata is multi-threaded, so multiple threads are active
at once.  A thread-module is a part of a functionality. One module is
for example for decoding a packet, another is the detect-module and
another one the output-module.  A packet can be processed by more than
one thread. The packet will be passed on to the next thread through a
queue. Packets will be processed by one thread at a time, but there
can be multiple packets being processed at a time by the engine. (see
:ref:`suricata-yaml-max-pending-packets`) A thread can have one or
more thread-modules. If they have more modules, they can only be
active on a a time.  The way threads, modules and queues are arranged
together is called the Runmode.

Different runmodes
~~~~~~~~~~~~~~~~~~

You can choose a runmode out of several predefined runmodes. The
command line option --list-runmodes shows all available runmodes.  All
runmodes have a name: auto, single, autofp.  The heaviest task is the
detection; a packet will be checked against thousands of signatures.

Example of the default runmode:

.. image:: runmodes/threading1.png

In the pfring mode, every flow follows its own fixed route in the runmode.

.. image:: runmodes/Runmode_autofp.png

For more information about the command line options concerning the
runmode, see :doc:`../command-line-options`.
