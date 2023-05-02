===============
Packet Pipeline
===============

Main Takeaways:

- What is Suricata's Packet Pipeline
- Main components
- How do these work together
- Different thread models (?)

Introduction
============

The Packet Pipeline might be considered the core part of Suricata. It is in this
macro-component that the Packet processing happen (``PacketProcessing``
threads). The two other main components are **Management threads**
responsible for *Flow Managing* and *Stats*.

In Suricata, the packet pipeline starts with the Packet Capture.

The pipeline either runs in a single thread (runmode *single* or *workers*) or
split in 2 stages (*autofp*).

A pipeline is created by Suricata's ``RunMode`` and stored in per thread
`ThreadVars <https://doxygen.openinfosecfoundation.org/threadvars_8h.html#ac6c5d759a1e814014a6a59ae58c594df>`_.

Main Components
===============

- :ref:`Packet Pool<DEV-PPL packet-pool>`
- :ref:`Packet Capture Module<DEV-PPL packet-capture>`
- :ref:`Packet Decode Module<DEV-PPL packet-decode>`
- Flow Worker Module (covered in the *Engines* chapter)

  - :ref:`Flow handling<DEV-ENG flow>`
  - :ref:`TCP stream<DEV-ENG stream>`
  - :ref:`Application Layer Protocols parsing <DEV-PPL app-layer>`
  - :ref:`Detection<DEV-ENG detect>`
  - :ref:`Outputs & logging<DEV-ENG outputs>`
- :ref:`Reject / Respond<DEV-PPL reject-respond>`
- :ref:`Verdict<DEV-PPL verdict>` (for selected IPS modes)

The different runmodes
======================

Runmodes are defined by the capture method (e.g.
`runmode-af-packet.c <https://doxygen.openinfosecfoundation.org/runmode-af-packet_8c.html>`_),
but generally implement 3 predefined modes: *workers*, *autofp*, *single*). For a
performance perspective and more on runmodes, see :doc:`../../../performance/runmodes`.

Workers
-------

In Workers mode, each worker thread is responsible for the whole pipeline
(Capture, Decode, and subsequent flow worker's tasks).

Autofp
------

In Autofp, 1:N threads are responsible for Capture+Decode, communicating with
1:N Packet Queues, which will then communicate with flow worker threads.
