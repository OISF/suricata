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

In Suricata, the packet pipeline starts with the Packet Capture.

The pipeline either runs in a single thread (runmode *single* or *workers*) or
split in 2 stages (*autofp*).

A pipeline is created by Suricata's ``RunMode`` and stored in per thread
`ThreadVars <https://doxygen.openinfosecfoundation.org/threadvars_8h.html#ac6c5d759a1e814014a6a59ae58c594df>`_.

Main Components
===============

- Packet Pool
- Packet Capture Module
- Packet Decode Module
- Flow Worker Module (check the *Engines* chapter for more)

