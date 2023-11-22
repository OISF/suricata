==============
Support Status
==============

Levels of Support
=================

The support tiers detailed below do not represent a binding
commitment. Instead, they serve as a framework that the OISF employs
to prioritize features and functionality.

Tier 1
------

Tier 1 supported items are developed and supported by the Suricata
team. These items receive full CI (continuous integration)
coverage, and functional failures block git merges and releases. Tier
1 features are enabled by default on platforms that support the
feature.

Tier 2
------

Tier 2 supported items are developed and supported by the Suricata
team, sometimes with help from community members. Major functional
failures block git merges and releases, however less major issues
may be documented as "known issues" and may go into a release. Tier 2
features and functionality may be disabled by default.

Community
---------

When a feature of Suricata is community supported, it means the
OISF/Suricata development team won’t directly support it. This is to
avoid overloading the team.

When accepting a feature into the code base anyway, it will come with
a number of limits and conditions:

* submitter must commit to maintaining it:

  - make sure code compiles and correctly functions after Suricata
    and/or external (e.g. library) changes.
  - support users when they encounter problems on forum and
    redmine tickets.

* the code will be disabled by default and will not become part of the
  QA setup. This means it will be enabled only by an ``--enable``
  configure flag.

* the code may not have CI coverage by the OISF infrastructure.

If the feature gets lots of traction, and/or if the team just
considers it very useful, it may get ‘promoted’ to being officially
supported.

On the other hand, the feature will be removed if the submitter stops
maintaining it and no-one steps up to take over.

Vendor
------

Vendor supported features are features specific to a certain vendor
and usually require software and/or hardware from that vendor. While
these features may exist in the main Suricata code, they rely on
support from the vendor to keep the feature in a functional state.

Vendor supported functionality will generally not have CI or QA
coverage by the OISF.

Unmaintained
------------

When a feature is unmaintained it is very likely broken and may be
(partially) removed during cleanups and code refactoring. No end-user
support is done by the core team. If someone wants to help maintain
and support such a feature, we recommend talking to the core team
before spending a lot of time on it.

Please see :doc:`devguide/contributing/contribution-process`
for more information if you wish to contribute.

Distributions
=============

Tier 1
------

These tier 1 supported Linux distributions and operating systems
receive full CI and QA, as well as documentation.

.. table::
   :widths: 20 15 15 10 40
   :width: 100%

   +------------------+-------------+----------+-------+--------------------------------+
   |Distribution      |Version      |Support   |QA     |Notes                           |
   +==================+=============+==========+=======+================================+
   |RHEL/CentOS       |7            |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |RHEL/Alma/Rocky   |8            |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |RHEL/Alma/Rocky   |9            |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |Ubuntu            |20.04        |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |Ubuntu            |22.04        |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |Debian            |10 (Buster)  |OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |Debian            |11 (Bullseye)|OISF      |       |Foundation of SELKS             |
   +------------------+-------------+----------+-------+--------------------------------+
   |Debian            |12 (Bookworm)|OISF      |       |                                |
   +------------------+-------------+----------+-------+--------------------------------+
   |FreeBSD           |12           |OISF      |       |Foundation of OPNsense, pfSense |
   +------------------+-------------+----------+-------+--------------------------------+
   |FreeBSD           |13           |OISF      |       |Foundation of OPNSense          |
   +------------------+-------------+----------+-------+--------------------------------+

Tier 2
------

These tier 2 supported Linux distributions and operating systems
receive CI but not full QA (functional testing).

.. table::
   :widths: 20 15 15 10 40
   :width: 100%

   +------------------+----------+----------+-------+--------------------------------+
   |Distribution      |Version   |Support   |QA     |Notes                           |
   +==================+==========+==========+=======+================================+
   |CentOS            |Stream    |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+
   |Fedora            |Active    |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+
   |OpenBSD           |7.2       |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+
   |OpenBSD           |7.1       |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+
   |OSX/macOS         |??        |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+
   |Windows/MinGW64   |          |OISF      |       |                                |
   +------------------+----------+----------+-------+--------------------------------+

Architecture Support
====================

Tier 1
------

.. table::
   :widths: 15 15 30 40
   :width: 100%

   +-------------+-------------+-------------+-------------+
   |Architecture |Support      |QA           |Notes        |
   +=============+=============+=============+=============+
   |x86_64       |OISF         |             |             |
   +-------------+-------------+-------------+-------------+
   |ARM8-64bit   |OISF         |             |             |
   +-------------+-------------+-------------+-------------+

Tier 2
------

.. table::
   :widths: 15 15 30 40
   :width: 100%

   +-------------+-------------+-------------+-------------+
   |Architecture |Support      |QA           |Notes        |
   +=============+=============+=============+=============+
   |ARM7-32bit   |OISF         |             |             |
   +-------------+-------------+-------------+-------------+
   |i386         |OISF         |             |             |
   +-------------+-------------+-------------+-------------+

Community
---------

.. table::
   :widths: 15 15 30 40
   :width: 100%

   +-------------+-------------+---------------------------+---------------------------------------------+
   |Architecture |Support      |QA                         |Notes                                        |
   +=============+=============+===========================+=============================================+
   |PPC64el      |             |Part of Fedora automated QA|Access can be arranged through IBM dev cloud |
   +-------------+-------------+---------------------------+---------------------------------------------+
   |PPC64        |             |                           |No access to working hardware                |
   +-------------+-------------+---------------------------+---------------------------------------------+
   |PPC32        |             |                           |No access to working hardware                |
   +-------------+-------------+---------------------------+---------------------------------------------+
   |RISC-V       |             |                           |                                             |
   +-------------+-------------+---------------------------+---------------------------------------------+

High Level Features
-------------------

Capture support
~~~~~~~~~~~~~~~

Tier 1
^^^^^^

.. table::
   :width: 100%

   +----------------+-------------------------+----+-----------------------------+
   | Capture Type   | Maintainer              | QA | Notes                       |
   +================+=========================+====+=============================+
   |AF_PACKET       |OISF                     |    |Used by Security Onion, SELKS|
   +----------------+-------------------------+----+-----------------------------+
   |NETMAP (FreeBSD)|OISF                     |    |Used by OPNsense, PFsense    |
   +----------------+-------------------------+----+-----------------------------+
   |NFQUEUE         |OISF                     |    |                             |
   +----------------+-------------------------+----+-----------------------------+
   |libpcap         |OISF                     |    |                             |
   +----------------+-------------------------+----+-----------------------------+

Tier 2
^^^^^^

.. table::
   :width: 100%

   +--------------------+-------------------------+----+---------------+
   |Capture Type        |Maintainer               |QA  |Notes          |
   +====================+=========================+====+===============+
   |PF_RING             |OISF                     |    |               |
   +--------------------+-------------------------+----+---------------+
   |NETMAP (Linux)      |OISF                     |    |               |
   +--------------------+-------------------------+----+---------------+
   |DPDK                |OISF                     |    |               |
   +--------------------+-------------------------+----+---------------+
   |AF_PACKET (eBPF/XDP)|OISF                     |    |               |
   +--------------------+-------------------------+----+---------------+

Community
^^^^^^^^^

.. table::
   :width: 100%

   +--------------------+--------------------------+----+---------------+
   |Capture Type        |Maintainer                |QA  |Notes          |
   +====================+==========================+====+===============+
   |NFLOG               |Community                 |    |               |
   +--------------------+--------------------------+----+---------------+
   |AF_XDP              |Community                 |    |               |
   +--------------------+--------------------------+----+---------------+

Vendor
^^^^^^

.. table::
   :width: 100%

   +--------------------+--------------------------+----+---------------+
   |Capture Type        |Maintainer                |QA  |Notes          |
   +====================+==========================+====+===============+
   |Napatech            |Napatech / Community      |    |               |
   +--------------------+--------------------------+----+---------------+

Unmaintained
^^^^^^^^^^^^

.. table::
   :width: 100%

   +---------------+-------------------------+----+---------------+
   |Capture Type   |Maintainer               |QA  |Notes          |
   +===============+=========================+====+===============+
   |IPFW           |                         |    |               |
   +---------------+-------------------------+----+---------------+
   |Endace/DAG     |                         |    |               |
   +---------------+-------------------------+----+---------------+

Operation modes
~~~~~~~~~~~~~~~

Tier 1
^^^^^^

.. table::
   :width: 100%
   :widths: 25 25 10 40

   +-----------------+------------------------+------+--------------------------------+
   |Mode             |Maintainer              |QA    |Notes                           |
   +=================+========================+======+================================+
   |IDS (passive)    |OISF                    |      |                                |
   +-----------------+------------------------+------+--------------------------------+
   |IPS (active)     |OISF                    |      |                                |
   +-----------------+------------------------+------+--------------------------------+
   |Offline pcap file|OISF                    |      |                                |
   +-----------------+------------------------+------+--------------------------------+

Tier 2
^^^^^^

.. table::
   :width: 100%
   :widths: 25 25 10 40

   +-----------------+------------------------+------+--------------------------------+
   |Mode             |Maintainer              |QA    |Notes                           |
   +=================+========================+======+================================+
   |Unix socket mode |OISF                    |      |                                |
   +-----------------+------------------------+------+--------------------------------+
   |IDS (active)     |OISF                    |      |Active responses, reject keyword|
   +-----------------+------------------------+------+--------------------------------+
