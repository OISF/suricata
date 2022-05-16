Suricata
========

SYNOPSIS
--------

**suricata** [OPTIONS] [BPF FILTER]

DESCRIPTION
-----------

**suricata** is a high performance Network IDS, IPS and Network Security
Monitoring engine. Open Source and owned by a community run non-profit
foundation, the Open Information Security Foundation (OISF).

**suricata** can be used to analyze live traffic and pcap files. It can
generate alerts based on rules. **suricata** will generate traffic logs.

When used with live traffic **suricata** can be passive or active. Active
modes are: inline in a L2 bridge setup, inline with L3 integration with
host filewall (NFQ, IPFW, WinDivert), or out of band using active responses.

OPTIONS
--------------

.. include:: ../partials/options.rst

OPTIONS FOR DEVELOPERS
----------------------

.. include:: ../partials/options-unittests.rst

SIGNALS
-------

Suricata will respond to the following signals:

SIGUSR2

    Causes Suricata to perform a live rule reload.

SIGHUP

    Causes Suricata to close and re-open all log files. This can be
    used to re-open log files after they may have been moved away by
    log rotation utilities.

FILES AND DIRECTORIES
---------------------

|sysconfdir|/suricata/suricata.yaml
    Default location of the Suricata configuration file.

|localstatedir|/log/suricata
    Default Suricata log directory.

EXAMPLES
--------

To capture live traffic from interface `eno1`::

    suricata -i eno1

To analyze a pcap file and output logs to the CWD::

    suricata -r /path/to/capture.pcap

To capture using `AF_PACKET` and override the flow memcap setting from the `suricata.yaml`::

    suricata --af-packet --set flow.memcap=1gb

To analyze a pcap file with a custom rule file::

    suricata -r /pcap/to/capture.pcap -S /path/to/custom.rules

BUGS
----

Please visit Suricata's support page for information about submitting
bugs or feature requests.

NOTES
-----

* Suricata Home Page

    https://suricata.io/

* Suricata Support Page

    https://suricata.io/support/
