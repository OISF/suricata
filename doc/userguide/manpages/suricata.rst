Suricata
========

SYNOPSIS
--------

**suricata** [OPTIONS] [BPF FILTER]

DESCRIPTION
-----------

Suricata is a high performance Network IDS, IPS and Network Security
Monitoring engine. Open Source and owned by a community run non-profit
foundation, the Open Information Security Foundation (OISF).

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

BUGS
----

Please visit Suricata's support page for information about submitting
bugs or feature requests.

NOTES
-----

* Suricata Home Page

    https://suricata-ids.org/

* Suricata Support Page

    https://suricata-ids.org/support/
