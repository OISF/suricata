.. _install-binary-debian:

Debian Package Installation
###########################

Suricata is available in the official Debian repositories for Debian 9
(stretch) and later versions.

.. note:: The following instructions require ``sudo`` to be installed.

In Debian 9 (stretch) and later do::

    sudo apt-get install suricata

In the "stable" version of Debian, Suricata is usually not available in the
latest version. A more recent version is often available from Debian backports,
if it can be built there.

To use backports, the backports repository for the current stable
distribution needs to be added to the system-wide sources list.
For Debian 10 (buster), for instance, run the following as ``root``::

    echo "deb http://http.debian.net/debian buster-backports main" > \
        /etc/apt/sources.list.d/backports.list
    apt-get update
    apt-get install suricata -t buster-backports

After Installation
******************

Building from Source on Debian
*****************************

If you prefer to build Suricata from source on Debian, the `./configure` script allows customization. Run `./configure --help` for the full list. Key options include:

Installation Options
~~~~~~~~~~~~~~~~~~~~
- ``--prefix=PREFIX``: Set install directory (default: /usr/local). Use /usr for system-wide install.
- ``--sysconfdir=DIR``: Config files location (default: PREFIX/etc). E.g., /etc/suricata.

Features
~~~~~~~~
- ``--enable-geoip``: GeoIP support (requires libmaxminddb-dev).
- ``--enable-lua``: Lua scripting (requires lua5.3-dev).
- ``--enable-ebpf``: Enable eBPF support (requires libbpf-dev).

After installing you can proceed to the :ref:`Basic setup`.
