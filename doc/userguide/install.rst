Installation
============

Before Suricata can be used it has to be installed. Suricata can be installed
on various distributions using binary packages: :ref:`install-binary-packages`.

For people familiar with compiling their own software, the Source method is
recommended.

Advanced users can check the advanced guides, see :ref:`install-advanced`.

Source
------

Installing from the source distribution files gives the most control over the Suricata installation.

Basic steps::

    tar xzvf suricata-4.0.0.tar.gz
    cd suricata-4.0.0
    ./configure
    make
    make install

This will install Suricata into ``/usr/local/bin/``, use the default
configuration in ``/usr/local/etc/suricata/`` and will output to
``/usr/local/var/log/suricata``


Common configure options
^^^^^^^^^^^^^^^^^^^^^^^^

.. option:: --disable-gccmarch-native

    Do not optimize the binary for the hardware it is built on. Add this 
    flag if the binary is meant to be portable or if Suricata is to be used in a VM.

.. option:: --prefix=/usr/

    Installs the Suricata binary into /usr/bin/. Default ``/usr/local/``

.. option:: --sysconfdir=/etc

    Installs the Suricata configuration files into /etc/suricata/. Default ``/usr/local/etc/``

.. option:: --localstatedir=/var

    Setups Suricata for logging into /var/log/suricata/. Default ``/usr/local/var/log/suricata``

.. option:: --enable-lua

    Enables Lua support for detection and output.

.. option:: --enable-geopip

    Enables GeoIP support for detection.

.. option:: --enable-rust

    Enables experimental Rust support

Dependencies
^^^^^^^^^^^^

For Suricata's compilation you'll need the following libraries and their development headers installed:

  libpcap, libpcre, libmagic, zlib, libyaml

The following tools are required:

  make gcc (or clang) pkg-config

For full features, also add:

  libjansson, libnss, libgeoip, liblua5.1, libhiredis, libevent

Rust support (experimental):

  rustc, cargo

Ubuntu/Debian
"""""""""""""

Minimal::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    make libmagic-dev

Recommended::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev        \
                    libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev

Extra for iptables/nftables IPS integration::

    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0

For Rust support (Ubuntu only)::

    apt-get install rustc cargo

.. _install-binary-packages:

Binary packages
---------------

Ubuntu
^^^^^^

For Ubuntu, the OISF maintains a PPA ``suricata-stable`` that always contains the latest stable release.

To use it::

    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt-get update
    sudo apt-get install suricata

Debian
^^^^^^

In Debian 9 (Stretch) do::

    apt-get install suricata

In Debian Jessie Suricata is out of date, but an updated version is in Debian Backports.

As root do::

    echo "deb http://http.debian.net/debian jessie-backports main" > \
        /etc/apt/sources.list.d/backports.list
    apt-get update
    apt-get install suricata -t jessie-backports

Fedora
^^^^^^

::

    dnf install suricata

RHEL/CentOS
^^^^^^^^^^^

For RedHat Enterprise Linux 7 and CentOS 7 the EPEL repository can be used.

::

    yum install epel-release
    yum install suricata


.. _install-advanced:

Advanced Installation
---------------------

Various installation guides for installing from GIT and for other operating systems are maintained at:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation

