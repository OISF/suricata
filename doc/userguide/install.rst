.. _installation:

Installation
============

Before Suricata can be used it has to be installed. Suricata can be installed
on various distributions using binary packages: :ref:`install-binary-packages`.

For people familiar with compiling their own software, the `Source method` is
recommended.

Advanced users can check the advanced guides, see :ref:`install-advanced`.

Source
------

Installing from the source distribution files gives the most control over the Suricata installation.

Basic steps::

    tar xzvf suricata-6.0.0.tar.gz
    cd suricata-6.0.0
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

.. option:: --enable-geoip

    Enables GeoIP support for detection.


Dependencies
^^^^^^^^^^^^

For Suricata's compilation you'll need the following libraries and their development headers installed::

  libjansson, libpcap, libpcre, libmagic, zlib, libyaml

The following tools are required::

  make gcc (or clang) pkg-config

For full features, also add::

  libnss, libgeoip, liblua5.1, libhiredis, libevent

Rust support::

  rustc, cargo

  Not every distro provides Rust packages yet. Rust can also be installed
  directly from the Rust project itself::

  https://www.rust-lang.org/en-US/install.html

Ubuntu/Debian
"""""""""""""

Minimal::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    make libmagic-dev libjansson libjansson-dev

Recommended::

    apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                    libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    libcap-ng-dev libcap-ng0 make libmagic-dev         \
                    libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev \
                    python-yaml rustc cargo

Extra for iptables/nftables IPS integration::

    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0

For Rust support::

    apt-get install rustc cargo
    cargo install --force --debug --version 0.14.1 cbindgen

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

Fedora
^^^^^^

The following is an example of installing Suricata 6.0 on Fedora. If you wish to install 5.0 instead, change the version in *@oisf/suricata-6.0*.

::

    dnf install dnf-plugins-core
    dnf copr enable @oisf/suricata-6.0
    dnf install suricata

RHEL/CentOS 8 and 7
^^^^^^^^^^^^^^^^^^^

The following is an example of installing Suricata 6.0 on CentOS. If you wish to install 5.0 instead, change the version in *@oisf/suricata-6.0*.

::

    yum install epel-release yum-plugin-copr
    yum copr enable @oisf/suricata-6.0
    yum install suricata

.. _install-advanced:

Advanced Installation
---------------------

Various installation guides for installing from GIT and for other operating systems are maintained at:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation
