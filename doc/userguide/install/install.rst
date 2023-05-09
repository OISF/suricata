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

  libjansson, libpcap, libpcre2, libmagic, zlib, libyaml

The following tools are required::

  make gcc (or clang) pkg-config

For full features, also add::

  libgeoip, liblua5.1, libhiredis, libevent

Rust support::

  rustc, cargo

  Not every distro provides Rust packages yet. Rust can also be installed
  directly from the Rust project itself::

  https://www.rust-lang.org/en-US/install.html

Ubuntu/Debian
"""""""""""""

Minimal::

    apt-get install build-essential libpcap-dev   \
                    libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    make libmagic-dev libjansson libjansson-dev libpcre2-dev

Recommended::

    apt-get install build-essential libpcap-dev   \
                    libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    libcap-ng-dev libcap-ng0 make libmagic-dev         \
                    libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev \
                    python-yaml rustc cargo libpcre2-dev

Extra for iptables/nftables IPS integration::

    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0

For Rust support::

    apt-get install rustc cargo
    cargo install --force --debug --version 0.14.1 cbindgen

Installation from Binary Packages
---------------------------------

Check :ref:`install-binary-packages` for more on installing Suricata from
binaries.

.. _install-advanced:

Advanced Installation
---------------------

Various installation guides for installing from GIT and for other operating systems are maintained at:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation
