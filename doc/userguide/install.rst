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

.. option:: --enable-dpdk

    Enables `DPDK <https://www.dpdk.org/>` packet capture method.

Dependencies
^^^^^^^^^^^^

For Suricata's compilation you'll need the following libraries and their development headers installed::

  libjansson, libpcap, libpcre2, libyaml, zlib

The following tools are required::

  make gcc (or clang) pkg-config rustc cargo

Rust support::

  rustc, cargo

  Some distros don't provide or provide outdated Rust packages.
  Rust can also be installed directly from the Rust project itself::

    1) Install Rust https://www.rust-lang.org/en-US/install.html
    2) Install cbindgen - if the cbindgen is not found in the repository
       or the cbindgen version is lower than required, it can be
       alternatively installed as: cargo install --force cbindgen
    3) Make sure the cargo path is within your PATH environment
        e.g. echo 'export PATH=”${PATH}:~/.cargo/bin”' >> ~/.bashrc
        e.g. export PATH="${PATH}:/root/.cargo/bin"

Ubuntu/Debian
"""""""""""""

Minimal::

    # Installed Rust and cargo as indicated above
    apt-get install build-essential git libjansson-dev libpcap-dev \
                    libpcre2-dev libtool libyaml-dev make pkg-config zlib1g-dev
    # On most distros installing cbindgen with package manager should be enough
    apt-get install cbindgen # alternative: cargo install --force cbindgen

Recommended::

    # Installed Rust and cargo as indicated above
    apt-get install autoconf automake build-essential ccache clang curl git \
                    gosu jq libbpf-dev libcap-ng0 libcap-ng-dev libelf-dev \
                    libevent-dev libgeoip-dev libhiredis-dev libjansson-dev \
                    liblua5.1-dev libmagic-dev libnet1-dev libpcap-dev \
                    libpcre2-dev libtool libyaml-0-2 libyaml-dev m4 make \
                    pkg-config python3 python3-dev python3-yaml sudo zlib1g \
                    zlib1g-dev
    cargo install --force cbindgen

Extra for iptables/nftables IPS integration::

    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0

CentOS, AlmaLinux, RockyLinux, Fedora, etc
""""""""""""""""""""""""""""""""""""""""""

To install all minimal dependencies, it is required to enable extra package
repository in most distros. You can enable it possibly by
one of the following ways::

    dnf -y update
    dnf -y install dnf-plugins-core
    # AlmaLinux 8
    dnf config-manager --set-enabled powertools
    # AlmaLinux 9
    dnf config-manager --set-enable crb
    # Oracle Linux 8
    dnf config-manager --set-enable ol8_codeready_builder
    # Oracle Linux 9
    dnf config-manager --set-enable ol9_codeready_builder

Minimal::

    # Installed Rust and cargo as indicated above
    dnf install -y gcc gcc-c++ git jansson-devel libpcap-devel libtool \
                   libyaml-devel make pcre2-devel which zlib-devel
    cargo install --force cbindgen

Recommended::

    # Installed Rust and cargo as indicated above
    dnf install -y autoconf automake diffutils file-devel gcc gcc-c++ git \
                   jansson-devel jq libcap-ng-devel libevent-devel \
                   libmaxminddb-devel libnet-devel libnetfilter_queue-devel \
                   libnfnetlink-devel libpcap-devel libtool libyaml-devel \
                   lua-devel lz4-devel make nss-devel pcre2-devel pkgconfig \
                   python3-devel python3-sphinx python3-yaml sudo which \
                   zlib-devel
    cargo install --force cbindgen

Compilation
"""""""""""

Follow these steps from your Suricata directory::

    ./scripts/bundle.sh
    ./autogen.sh
    ./configure # you may want to add additional parameters here
    # ./configure --help to get all available parameters
    make -j8 # j is for paralleling, you may de/increase depending on your CPU
    make install # to install your Suricata compiled binary

.. _install-binary-packages:

Binary packages
---------------

Ubuntu
^^^^^^

For Ubuntu, the OISF maintains a PPA ``suricata-stable`` that always contains the latest stable release.

To use it::

    sudo apt-get install software-properties-common
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

CentOS, AlmaLinux, RockyLinux, Fedora, etc
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

RPMs are provided for the latest release of *Enterprise Linux*. This
includes CentOS Linux and rebuilds such as AlmaLinux and RockyLinux.
Additionally, RPMs are provided for the latest supported versions of Fedora.

RPMs specifically for CentOS Stream are not provided, however the RPMs for their
related version may work fine.

Installing From Package Repositories
""""""""""""""""""""""""""""""""""""

CentOS, RHEL, AlmaLinux, RockyLinux, etc Version 8+
'''''''''''''''''''''''''''''''''''''''''''''''''''

.. code-block:: none

   dnf install epel-release dnf-plugins-core
   dnf copr enable @oisf/suricata-7.0
   dnf install suricata

CentOS 7
''''''''

.. code-block:: none

   yum install epel-release yum-plugin-copr
   yum copr enable @oisf/suricata-7.0
   yum install suricata

Fedora
''''''

.. code-block:: none

    dnf install dnf-plugins-core
    dnf copr enable @oisf/suricata-7.0
    dnf install suricata

Additional Notes for RPM Installations
""""""""""""""""""""""""""""""""""""""

- Suricata is pre-configured to run as the ``suricata`` user.
- Command line parameters such as providing the interface names can be
  configured in ``/etc/sysconfig/suricata``.
- Users can run ``suricata-update`` without being root provided they
  are added to the ``suricata`` group.
- Directories:

  - ``/etc/suricata``: Configuration directory
  - ``/var/log/suricata``: Log directory
  - ``/var/lib/suricata``: State directory rules, datasets.

Starting Suricata On-Boot
'''''''''''''''''''''''''

The Suricata RPMs are configured to run from Systemd.

To start Suricata::

  systemctl start suricata

To stop Suricata::

  systemctl stop suricata

To have Suricata start on-boot::

  systemctl enable suricata

To reload rules::

   systemctl reload suricata

.. _install-advanced:

Arch Based
^^^^^^^^^^

The ArchLinux AUR contains Suricata and suricata-nfqueue packages, with commonly
used configurations for compilation (may also be edited to your liking). You may
use makepkg, yay (sample below), or other AUR helpers to compile and build
Suricata packages.

::

    yay -S suricata

Advanced Installation
---------------------

Various installation guides for installing from GIT and for other operating systems are maintained at:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation
