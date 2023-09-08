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


Dependencies and compilation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ubuntu/Debian
"""""""""""""

Minimal::

    apt-get install build-essential cargo cbindgen git libjansson-dev \ 
                    libpcap-dev libpcre3-dev libtool libyaml-dev make \
                    pkg-config rustc zlib1g-dev

Recommended::

    apt-get install build-essential cargo cbindgen clang git jq libbpf-dev \
                    libcap-ng-dev libevent-dev libgeoip-dev libhiredis-dev \
                    libhyperscan-dev libjansson-dev liblua5.1-dev liblz4-dev \
                    libmagic-dev libmagic-dev libmaxminddb-dev libnet-dev \
                    libnetfilter-queue-dev libnspr4-dev libnss3-dev \
                    libpcap-dev libpcre3-dev libtool libyaml-dev make \
                    pkg-config python3 python3-dev python3-yaml rustc zlib1g-dev

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
    # AlmaLinux 8 / RockyLinux 8
    dnf config-manager --set-enabled powertools
    # AlmaLinux 9 / RockyLinux 9
    dnf config-manager --set-enable crb
    # Oracle Linux 8
    dnf config-manager --set-enable ol8_codeready_builder
    # Oracle Linux 9
    dnf config-manager --set-enable ol9_codeready_builder

Minimal::

    dnf install -y rustc cargo
    cargo install --force cbindgen # can be run as a non-root
    # Make sure the cargo path is within your PATH environment e.g.:
    echo 'export PATH=”${PATH}:~/.cargo/bin”' >> ~/.bashrc
    export PATH="${PATH}:~/.cargo/bin"
    dnf install -y gcc gcc-c++ git jansson-devel libpcap-devel libtool \
                   libyaml-devel make pcre-devel which zlib-devel

Recommended::

    # Minimal dependencies installed and then
    dnf install -y epel-release
    dnf install -y clang file-devel hiredis-devel hyperscan-devel \ 
                    jansson-devel jq libbpf-devel libcap-ng-devel \
                    libevent-devel libmaxminddb-devel libnet-devel \
                    libnetfilter_queue-devel libnfnetlink-devel libpcap-devel \
                    libtool libyaml-devel llvm-toolset lua-devel \
                    lz4-devel make nspr-devel nss-devel pcre-devel \
                    pkgconfig python3-devel python3-sphinx python3-yaml \
                    zlib-devel

Compilation
"""""""""""

Follow these steps from your Suricata directory::

    ./configure # you may want to add additional parameters here
    # ./configure --help to get all available parameters
    # Recommended parameters:
    CC=clang ./configure --enable-ebpf --enable-ebpf-build --enable-nfqueue \
        --enable-dpdk --enable-http2-decompression --enable-unix-socket \
        --enable-af-packet --enable-libmagic --enable-lua --enable-geoip \
        --enable-hiredis
    make -j8 # j is for simultaneous compilation, number can be de/increased based on your CPU
    make install # to install your Suricata compiled binary
    # make install-full - installs configuration and rulesets as well

Rust support
""""""""""""

  Rust packages can be found in package managers but some distros
  don't provide or provide outdated Rust packages.
  In case of insufficient version you can install Rust directly
  from the Rust project itself::

    1) Install Rust https://www.rust-lang.org/en-US/install.html
    2) Install cbindgen - if the cbindgen is not found in the repository
       or the cbindgen version is lower than required, it can be
       alternatively installed as: cargo install --force cbindgen
    3) Make sure the cargo path is within your PATH environment
        e.g. echo 'export PATH=”${PATH}:~/.cargo/bin”' >> ~/.bashrc
        e.g. export PATH="${PATH}:~/.cargo/bin"

.. _install-binary-packages:

Binary packages
---------------

Ubuntu from Personal Package Archives (PPA)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For Ubuntu, OISF maintains a PPA ``suricata-6.0`` that always contains the
latest stable release for Suricata 6.

Setup to install the latest stable Suricata 6::

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:oisf/suricata-6.0
    sudo apt-get update

Then, you can install the latest stable with::

    sudo apt-get install suricata

After installing you can proceed to the :ref:`Basic setup`.

`OISF launchpad: suricata-6.0 <https://launchpad.net/~oisf/+archive/ubuntu/suricata-6.0>`_.

Upgrading
"""""""""

To upgrade::

    sudo apt-get update
    sudo apt-get upgrade suricata

Remove
""""""

To remove Suricata from your system::

    sudo apt-get remove suricata



Getting Debug or Pre-release Versions
"""""""""""""""""""""""""""""""""""""

If you want Suricata with built-in (enabled) debugging, you can install the
debug package::

    sudo apt-get install suricata-dbg

If you would like to help test the Release Candidate (RC) packages, the same procedures
apply, just using another PPA: ``suricata-beta``::

    sudo add-apt-repository ppa:oisf/suricata-beta
    sudo apt-get update
    sudo apt-get upgrade

You can use both the suricata-stable and suricata-beta repositories together.
Suricata will then always be the latest release, stable or beta.

`OISF launchpad: suricata-beta <https://launchpad.net/~oisf/+archive/suricata-beta>`_.

Daily Releases
""""""""""""""

If you would like to help test the daily build packages from our latest git(dev)
repository, the same procedures as above apply, just using another PPA,
``suricata-daily``::

    sudo add-apt-repository ppa:oisf/suricata-daily-allarch
    sudo apt-get update
    sudo apt-get upgrade

.. note::

    Please have in mind that this is packaged from our latest development git master
    and is therefore potentially unstable.

    We do our best to make others aware of continuing development and items
    within the engine that are not yet complete or optimal. With this in mind,
    please refer to `Suricata's issue tracker on Redmine 
    <http://redmine.openinfosecfoundation.org/projects/suricata/issues>`_ 
    for an up-to-date list of what we are working on, planned roadmap, 
    and to report issues.

`OISF launchpad: suricata-daily <https://launchpad.net/~oisf/+archive/suricata-daily>`_.

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
