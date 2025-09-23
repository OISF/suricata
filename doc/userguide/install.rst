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

The Suricata source distribution files should be verified before building
the source, see :doc:`verifying-source-files`.

Basic steps::

    tar xzvf suricata-7.0.5.tar.gz
    cd suricata-7.0.5
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

    Enables `DPDK <https://www.dpdk.org/>`_ packet capture method.

Dependencies and compilation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ubuntu/Debian
"""""""""""""

.. note:: The following instructions require ``sudo`` to be installed.

.. literalinclude:: ../../scripts/docs-ubuntu-debian-minimal-build.sh
    :caption: Minimal dependencies for Ubuntu/Debian
    :language: bash
    :start-after: # install-guide-documentation tag start: Minimal dependencies
    :end-before: # install-guide-documentation tag end: Minimal dependencies

CentOS, AlmaLinux, RockyLinux, Fedora, etc
""""""""""""""""""""""""""""""""""""""""""

.. note:: The following instructions require ``sudo`` to be installed.

To install all minimal dependencies, it is required to enable extra package
repository in most distros. You can enable it possibly by
one of the following ways::

    sudo dnf -y update
    sudo dnf -y install epel-release dnf-plugins-core
    # AlmaLinux 8 / RockyLinux 8
    sudo dnf config-manager --set-enabled powertools
    # AlmaLinux 9 / RockyLinux 9
    sudo dnf config-manager --set-enable crb
    # Oracle Linux 8
    sudo dnf config-manager --set-enable ol8_codeready_builder
    # Oracle Linux 9
    sudo dnf config-manager --set-enable ol9_codeready_builder

.. literalinclude:: ../../scripts/docs-almalinux9-minimal-build.sh
    :caption: Minimal dependencies for RPM-based distributions
    :language: bash
    :start-after: # install-guide-documentation tag start: Minimal RPM-based dependencies
    :end-before: # install-guide-documentation tag end: Minimal RPM-based dependencies

Compilation
"""""""""""

Follow these steps from your Suricata directory::

    ./configure # you may want to add additional parameters here
    # ./configure --help to get all available parameters
    # j is for adding concurrency to make; the number indicates how much 
    # concurrency so choose a number that is suitable for your build system
    make -j8 
    make install # to install your Suricata compiled binary
    # make install-full - installs configuration and rulesets as well

Rust support
""""""""""""

  Rust packages can be found in package managers but some distributions
  don't provide Rust or provide outdated Rust packages.
  In case of insufficient version you can install Rust directly
  from the Rust project itself::

    1) Install Rust https://www.rust-lang.org/en-US/install.html
    2) Install cbindgen - if the cbindgen is not found in the repository
       or the cbindgen version is lower than required, it can be
       alternatively installed as: cargo install --force cbindgen
    3) Make sure the cargo path is within your PATH environment
       echo 'export PATH="~/.cargo/bin:${PATH}"' >> ~/.bashrc
       export PATH="~/.cargo/bin:${PATH}"

Auto-Setup
^^^^^^^^^^

You can also use the available auto-setup features of Suricata:

::

    ./configure && make && sudo make install-conf

*make install-conf* would do the regular "make install" and then it would automatically
create/setup all the necessary directories and ``suricata.yaml`` for you.

::

    ./configure && make && sudo make install-rules

*make install-rules* would do the regular "make install" and then it would automatically
download and set up the latest ruleset from Emerging Threats available for Suricata.

::

    ./configure && make && sudo make install-full

*make install-full* would combine everything mentioned above (install-conf and install-rules)
and will present you with a ready-to-run (configured and set-up) Suricata.

.. _install-binary-packages:

Binary packages
---------------

Ubuntu from Personal Package Archives (PPA)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For Ubuntu, OISF maintains a PPA ``suricata-stable`` that always contains the
latest stable release.

.. note:: The following instructions require ``sudo`` to be installed.

Setup to install the latest stable Suricata::

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt-get update

Then, you can install the latest stable with::

    sudo apt-get install suricata

After installing you can proceed to the :ref:`Basic setup`.

`OISF launchpad: suricata-stable <https://launchpad.net/~oisf/+archive/suricata-stable>`_.

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

.. note:: The following instructions require ``sudo`` to be installed.

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

.. note:: The following instructions require ``sudo`` to be installed.

If you would like to help test the daily build packages from our latest git(dev)
repository, the same procedures as above apply, just using another PPA,
``suricata-daily``::

    sudo add-apt-repository ppa:oisf/suricata-daily-allarch
    sudo apt-get update
    sudo apt-get upgrade

.. note::

    Please have in mind that this is packaged from our latest development git main
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

.. _RPM packages:

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

.. note:: The following instructions require ``sudo`` to be installed.

.. code-block:: none

   sudo dnf install epel-release dnf-plugins-core
   sudo dnf copr enable @oisf/suricata-7.0
   sudo dnf install suricata

CentOS 7
''''''''

.. code-block:: none

   sudo yum install epel-release yum-plugin-copr
   sudo yum copr enable @oisf/suricata-7.0
   sudo yum install suricata

Fedora
''''''

.. code-block:: none

    sudo dnf install dnf-plugins-core
    sudo dnf copr enable @oisf/suricata-7.0
    sudo dnf install suricata

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

.. note:: The following instructions require ``sudo`` to be installed.

To start Suricata::

  sudo systemctl start suricata

To stop Suricata::

  sudo systemctl stop suricata

To have Suricata start on-boot::

  sudo systemctl enable suricata

To reload rules::

  sudo systemctl reload suricata

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

If you are using Ubuntu, you can follow
:doc:`devguide/codebase/installation-from-git`.

For other various installation guides for installing from GIT and for other operating
systems, please check (bear in mind that those may be somewhat outdated):
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation
