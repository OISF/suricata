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

    tar xzvf suricata-7.0.0.tar.gz
    cd suricata-7.0.0
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

Windows
"""""""

For building and installing from source on Windows, see :doc:`install/windows`.

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

.. toctree::
   :maxdepth: 1

   install/ubuntu
   install/debian
   install/rpm
   install/other

Suricata is available on various distributions as binary
packages. These offer a convenient way to install and manage Suricata
without compiling from source.

**For Ubuntu systems**:

    See :doc:`install/ubuntu` for detailed instructions on
    installing from PPA repositories.

**For Debian systems**:

    See :doc:`install/debian` for detailed instructions on
    installing from official repositories and backports.

**For RPM-based distributions (CentOS, AlmaLinux, RockyLinux, Fedora, etc)**:

    See :doc:`install/rpm` for detailed instructions on
    installing from COPR repositories.

**For other distributions**:

    See :doc:`install/other` for installation instructions
    for Arch Linux and other distributions.

.. _install-advanced:

Advanced Installation
---------------------

If you are using Ubuntu, you can follow
:doc:`devguide/codebase/installation-from-git`.

For other various installation guides for installing from GIT and for other operating
systems, please check (bear in mind that those may be somewhat outdated):
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation
