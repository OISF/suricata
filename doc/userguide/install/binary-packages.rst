.. _install-binary-packages:

Binary Packages
===============

Ubuntu
------

For Ubuntu, the OISF maintains a PPA ``suricata-stable`` that always contains the latest stable release.

To use it::

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt-get update
    sudo apt-get install suricata

Debian
------

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
------------------------------------------

RPMs are provided for the latest release of *Enterprise Linux*. This
includes CentOS Linux and rebuilds such as AlmaLinux and RockyLinux.
Additionally, RPMs are provided for the latest supported versions of Fedora.

RPMs specifically for CentOS Stream are not provided, however the RPMs for their
related version may work fine.

Installing From Package Repositories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

CentOS, RHEL, AlmaLinux, RockyLinux, etc Version 8+
"""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: none

   dnf install epel-release dnf-plugins-core
   dnf copr enable @oisf/suricata-7.0
   dnf install suricata

CentOS Linux 7
""""""""""""""

.. code-block:: none

   yum install epel-release yum-plugin-copr
   yum copr enable @oisf/suricata-7.0
   yum install suricata

Fedora
""""""

.. code-block:: none

    dnf install dnf-plugins-core
    dnf copr enable @oisf/suricata-7.0
    dnf install suricata

Additional Notes for RPM Installations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
"""""""""""""""""""""""""

The Suricata RPMs are configured to run from Systemd.

To start Suricata::

  systemctl start suricata

To stop Suricata::

  systemctl stop suricata

To have Suricata start on-boot::

  systemctl enable suricata

To reload rules::

   systemctl reload suricata

