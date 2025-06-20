.. _install-binary-rpm:

RPM Installation
################

Using the Fedora COPR system, the OISF provides Suricata packages for
Fedora, Red Hat Enterprise Linux, and Enterprise Linux rebuilds.

The benefit of using the OISF maintained COPR package repositories is
that the OISF maintains packages for all non-EOL Suricata versions for
each distribution version. For example, the OISF maintains Suricata 7
and Suricata 8 packages for RHEL 9 and 10.

Installing From Package Repositories
************************************

.. note:: Instructions in the following sections require ``sudo`` to
          be installed.

Enterprise Linux and Rebuilds
=============================

.. code-block:: none

   sudo dnf install epel-release dnf-plugins-core
   sudo dnf copr enable @oisf/suricata-8.0
   sudo dnf install suricata

Fedora
======

.. code-block:: none

    sudo dnf install dnf-plugins-core
    sudo dnf copr enable @oisf/suricata-8.0
    sudo dnf install suricata

Additional Notes for RPM Installations
**************************************

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
=========================

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

After Installation
******************

After installing you can proceed to the :ref:`Basic setup`.
