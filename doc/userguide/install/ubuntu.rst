.. _install-binary-ubuntu:

Ubuntu Package Installation
###########################

For Ubuntu, the OISF maintains a Personal Package Archive (PPA)
``suricata-stable`` that always contains the latest stable release.

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
*********

To upgrade::

    sudo apt-get update
    sudo apt-get upgrade suricata

Remove
******

To remove Suricata from your system::

    sudo apt-get remove suricata

Getting Debug or Pre-release Versions
*************************************

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
**************

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

After Installation
******************

After installing you can proceed to the :ref:`Basic setup`.
