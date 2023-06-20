Security Considerations
=======================

Suricata is a security tool that processes untrusted network data, as
well as requiring elevated system privileges to acquire that
data. This combination deserves extra security precautions that we
discuss below.

Additionally, supply chain attacks, particularly around rule
distribution, could potentially target Suricata installations.

Running as a User Other Than Root
---------------------------------

.. note:: If using the Suricata RPMs, either from the OISF COPR repo,
          or the EPEL repo, the following is already configured for
          you. The only thing you might want to do is add your
          management user to the ``suricata`` group.

Many Suricata examples and guides will show Suricata running as the
*root* user, particularly when running on live traffic. As Suricata
generally needs low level read (and in IPS write) access to network
traffic, it is required that Suricata starts as root, however Suricata
does have the ability to drop down to a non-root user after startup,
which could limit the impact of a security vulnerability in Suricata
itself.

.. note:: Currently the ability to drop root privileges after startup
          is only available on Linux systems.

Create User
~~~~~~~~~~~

Before running as a non-root user, you need to choose and possibly
create the user and group that will Suricata will run as. Typically
this user would be a sytem user with the name ``suricata``. Such a
user can be created with the following command::

  useradd --no-create-home --system --shell /sbin/nologin suricata

This will create a user and group with the name ``suricata``.

File System Permissions
~~~~~~~~~~~~~~~~~~~~~~~

Before running Suricata as the user ``suricata``, some directory
permissions will need to be updated to allow the ``suricata`` read and
write access.

Assuming your Suricata was installed from source using the recommended
configuration of::

  ./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/

the following directories will need their permissions updated:

+------------------+-----------+
|Directory         |Permissions|
+==================+===========+
|/etc/suricata     |Read       |
+------------------+-----------+
|/var/log/suricata |Read, Write|
+------------------+-----------+
|/var/lib/suricata |Read, Write|
+------------------+-----------+
|/var/run/suricata |Read, Write|
+------------------+-----------+

The following commands will setup the correct permissions:

* ``/etc/suricata``::

    chgrp -R suricata /etc/suricata
    chmod -R g+r /etc/suricata

* ``/var/log/suricata``::

    chgrp -R suricata /var/log/suricata
    chmod -R g+rw /var/log/suricata

* ``/var/lib/suricata``::

    chgrp -R suricata /var/lib/suricata
    chmod -R g+srw /var/lib/suricata

* ``/var/lib/suricata``::

    chgrp -R suricata /var/run/suricata
    chmod -R g+srw /var/run/suricata

Configure Suricata to Run as ``Suricata``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Suricata can be configured to run as an alternate user by updating the
configuration file or using command line arguments.

* Using the configuration file, update the ``run-as`` section to look like::

    run-as:
      user: suricata
      group: suricata

* Or if using command line arguments, add the following to your command::

    --user suricata --group suricata

Starting Suricata
~~~~~~~~~~~~~~~~~

It is important to note that Suricata still needs to be started with
**root** permissions in most cases. Starting as *root* allows Suricata
to get access to the network interfaces and set the *capabilities*
required during runtime before it switches down to the configured
user.

Other Commands: Suricata-Update, SuricataSC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With the previous permissions setup, ``suricata-update`` and
``suricatasc`` can also be run without root or sudo. To allow a user
to access these commands, add them to the ``suricata`` group.

Containers
----------

Containers such as Docker and Podman are other methods to provide
isolation between Suricata and the host machine running Suricata.
However, we still recommend running as a non-root user, even in
containers.

Capabilities
~~~~~~~~~~~~

For both Docker and Podman the following capabilities should be
provided to the container running Suricata for proper operation::

  --cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice

Podman
~~~~~~

Unfortunately Suricata will not work with *rootless* Podman, this is
due to Suricata's requirement to start with root privileges to gain
access to the network interfaces. However, if started with the above
capabilities, and configured to run as a non-root user, it will drop
root privileges before processing network data.
