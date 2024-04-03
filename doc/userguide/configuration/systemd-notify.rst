systemd notification
====================

Introduction
------------
Suricata supports systemd notification with the aim of notifying the service manager of successful
initialisation. The purpose is to enable the ability to start upon/await successful start-up for
services/test frameworks that depend on a fully initialised Suricata .

During the initialisation phase Suricata synchronises the initialisation thread with all active
threads to ensure they are in a running state. Once synchronisation has been completed a ``READY=1``
status notification is sent to the service manager using across the Systemd UNIX socket.

The path of the UNIX socket is taken from the ``NOTIFY_SOCKET`` env var.

Example
-------
A test framework requires Suricata to be capturing before the tests can be carried out.
Writing a ``test.service`` and ensuring the correct execution order with ``After=suricata.service``
forces the unit to be started after ``suricata.service``. This does not enforce Suricata has fully
initialised. By configuring ``suricata.service`` as ``Type=notify`` instructs the service manager
to wait for the notification before starting ``test.service``.

Requirements
------------
This feature is only supported for distributions under the following conditions:

1. Any distribution that runs under **systemd**
2. Unit file configuration: ``Type=notify``

For notification to the service manager the unit file must be configured as shown in requirement [2].
Upon all requirements being met the service manager will start and await
``READY=1`` status from Suricata. Otherwise the service manager will treat the service unit as
``Type=simple`` and consider it started immediately after the main process ``ExecStart=`` has been
forked.

Additional Information
----------------------
To confirm the system is running under systemd::

    ps --no-headers -o comm 1

See https://www.freedesktop.org/software/systemd/man/systemd.service.html for help
writing systemd unit files.

See https://www.freedesktop.org/software/systemd/man/devel/sd_notify.html#Notes for a discussion of
the UNIX socket based notification.
