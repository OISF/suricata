Rule Reloads
============

Suricata was designed to reload rules while it is actively processing
network traffic to minimize service disruption.

Suricata must be administratively directed to reload rules while it is running.

It is also possible to get information about the last reload via dedicated commands.
See :ref:`standard-unix-socket-commands` for more information.

Reload Triggers
~~~~~~~~~~~~~~~
There are multiple ways to trigger a rule reload. ``suricatasc`` is a program distributed with Suricata
that provides client-side services, including the ability to trigger a Suricata rule reload..

Via process signal
------------------

The ``USR2`` signal will cause Suricata to start a rule reload. The signal can be sent from the command
line or from a script/program. Escalation of privileges may be necessary to send the signal.

  $ kill -USR2 $(pidof suricata)

Via the UNIX domain socket
--------------------------

The ``suricatasc`` program has two commands to initiate a Suricata rule reload.

Blocking reload
^^^^^^^^^^^^^^^

This will cause Suricata to reload rules while the caller blocks, or waits.

  suricatasc -c reload-rules

Non-blocking reload
^^^^^^^^^^^^^^^^^^^

This will cause Suricata to reload rules without the caller blocking or waiting.

  suricatasc -c ruleset-reload-nonblocking

.. _rule-reload-windows-service:

Via Windows service control
---------------------------

Windows does not support the ``USR2`` signal or the UNIX domain socket.
Instead, when Suricata is running as a Windows service, a rule reload can be
requested by sending the service the user-defined control code ``128``::

  sc.exe control Suricata 128

This is a non-blocking reload. ``sc.exe`` does not report the result of the
reload; it is logged by Suricata.

When installed with ``--service-install``, only SYSTEM and Administrators may
send control codes to the Suricata service. A service installed by older
versions of Suricata, or by other tools, may allow any interactive user to
send control codes. This can be restricted with::

  sc.exe sdset Suricata "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)"

.. note:: In PowerShell, ``sc`` is an alias for ``Set-Content``, so
          ``sc.exe`` must be used.

Resources Reloaded
~~~~~~~~~~~~~~~~~~

There are two types of resources that are reloaded during a rule reload.

* Rule-related configuration:

  * Suricata's configuration file(s): ``suricata.yaml`` and any specified with the command-line
    options ``--include <config-file.yaml>``. Only rule-related information is reloaded.

    * Rule variables: items in the ``vars`` section.
    * Rule files from the ``rule-files`` section (if the ``-S`` command line option was not used)

  * Ancillary rule-related configuration files: ``classification.config``, ``reference.config``
    and ``threshold.config``

  * Dataset(s) used by rules.

  * When multi-tenants are configured, rule-related configuration information for each tenant.

When to reload rules
~~~~~~~~~~~~~~~~~~~~

Rule reloads are used in situations when:

* Rules have been changed since the last reload. Vendors often add rules frequently and
  sometimes update existing rules. Rules should be reloaded according to a security policy
  that includes Suricata rule and configuration settings.
* Rule variables have been changed. Rule reloads will use rule variables from the Suricata
  configuration file. When updating these, reload the rules in order for the updated rule
  variables to take effect.
* Ancillary rule-related configuration files are updated.

Advanced: Rule Reload Steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~

When reloading rules, Suricata executes the following steps to ensure a safe
and consistent update:

* The main Suricata configuration is reloaded to update rule variables and values,
  including the rule related files ``classification.config``, ``reference.config`` and
  ``theshold.config``.
* All rule files are reloaded with new rule variables applied.
* A new detection engine is created for the updated rules.
* The previous and newly created detection engines are swapped.
* Ensure all threads are updated.
* Free old detection engine and associated resources.

Suricata will continue to process packets during the update process. Note that additional system
memory is used during the reload process as a new detection engine and the reloaded rules are
associated with it.
