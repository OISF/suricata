Rule Reloads
============

Suricata was designed to reload rules while it is actively processing
network traffic to minimize service disruption.

Suricata must be administratively directed to reload rules while it is running; there
are two ways to cause this:

* Via a UNIX domain socket with the command ``reload-rules`` or ``ruleset-reload-nonblocking``
* Upon receipt of the ``USR2`` signal

Reload Triggers
~~~~~~~~~~~~~~~
There are multiple ways to trigger a rule reload. Note that the steps using ``suricatasc``
can be done using the suricata`
Via process signal
^^^^^^^^^^^^^^^^^^

  kill -USR2 $(pidof suricata)

Via the UNIX domain socket.

Blocking reload
^^^^^^^^^^^^^^^

  suricatasc -c reload-rules

Non-blocking reload
^^^^^^^^^^^^^^^^^^^

  suricatasc -c ruleset-reload-nonblocking

It is also possible to get information about the last reload via dedicated commands.
See :ref:`standard-unix-socket-commands` for more information.

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

When to reload rules
~~~~~~~~~~~~~~~~~~~~

Rule reloads are used in situations when:

* Rules have been changed since the last reload. Vendors often add rules frequently and
  sometimes update existing rules. Rules should be reloaded according to a security policy
  that includes Suricata rule and configuration settings.
* Rule variables have been changed. Rule reloads will use rule variables from the Suricata
  configuration file.  When updating these, reload the rules in order to the updated rule
  variables take effect.
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
