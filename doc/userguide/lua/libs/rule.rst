Rule
====

Rule details for an alert are exposed to Lua scripts with the
``suricata.rule`` library, for example::

  local rule = require("suricata.rule")

Rule Setup
----------

For use in Suricata Lua rules, no additional setup is required.

Output Setup
------------

For use in Suricata Lua output scripts, some additional setup is
required::

  function init(args)
      return {
          type = "packet",
          filter = "alerts",
      }
  end

Getting a Rule Instance
-----------------------

To obtain a rule object, use the ``get_rule()`` function on the
``rule`` library::

  local sig = rule.get_rule()

Rule Methods
------------

``action()``
^^^^^^^^^^^^

Returns the action of the rule, for example: `alert`, `pass`.

``class_description()``
^^^^^^^^^^^^^^^^^^^^^^^

Returns the classification description.

``gid()``
^^^^^^^^^

Returns the generator ID of the rule.

``rev()``
^^^^^^^^^

Returns the revision of the rule.

``msg()``
^^^^^^^^^

Returns the rule message (``msg``).

``priority``
^^^^^^^^^^^^

Returns the priority of the rule as a number.

``sid()``
^^^^^^^^^

Returns the signature ID of the rule.
