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

``sid()``
^^^^^^^^^

Returns the signature ID of the rule.

``gid()``
^^^^^^^^^

Returns the generator ID of the rule.

``rev()``
^^^^^^^^^

Returns the revision of the rule.

``action()``
^^^^^^^^^^^^

Returns the action of the rule, for example: `alert`, `pass`.

``msg()``
^^^^^^^^^

Returns the rule message (``msg``).

``class()``
^^^^^^^^^^^

Returns the classification name, as well as priority for the rule. For
example::

  local r = rule.get_rule()
  local class, prio = r:class()
