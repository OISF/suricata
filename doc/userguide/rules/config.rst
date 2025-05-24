Config Rules
============

Config rules are rules that when matching, will change the configuration of
Suricata for a flow, transaction, packet or other unit.

Example::

  config dns any any -> any any (dns.query; content:"suricata"; config: logging disable, type tx, scope tx; sid:1;)

This example will detect if a DNS query contains the string `suricata` and if
so disable the DNS transaction logging. This means that `eve.json` records,
but also Lua output, will not be generated/triggered for this DNS transaction.

Example::

  config tcp:pre_flow any any <> any 666 (config: tracking disable, type flow, scope packet; sid:1;)

This example skips flow tracking for any packet from or to tcp port 666.

Keyword
-------

The `config` rule keyword provides the setting and the scope of the change.

Syntax::

  config:<subsys> <action>, type <type>, scope <scope>;

`subsys` can be set to:

* `logging` setting affects logging.
* `tracking` setting affects tracking.

`type` can be set to:

* `tx` sub type of the `subsys`. If `subsys` is set to `logging`, setting the `type` to `tx` means transaction logging is affected.
* `flow` sub type of the `subsys`. If `subsys` is set to `flow`, setting the `type` to `flow` means flow tracking is disabled.

`scope` can be set to:

* `tx` setting affects the matching transaction.
* `packet` setting affects the matching packet.

The `action` in `<subsys>` is currently limited to `disable`.


Action
------

Config rules can, but don't have to, use the `config` rule action. The `config`
rule action won't generate an alert when the rule matches, but the rule actions
will still be applied. It is equivalent to `alert ... (noalert; ...)`.
