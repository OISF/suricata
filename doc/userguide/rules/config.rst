Config Rules
============

Config rules are rules that when matching, will change the configuration of
Suricata for a flow, transaction, packet or other unit.

Example::

  config dns any any -> any any (dns.query; content:"suricata"; config: logging disable, type tx, scope tx; sid:1;)

This example will detect if a DNS query contains the string `suricata` and if
so disable the DNS transaction logging. This means that `eve.json` records,
but also Lua output, will not be generated/triggered for this DNS transaction.

Keyword
-------

The `config` rule keyword provides the setting and the scope of the change.

Syntax::

  config:<subsys> <action>, type <type>, scope <scope>;

`subsys` can be set to:

* `logging` setting affects logging.

`type` can be set to:

* `tx` sub type of the `subsys`. If `subsys` is set to `logging`, setting the `type` to `tx` means transaction logging is affected.

`scope` can be set to:

* `tx` setting affects the matching transaction.

The `action` in `<subsys>` is currently limited to `disable`.


Action
------

Config rules can, but don't have to, use the `config` rule action. The `config`
rule action won't generate an alert when the rule matches, but the rule actions
will still be applied. It is equivalent to `alert ... (noalert; ...)`.
