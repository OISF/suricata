PGSQL Keywords
##############

.. role:: example-rule-emphasis

pgsql.query
***********

This keyword is a sticky buffer that allows matching on the contents of
PostgreSQL's `query` request messages parsed by the engine. Note that this
buffer inspects only the `string` portion of the PostgreSQL message, skipping
other fields such as identifier and length, and focusing on the query itself.

Currently, it exposes the contents of the ``pgsql.request.simple_query`` field
from EVE output.

``pgsql.query`` can be used as a ``fast_pattern``
(see :ref:`rules-keyword-fast_pattern`).

Use ``nocase`` with this keyword to avoid case sensitivity for the matches.

Examples
========

.. container:: example-rule

    alert pgsql any any -> any any (msg:"Simple SELECT rule";
    :example-rule-emphasis:`pgsql.query; content:"SELECT \*";` sid:1;)

.. container:: example-rule

    alert pgsql any any -> any any (msg:"Simple delete rule";
    :example-rule-emphasis:`pgsql.query; content:"delete"; nocase` sid:2;)
