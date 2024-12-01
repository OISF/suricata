MySQL Keywords
============

The MySQL keywords are implemented and can be used to match on fields in MySQL messages.

============================== ==================
Keyword                        Direction
============================== ==================
mysql.command                  Request
mysql.rows                     Response
============================== ==================

mysql.command
----------

This keyword matches on the query statement like `select * from xxx where yyy = zzz` found in a MySQL request.

Syntax
~~~~~~

::

  mysql.command; content:<command>;

Examples
~~~~~~~~

::

  mysql.commands; content:"select";

mysql.rows
-------

This keyword matches on the rows which come from query statement result found in a Mysql response.
row format: 1,foo,bar

Syntax
~~~~~~

::

  mysql.rows; content:<rows>;

Examples
~~~~~~~~

::

  mysql.rows; content:"foo,bar";
