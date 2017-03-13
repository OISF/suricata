IP Reputation Format
====================

Description of IP Reputation file formats. For the configuration see :doc:`ip-reputation-config` and :doc:`ip-reputation-rules` for the rule format.

Categories file
~~~~~~~~~~~~~~~

The categories file provides a mapping between a category number, short name, and long description. It's a simple CSV file:

::


  <id>,<short name>,<description>

Example:

::


  1,BadHosts,Known bad hosts
  2,Google,Known google host

The maximum value for the category id is hard coded at 60 currently.

Reputation file
~~~~~~~~~~~~~~~

The reputation file lists a reputation score for hosts in the categories. It's a simple CSV file:

::


  <ip>,<category>,<reputation score>

The IP is an IPv4 address in the quad-dotted notation. The category is the number as defined in the categories file. The reputation score is the confidence that this IP is in the specified category, represented by a number between 1 and 127 (0 means no data).

Example:

::


  1.2.3.4,1,101
  1.1.1.1,6,88

If an IP address has a score in multiple categories it should be listed in the file multiple times.

Example:

::


  1.1.1.1,1,10
  1.1.1.1,2,10

This lists 1.1.1.1 in categories 1 and 2, each with a score of 10.
