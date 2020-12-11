:orphan: Document not referenced in a toctree, so add this.

.. _unified2-removed:

Unified2 Output Removed
-----------------------

As of Suricata 6.0 the Unified2 output has been removed. The legacy
Unified2 format lacks the flexibility found in the Eve format, and is
considerably more difficult to integrate with other tools.  The
current recommended output is :ref:`eve`.

Packet (Payload) Logging
------------------------

By default, Eve does not log the packet or payload like Unified2
does. This can be done with Eve by enabling the payload in Eve alert
logs. This will log the payload in base64 format to be compatible with
the JSON format of Eve logs.

It is important to note that while Eve does have an option to log the
packet, it is the payload option that provides the equivalent data to
that of the Unified2 output.

Migration Tools
---------------

Meer
~~~~

Meer is an Eve log processing tool that can process Eve logs and
insert them into a database that is compatible with Barnyard2. This
could could be used as a Barnyard2 replacement if your use of Unified2
was to have Suricata events added this style of database for use with
tools such as Snorby and BASE.

More information on Meer can be found at its GitHub project page:
`https://github.com/beave/meer <https://github.com/beave/meer>`_.

.. note:: Please note that Meer is not supported or maintained by the
          OISF or the Suricata development team.
