.. _includes:

Includes
========

A Suricata configuration file (typically
``/etc/suricata/suricata.yaml``) may include other files allowing a
configuration file to be broken into multiple files. The *special*
field name ``include`` is used to include one or more files.

The contents of the *include* file are inlined at the level of the
``include`` statement. *Include* fields may also be included at any
level within a mapping.

Including a Single File
-----------------------

::

    include: filename.yaml

Including Multiple Files
------------------------

::

    include:
      - filename1.yaml
      - filename2.yaml

Include Inside a Mapping
------------------------

::

    vars:
      address-groups:
        include: address-groups.yaml

where ``address-groups.yaml`` contains::
    
    %YAML 1.1
    ---
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

is the equivalent of::

    vars:
      address-groups:
        HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

Glob Patterns
-------------

Filenames in ``include`` may contain shell-style glob metacharacters
(``*``, ``?``, ``[...]``). Patterns are expanded at startup via
``glob(3)`` and each matching file is loaded in lexicographic order. A
pattern that matches no files is logged as a warning and is not treated
as an error, which allows drop-in ``conf.d/``-style directories to be
empty.

::

    include:
      - /etc/suricata/conf.d/*.yaml

Relative patterns are resolved against the directory of the top-level
configuration file, the same as literal includes.

.. note:: Suricata versions less than 7 required multiple ``include``
    statements to be specified to include more than one file. While
    Suricata 7.0 still supports this it will issue a deprecation
    warning. Suricata 8.0 will not allow multiple ``include``
    statements at the same level as this is not allowed by YAML.
