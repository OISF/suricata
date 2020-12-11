Command Line Options
====================

.. toctree::

Suricata's command line options:

.. include:: partials/options.rst

Unit Tests
~~~~~~~~~~

The builtin unittests are only available when Suricata has been configured and built with
``--enable-unittests``.

Running unittests does not require a configuration file. Use -l to supply
an output directory.::

    sudo suricata -u

.. include:: partials/options-unittests.rst
