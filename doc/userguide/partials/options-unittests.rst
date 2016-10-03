.. Options for developers - unittests.

.. option:: -u

   Run the unit tests and exit. Requires that Suricata be compiled
   with *--enable-unittests*.

.. option:: -U, --unittest-filter=REGEX

   With the -U option you can select which of the unit tests you want
   to run. This option uses REGEX.  Example of use: suricata -u -U
   http

.. option:: --list-unittests

   List all unit tests.

.. option:: --fatal-unittests

   Enables fatal failure on a unit test error. Suricata will exit
   instead of continuuing more tests.

.. option:: --unittests-coverage

   Display unit test coverage report.
