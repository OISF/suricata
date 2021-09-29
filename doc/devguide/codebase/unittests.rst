**********
Unit Tests
**********

Unit tests are a great way to create tests that can check the internal state
of parsers, structures and other objects.

Tests should:

- use FAIL/PASS macros
- be deterministic
- not leak memory on PASS
- not use conditions

Unit tests are used by developers of Suricata and advanced users who would like to contribute by debugging and testing the engine.
Unit tests are small pieces (units) of code which check certain code functionalities in Suricata. If Suricata's code is modified, developers can run unit tests to see if there are any unforeseen effects on other parts of the engine's code.
Unit tests will not be compiled with Suricata by default.
If you would like to compile Suricata with unit tests, enter the following during the configure-stage::

   ./configure --enable-unittests

The unit tests specific command line options can be found at `Command Line Options <https://suricata.readthedocs.io/en/suricata-6.0.3/command-line-options.html#unit-tests>`_.

Example:
You can run tests specifically on flowbits. This is how you should do that::

   suricata -u -U flowbit

It is highly appreciated if you would run unit tests and report failing tests at Issues.

If you want more info about the unittests, regular debug mode can help::

    --enable-debug

Then, set the debug level from the commandline::

    SC_LOG_LEVEL=Debug suricata -u

This will be very verbose. You can also add the ``SC_LOG_OP_FILTER`` to limit the output, it is grep-like::

    SC_LOG_LEVEL=Debug SC_LOG_OP_FILTER="(something|somethingelse)" suricata -u

This example will show all lines (debug, info, and all other levels) that contain either something or something else.

Writing Unit Tests - C codebase
===============================

Suricata unit tests are somewhat different in C and in Rust. In C, they are comprised of a function with no arguments and returning 0 for failure or 1 for success. Instead of explicitly returning a value, FAIL_* and PASS macros should be used. For example:

.. code-block:: c

    void MyUnitTest(void)
    {
        int n = 1;
        void *p = NULL;
    
        FAIL_IF(n != 1);
        FAIL_IF_NOT(n == 1);
        FAIL_IF_NOT_NULL(p);
        FAIL_IF_NULL(p);
    
        PASS;
    }

Each unit test needs to be registered with ``UtRegisterTest()``. Example::

    UtRegisterTest("MyUnitTest", MyUnitTest);

where the first argument is the name of the test, and the second argument is the function. Existing modules should already have a function that registers its unit tests. Otherwise the unit tests will need to be registered. Look for a module similar to your new module to see how best to register the unit tests or ask the development team for help.

Unit Tests - Rust codebase
==========================

Please check the Developer's Guide on Rust unit tests for a detailed explanation on how those work.
