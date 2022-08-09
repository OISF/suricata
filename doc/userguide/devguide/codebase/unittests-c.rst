**************
Unit Tests - C
**************

Unit tests are a great way to create tests that can check the internal state
of parsers, structures and other objects.

Tests should:

- use ``FAIL``/``PASS`` macros
- be deterministic
- not leak memory on ``PASS``
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

It is highly appreciated if you would run unit tests and report failing tests in our `issue tracker
<https://redmine.openinfosecfoundation.org/projects/suricata/issues>`_.

If you want more info about the unittests, regular debug mode can help. This is enabled by adding the configure option::

    --enable-debug

Then, set the debug level from the command-line::

    SC_LOG_LEVEL=Debug suricata -u

This will be very verbose. You can also add the ``SC_LOG_OP_FILTER`` to limit the output, it is grep-like::

    SC_LOG_LEVEL=Debug SC_LOG_OP_FILTER="(something|somethingelse)" suricata -u

This example will show all lines (debug, info, and all other levels) that contain either something or something else.
Keep in mind the `log level <https://suricata.readthedocs.io/en/latest/manpages/suricata.html#id1>`_  precedence: if you choose *Info* level, for instance, Suricata won't show messages from the other levels.

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

Examples
--------

From ``conf-yaml-loader.c``:

.. code-block:: c

    /**
     * Test that a configuration section is overridden but subsequent
     * occurrences.
     */
    static int
    ConfYamlOverrideTest(void)
    {
        char config[] =
            "%YAML 1.1\n"
            "---\n"
            "some-log-dir: /var/log\n"
            "some-log-dir: /tmp\n"
            "\n"
            "parent:\n"
            "  child0:\n"
            "    key: value\n"
            "parent:\n"
            "  child1:\n"
            "    key: value\n"
            ;
        const char *value;

        ConfCreateContextBackup();
        ConfInit();

        FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);
        FAIL_IF_NOT(ConfGet("some-log-dir", &value));
        FAIL_IF(strcmp(value, "/tmp") != 0);

        /* Test that parent.child0 does not exist, but child1 does. */
        FAIL_IF_NOT_NULL(ConfGetNode("parent.child0"));
        FAIL_IF_NOT(ConfGet("parent.child1.key", &value));
        FAIL_IF(strcmp(value, "value") != 0);

        ConfDeInit();
        ConfRestoreContextBackup();

        PASS;
    }

In ``detect-ike-chosen-sa.c``, it is possible to see the freeing of resources (``DetectIkeChosenSaFree``) and the
function that should group all the ``UtRegisterTest`` calls:

.. code-block:: c

    #ifdef UNITTESTS
    .
    .
    .
    static int IKEChosenSaParserTest(void)
    {
        DetectIkeChosenSaData *de = NULL;
        de = DetectIkeChosenSaParse("alg_hash=2");

        FAIL_IF_NULL(de);
        FAIL_IF(de->sa_value != 2);
        FAIL_IF(strcmp(de->sa_type, "alg_hash") != 0);

        DetectIkeChosenSaFree(NULL, de);
        PASS;
    }

    #endif /* UNITTESTS */

    void IKEChosenSaRegisterTests(void)
    {
    #ifdef UNITTESTS
        UtRegisterTest("IKEChosenSaParserTest", IKEChosenSaParserTest);
    #endif /* UNITTESTS */
