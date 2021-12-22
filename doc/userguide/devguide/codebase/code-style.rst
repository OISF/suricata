.. _Coding Style:

Coding Style
============

Suricata uses a fairly strict coding style. This document describes it.

Formatting
~~~~~~~~~~

clang-format
^^^^^^^^^^^^
``clang-format`` is configured to help you with formatting C code.

.. note::

    The ``.clang-format`` script requires clang 9 or newer.

Format your Changes
*******************

Before opening a pull request, please also try to ensure it is formatted
properly. We use ``clang-format`` for this, which has git integration through the
``git-clang-format`` script to only format your changes.
On some systems, it may already be installed (or be installable via your package
manager). If so, you can simply run it.

It is recommended to format each commit as you go. However, you can always
reformat your whole branch after the fact.

.. note::

    Depending on your installation, you might have to use the version-specific
    ``git clang-format`` in the commands below, e.g. ``git clang-format-9``,
    and possibly even provide the ``clang-format`` binary with
    ``--binary clang-format-9``.

    As an alternative, you can use the provided ``scripts/clang-format.sh``
    that isolates you from the different versions.

Formatting the most recent commit only
""""""""""""""""""""""""""""""""""""""
The following command will format only the code changed in the most recent commit:

.. code-block:: bash

    $ git clang-format HEAD^
    # Or with script:
    $ scripts/clang-format.sh commit

Note that this modifies the files, but doesn’t commit them – you’ll likely want to run

.. code-block:: bash

    $ git commit --amend -a

in order to update the last commit with all pending changes.

Formatting code in staging
""""""""""""""""""""""""""
The following command will format the changes in staging, i.e. files you ``git add``-ed:

.. code-block:: bash

    $ git clang-format
    # Or with script:
    $ scripts/clang-format.sh cached

If you also want to change the unstaged changes, do:

.. code-block:: bash

    $ git clang-format --force
    # Or with script:
    $ scripts/clang-format.sh cached --force

Formatting your branch' commits
"""""""""""""""""""""""""""""""
In case you have multiple commits on your branch already and forgot to
format them you can fix that up as well.

The following command will format every commit in your branch off master and
rewrite history using the existing commit metadata.

Tip: Create a new version of your branch first and run this off the new version.

.. code-block:: bash

    # In a new version of your pull request:
    $ scripts/clang-format.sh rewrite-branch

You could also add the formatting as an additional commit "at the end". However,
this is frowned upon. It's preferred to use ``rewrite-branch`` instead.

.. code-block:: bash

    # It's preferred to use rewrite-branch instead of this:
    $ git clang-format first_commit_on_your_branch^
    # Or with script:
    $ scripts/clang-format.sh branch

Note the usage of ``first_commit_on_your_branch^``, not ``master``, to avoid picking up
new commits on master in case you've updated master since you've branched.

Check formatting
""""""""""""""""
Check if your branch changes' formatting is correct with:

.. code-block:: bash

    $ scripts/clang-format.sh check-branch

Add the ``--diffstat`` parameter if you want to see the files needing formatting.
Add the ``--diff`` parameter if you want to see the actual diff of the formatting
change.

Formatting a whole file
"""""""""""""""""""""""

+--------------------------------------------------------------------+
| **Note**                                                           |
|                                                                    |
| Do not reformat whole files by default, i.e. do not use            |
| ``clang-format`` proper in general.                                |
+--------------------------------------------------------------------+

If you were ever to do so, formatting changes of existing code with clang-format
shall be a different commit and must not be mixed with actual code changes.

.. code-block:: bash

    $ clang-format -i {file}

Disabling clang-format
**********************

There might be times, where the clang-format's formatting might not please.
This might mostly happen with macros, arrays (single or multi-dimensional ones),
struct initialization, or where one manually formatted code.

You can always disable clang-format.

.. code-block:: c

    /* clang-format off */
    #define APP_LAYER_INCOMPLETE(c, n) (AppLayerResult){1, (c), (n)}
    /* clang-format on */

Installing clang-format and git-clang-format
********************************************
clang-format 9 or newer is required.

On ubuntu 18.04:

- It is sufficient to only install clang-format, e.g.

    .. code-block:: bash

        $ sudo apt-get install clang-format-9

- See http://apt.llvm.org for other releases in case the clang-format version
  is not found in the default repos.

On fedora:

- Install the ``clang``  and ``git-clang-format`` packages with

    .. code-block:: bash

        $ sudo dnf install clang git-clang-format


Line length
^^^^^^^^^^^

Limit line lengths to 100 characters.

When wrapping lines that are too long, they should be indented at least 8
spaces from previous line. You should attempt to wrap the minimal portion of
the line to meet the 100 character limit.

clang-format:
 - ColumnLimit: 100
 - ContinuationIndentWidth: 8
 - ReflowComments: true


Indent
^^^^^^

We use 4 space indentation.

.. code-block:: c

    int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
            uint8_t *pkt, uint16_t len, PacketQueue *pq)
    {
        SCPerfCounterIncr(dtv->counter_eth, tv->sc_perf_pca);

        if (unlikely(len < ETHERNET_HEADER_LEN)) {
            ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
            return TM_ECODE_FAILED;
        }

        ...

        DecodeNetworkLayer(tv, dtv, SCNtohs(p->ethh->eth_type), p,
                pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

        return TM_ECODE_OK;
    }

Use 8 space indentation when wrapping function parameters, loops and if statements.

Use 4 space indentation when wrapping variable definitions.

.. code-block:: c

    const SCPlugin PluginSpec = {
        .name = OUTPUT_NAME,
        .author = "Some Developer",
        .license = "GPLv2",
        .Init = TemplateInit,
    };


clang-format:
 - AlignAfterOpenBracket: DontAlign
 - Cpp11BracedListStyle: false
 - IndentWidth: 4
 - TabWidth: 8 [llvm]_
 - UseTab: Never [llvm]_

Braces
^^^^^^

Functions should have the opening brace on a newline:

.. code-block:: c

    int SomeFunction(void)
    {
        DoSomething();
    }

Note: you may encounter non-compliant code.

Control and loop statements should have the opening brace on the same line:

.. code-block:: c

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    for (ascii_code = 0; ascii_code < 256; ascii_code++) {
        ctx->goto_table[ctx->state_count][ascii_code] = SC_AC_FAIL;
    }

    while (funcs != NULL) {
        temp = funcs;
        funcs = funcs->next;
        SCFree(temp);
    }

Opening and closing braces go on the same line as as the _else_ (also known as a "cuddled else").

.. code-block:: c

    if (this) {
        DoThis();
    } else {
        DoThat();
    }

Structs, unions and enums should have the opening brace on the same line:

.. code-block:: c

    union {
        TCPVars tcpvars;
        ICMPV4Vars icmpv4vars;
        ICMPV6Vars icmpv6vars;
    } l4vars;

    struct {
        uint8_t type;
        uint8_t code;
    } icmp_s;

    enum {
        DETECT_TAG_TYPE_SESSION,
        DETECT_TAG_TYPE_HOST,
        DETECT_TAG_TYPE_MAX
    };

clang-format:
 - BreakBeforeBraces: Custom [breakbeforebraces]_
 - BraceWrapping:

   - AfterClass:      true
   - AfterControlStatement: false
   - AfterEnum:       false
   - AfterFunction:   true
   - AfterStruct:     false
   - AfterUnion:      false
   - AfterExternBlock: true
   - BeforeElse:      false
   - IndentBraces:    false

Flow
~~~~

Don't use conditions and statements on the same line. E.g.

.. code-block:: c

    if (a) b = a; // <- wrong

    if (a)
        b = a; // <- right

    for (int i = 0; i < 32; ++i) f(i); // <- wrong

    for (int i = 0; i < 32; ++i)
        f(i); // <- right

Don't put short or empty functions and structs on one line.

.. code-block:: c

    void empty_function(void)
    {
    }

    int short_function(void)
    {
        return 1;
    }

Don't use unnecessary branching. E.g.:

.. code-block:: c

    if (error) {
        goto error;
    } else {
        a = b;
    }


Can be written as:

.. code-block:: c

    if (error) {
        goto error;
    }
    a = b;

clang-format:
 - AllowShortBlocksOnASingleLine: false [llvm]_
 - AllowShortBlocksOnASingleLine: Never [llvm]_ (breaking change in clang 10!) [clang10]_
 - AllowShortEnumsOnASingleLine: false [clang11]_
 - AllowShortFunctionsOnASingleLine: None
 - AllowShortIfStatementsOnASingleLine: Never [llvm]_
 - AllowShortLoopsOnASingleLine: false [llvm]_
 - BreakBeforeBraces: Custom [breakbeforebraces]_
 - BraceWrapping:

   - SplitEmptyFunction: true
   - SplitEmptyRecord: true

Alignment
~~~~~~~~~

Pointers
^^^^^^^^
Pointers shall be right aligned.

.. code-block:: c

    void *ptr;
    void f(int *a, const char *b);
    void (*foo)(int *);

clang-format:
 - PointerAlignment: Right
 - DerivePointerAlignment: false

Declarations and Comments
^^^^^^^^^^^^^^^^^^^^^^^^^
Trailing comments should be aligned for consecutive lines.

.. code-block:: c

    struct bla {
        int a;       /* comment */
        unsigned bb; /* comment */
        int *ccc;    /* comment */
    };

    void alignment()
    {
        // multiple consecutive vars
        int a = 13;           /* comment */
        int32_t abc = 1312;   /* comment */
        int abcdefghikl = 13; /* comment */
    }

clang-format:
 - AlignConsecutiveAssignments: false
 - AlignConsecutiveDeclarations: false
 - AlignTrailingComments: true

Functions
~~~~~~~~~

parameter names
^^^^^^^^^^^^^^^

TODO

Function names
^^^^^^^^^^^^^^

Function names are NamedLikeThis().

.. code-block:: c

    static ConfNode *ConfGetNodeOrCreate(char *name, int final)

static vs non-static
^^^^^^^^^^^^^^^^^^^^

Functions should be declared static whenever possible.

inline
^^^^^^

The inlining of functions should be used only in critical paths.

Variables
~~~~~~~~~

Names
^^^^^

A variable is ``named_like_this`` in all lowercase.

.. code-block:: c

    ConfNode *parent_node = root;

Generally, use descriptive variable names.

In loop vars, make sure ``i`` is a signed int type.

Scope
^^^^^

TODO

Macros
~~~~~~

Macro names are ALL_CAPS_WITH_UNDERSCORES.
Enclose parameters in parens on each usage inside the macro.

Align macro values on consecutive lines.

.. code-block:: c

    #define ACTION_ALERT       0x01
    #define ACTION_DROP        0x02
    #define ACTION_REJECT      0x04
    #define ACTION_REJECT_DST  0x08
    #define ACTION_REJECT_BOTH 0x10
    #define ACTION_PASS        0x20

Align escape for multi-line macros right-most at ColumnLimit.

.. code-block:: c

    #define MULTILINE_DEF(a, b)                                              \
        if ((a) > 2) {                                                       \
            auto temp = (b) / 2;                                             \
            (b) += 10;                                                       \
            someFunctionCall((a), (b));                                      \
        }

clang-format:
 - AlignConsecutiveMacros: true [clang9]_
 - AlignEscapedNewlines: Right

Comments
~~~~~~~~

TODO

Function comments
^^^^^^^^^^^^^^^^^

We use Doxygen, functions are documented using Doxygen notation:

.. code-block:: c

    /**
     * \brief Helper function to get a node, creating it if it does not
     * exist.
     *
     * This function exits on memory failure as creating configuration
     * nodes is usually part of application initialization.
     *
     * \param name The name of the configuration node to get.
     * \param final Flag to set created nodes as final or not.
     *
     * \retval The existing configuration node if it exists, or a newly
     * created node for the provided name. On error, NULL will be returned.
     */
    static ConfNode *ConfGetNodeOrCreate(char *name, int final)

General comments
^^^^^^^^^^^^^^^^

We use ``/* foobar */`` style and try to avoid ``//`` style.

File names
~~~~~~~~~~

File names are all lowercase and have a .c. .h  or .rs (Rust) extension.

Most files have a _subsystem_ prefix, e.g. ``detect-dsize.c, util-ip.c``

Some cases have a multi-layer prefix, e.g. ``util-mpm-ac.c``

Enums
~~~~~

Use a common prefix for all enum values. Value names are ALL_CAPS_WITH_UNDERSCORES.

Put each enum values on a separate line.
Tip: Add a trailing comma to the last element to force "one-value-per-line"
formatting in clang-format.

.. code-block:: c

    enum { VALUE_ONE, VALUE_TWO };  // <- wrong

    // right
    enum {
        VALUE_ONE,
        VALUE_TWO, // <- force one-value-per-line
    };

clang-format:
 - AllowShortEnumsOnASingleLine: false [clang11]_

Structures and typedefs
~~~~~~~~~~~~~~~~~~~~~~~

TODO

switch statements
~~~~~~~~~~~~~~~~~

Switch statements are indented like in the following example, so the 'case' is indented from the switch:

.. code-block:: c

    switch (ntohs(p->ethh->eth_type)) {
        case ETHERNET_TYPE_IP:
            DecodeIPV4(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN, pq);
            break;

Fall through cases will be commented with ``/* fall through */``. E.g.:

.. code-block:: c

        switch (suri->run_mode) {
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
            case RUNMODE_PFRING:
                /* find payload for interface and use it */
                default_packet_size = GetIfaceMaxPacketSize(suri->pcap_dev);
                if (default_packet_size)
                    break;
                /* fall through */
            default:
                default_packet_size = DEFAULT_PACKET_SIZE;


Do not put short case labels on one line.
Put opening brace on same line as case statement.

.. code-block:: c

    switch (a) {
        case 13: {
            int a = bla();
            break;
        }
        case 15:
            blu();
            break;
        default:
            gugus();
    }


clang-format:
 - IndentCaseLabels: true
 - IndentCaseBlocks: false [clang11]_
 - AllowShortCaseLabelsOnASingleLine: false [llvm]_
 - BreakBeforeBraces: Custom [breakbeforebraces]_
 - BraceWrapping:

   - AfterCaseLabel:  false (default)

const
~~~~~

TODO

goto
~~~~

Goto statements should be used with care. Generally, we use it primarily for error handling. E.g.:

.. code-block:: c

    static DetectFileextData *DetectFileextParse (char *str)
    {
        DetectFileextData *fileext = NULL;

        fileext = SCMalloc(sizeof(DetectFileextData));
        if (unlikely(fileext == NULL))
            goto error;

        memset(fileext, 0x00, sizeof(DetectFileextData));

        if (DetectContentDataParse("fileext", str, &fileext->ext, &fileext->len, &fileext->flags) == -1) {
            goto error;
        }

        return fileext;

    error:
        if (fileext != NULL)
            DetectFileextFree(fileext);
        return NULL;
    }

Put goto labels at brace level.

.. code-block:: c

    int goto_style_nested()
    {
        if (foo()) {
        label1:
            bar();
        }

    label2:
        return 1;
    }

clang-format:
 - IndentGotoLabels: true (default) [clang10]_

Includes
~~~~~~~~

TODO

A .c file shall include it's own header first.

clang-format:
 - SortIncludes: false

Unittests
~~~~~~~~~

When writing unittests that use a data array containing a protocol message, please put an explanatory comment that contain the readable content of the message

So instead of:

.. code-block:: c

    int SMTPProcessDataChunkTest02(void)
    {
        char mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,

you should have something like:

.. code-block:: c

    int SMTPParserTest14(void)
    {
        /* 220 mx.google.com ESMTP d15sm986283wfl.6<CR><LF> */
        static uint8_t welcome_reply[] = { 0x32, 0x32, 0x30, 0x20,

Banned functions
~~~~~~~~~~~~~~~~

+------------+---------------+-----------+
| function   | replacement   | reason    |
+============+===============+===========+
| strtok     | strtok_r      |           |
+------------+---------------+-----------+
| sprintf    | snprintf      | unsafe    |
+------------+---------------+-----------+
| strcat     | strlcat       | unsafe    |
+------------+---------------+-----------+
| strcpy     | strlcpy       | unsafe    |
+------------+---------------+-----------+
| strncpy    | strlcat       |           |
+------------+---------------+-----------+
| strncat    | strlcpy       |           |
+------------+---------------+-----------+
| strndup    |               |OS specific|
+------------+---------------+-----------+
| strchrnul  |               |           |
+------------+---------------+-----------+
| rand       |               |           |
+------------+---------------+-----------+
| rand_r     |               |           |
+------------+---------------+-----------+
| index      |               |           |
+------------+---------------+-----------+
| rindex     |               |           |
+------------+---------------+-----------+
| bzero      |  memset       |           |
+------------+---------------+-----------+

Also, check the existing code. If yours is wildly different, it's wrong.
Example: https://github.com/oisf/suricata/blob/master/src/decode-ethernet.c

.. rubric:: Footnotes

.. [llvm] Default LLVM clang-format Style
.. [clang9] Requires clang 9
.. [clang10] Requires clang 10
.. [clang11] Requires clang 11
.. [breakbeforebraces] BreakBeforeBraces: Mozilla is closest, but does not split empty functions/structs
