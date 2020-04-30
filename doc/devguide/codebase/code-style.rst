Coding Style
============

Suricata uses a fairly strict coding style. This document describes it.

Formatting
~~~~~~~~~~

Line length
^^^^^^^^^^^

There is a soft limit of ~80 characters.

When wrapping lines that are too long, they should be indented at least 8 spaces from previous line. You should attempt to wrap the minimal portion of the line to meet the 80 character limit.

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

Braces
^^^^^^

Functions should have the opening brace on a newline:

.. code-block:: c

    int SomeFunction(void)
    {
        DoSomething();
    }


Control statements should have the opening brace on the same line:

.. code-block:: c

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

Opening and closing braces go on the same line as as the _else_ (also known as a "cuddled else").

.. code-block:: c

    if (this) {
        DoThis();
    } else {
        DoThat();
    }

Flow
~~~~

Don't use conditions and statements on the same line. E.g.

.. code-block:: c

    if (a) b = a; // <- wrong

    if (a)
        b = a; // <- right

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

curly braces / brackets
^^^^^^^^^^^^^^^^^^^^^^^

Functions should have the opening bracket on a newline:

.. code-block:: c

    int SomeFunction(void)
    {
        DoSomething();
    }

Note: this is a fairly new requirement, so you'll encounter a lot of non-compliant code.

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

TODO

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

TODO

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

Unittests
~~~~~~~~~

When writing unittests that use  when using a data array containing a protocol message, please put an explanatory comment that contain the readable content of the message

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
| strok      | strtok_r      |           |
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
