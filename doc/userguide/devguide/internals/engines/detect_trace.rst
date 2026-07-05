Detection Inspection Tracing
============================

The content-inspection engine (``DetectEngineContentInspection``) can emit a
human-readable trace of every keyword it evaluates against a buffer. For each
inspected keyword it prints the signature being evaluated, the keyword and its
parameters, and -- on a match or a definitive no-match -- a hexdump of the
buffer windowed around the current inspection offset, with the bytes the
keyword matched called out in the dump. It is a developer aid for answering
"why did (or didn't) this rule match this traffic?".

The facility is intended for interactive debugging with a single pcap and a
small rule set. It writes directly to ``stdout`` and is not meant for
production traffic.

Enabling
--------

Tracing is compiled in only when Suricata is configured with::

    ./configure --enable-detect-trace

This defines the ``DETECT_TRACE`` preprocessor macro. When the macro is not
defined the trace call sites expand to nothing, so a normal build carries no
overhead at all.

Even in a trace-enabled build the output stays off until it is switched on at
runtime through an environment variable::

    SURICATA_DETECT_TRACE=1 suricata -S rules.rules -r input.pcap -k none -l ./log

When the variable is unset, each trace call is guarded by a single predictable
branch, so a trace-enabled build can be used normally with negligible cost.

Output
------

Each inspected keyword produces a block such as::

    ------------------------------------------------------------------------------
    TRACE (4) MSG: trace demo deep body
    TRACE (4) Mode: state  AppProto: http_any  Buffer: file_data  Match Type: content  Recursion: 1/3000
    TRACE (4) Inspecting content:"</html>" (len 7)
    TRACE (4) -> MATCH! <-  (content)
    TRACE (4) post-detect offset: 4259
    TRACE buffer window +4000..+4259 of 4259 (match +4252..+4259, cursor +4259 past end):
     00000FA0  3E 20 6C 6F 77 3C 62 72  20 2F 3E 3C 65 6D 3E 50   > low<br  /><em>P
     ...
     00001080  0D 0A 0D 0A 09 09 3C 2F  64 69 76 3E 0D 0A 0D 0A   ......</ div>....
    >00001090  09 3C 2F 62 6F 64 79 3E  0D 0A 0D 0A 3C 2F 68 74   .</body> ....</ht
    >000010A0  6D 6C 3E                                           ml>

Reading the dump
~~~~~~~~~~~~~~~~

Row offsets are absolute within the inspected buffer, so they can be compared
directly against the ``post-detect offset`` and against the ``offset``,
``depth`` and ``distance`` values printed for the keyword. Only a window around
the current offset is dumped -- 256 bytes on either side -- so that a large
stream or body buffer does not flood the terminal; the header line gives the
window bounds and the buffer's full length.

Two things are called out in the dump. The bytes the keyword just matched are
shown as a span, and the offset the next keyword will start from is shown as a
single cursor byte. They are distinct because a content match leaves the
inspection offset just *past* the bytes it matched, so ``match +4252..+4259``
and ``cursor +4259`` in the example above describe the seven bytes of
``</html>`` and the position after them. A match span is only reported for a
positive, non-negated ``content``; every other keyword, and every no-match,
leaves the offset as a bare cursor with no span to show. Rows containing either
marker carry a ``>`` in the left gutter.

When ``stdout`` is a terminal the span and the cursor are colored, in both the
hex and the ascii column. Otherwise -- output redirected to a file or a pager,
or ``NO_COLOR`` set in the environment -- the whole trace is emitted without
escape sequences and the markers appear on a row of their own beneath the hex
bytes, with ``^`` under the matched span and ``*`` under the cursor::

    TRACE buffer window +0..+27 of 27 (cursor +10) [^ match, * cursor]:
    >00000000  2F 66 69 6C 65 32 70 63  61 70 2F 62 6F 64 79 74   /file2pc ap/bodyt
                                                **
     00000010  65 78 74 74 65 73 74 2E  74 78 74                  exttest. txt

The ``Buffer`` name is only shown when Suricata is additionally built with
``--enable-profiling`` (the current inspection buffer id is only tracked on the
thread context in profiling builds); otherwise it is reported as ``(null)``.

Per-keyword parameter detail is printed for ``content``, ``pcre``, ``isdataat``,
``byte_test``, ``byte_jump`` and ``base64_decode``. Other keywords are still
traced by name via the ``Match Type`` field.

Implementation
--------------

All of the tracing lives in ``src/detect-engine-inspect-trace.{c,h}`` and is
invoked from ``DetectEngineContentInspection`` through the ``DETECT_TRACE_*``
macros, which are no-ops unless ``DETECT_TRACE`` is defined. To keep the trace
readable, ``content`` values are rendered from the parsed ``DetectContentData``
(no signature re-parsing), and the original ``pcre`` pattern text is retained on
the ``DetectParseRegex`` only in trace builds.

The dump is written by ``DetectTraceHexdump()`` rather than by the shared
``PrintRawDataFp()`` helper, since it needs absolute row offsets and per-byte
markers that the shared dumper does not provide. Color is decided once in
``DetectTraceInit()``: the ANSI sequences are held in file-scope pointers that
stay empty strings unless ``stdout`` is a tty and ``NO_COLOR`` is unset, so the
same format strings produce both forms of output.
