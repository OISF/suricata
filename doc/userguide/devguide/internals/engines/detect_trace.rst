Detection Inspection Tracing
============================

The content-inspection engine (``DetectEngineContentInspection``) can emit a
human-readable trace of every keyword it evaluates against a buffer. For each
inspected keyword it prints the signature being evaluated, the keyword and its
parameters, and -- on a match or a definitive no-match -- a hexdump of the
buffer windowed around the current inspection offset. It is a developer aid for
answering "why did (or didn't) this rule match this traffic?".

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
    TRACE (5400063) MSG: ETPRO HUNTING Expired SAML Assertion Expiry Timestamp
    TRACE (5400063) Mode: state  AppProto: http_any  Buffer: http.request_body  Match Type: content  Recursion: 3/3000
    TRACE (5400063) Inspecting content:"NotOnOrAfter=\x22" (len 14)
    TRACE (5400063) -> MATCH! <-  (content)
    TRACE (5400063) post-detect offset: 1211
    TRACE buffer window +1024..+1467 of 1467 (detect offset +1211):
     0400  30 22 20 49 44 3d 22 5f  ...  0" ID="_assertio

The hexdump itself is produced by the shared ``PrintRawDataFp()`` helper; its
row offsets are relative to the start of the printed window (see the header
line for the absolute anchor).

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
