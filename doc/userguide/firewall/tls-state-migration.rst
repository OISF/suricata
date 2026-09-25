Migrating from the old TLS state names
======================================

In this release the TLS state names changed from completion
milestones to active phases, following the HTTP1 unit states: a state
names the handshake message (or data exchange) the track is working
through - it is entered when that unit starts being parsed and left
when the unit completes. The phase data (SNI, certificates) exists
once the message has been fully parsed; rules evaluated while it is
still arriving (a fragmented message) see partial data, as they do
for a split HTTP request line. The state names used in rules
(``accept:hook tls:<state>``, ``alert tls:<state>``) and in the
``firewall.policies.app.tls`` config keys were renamed accordingly, and
the flight-completion state was removed.

Old and new names
-----------------

.. list-table::
   :header-rows: 1

   * - old state (milestone)
     - new state (phase)
     - note
   * - ``client_in_progress``
     - ``client_started``
     - covers the packets before the hello
   * - ``client_hello_done``
     - ``client_hello``
     - the phase is entered at the start of the hello message
   * - ``client_cert_done``
     - ``client_cert``
     -
   * - ``client_handshake_done``
     - ``client_data``
     -
   * - ``client_finished``
     - ``client_finished``
     - unchanged
   * - ``server_in_progress``
     - ``server_started``
     -
   * - ``server_hello``
     - ``server_hello``
     - unchanged
   * - ``server_cert_done``
     - ``server_cert``
     -
   * - ``server_hello_done``
     - ``server_data``
     - the flight-completion milestone no longer exists
   * - ``server_handshake_done``
     - ``server_data``
     - both map to the data phase
   * - ``server_finished``
     - ``server_finished``
     - unchanged

Semantics that changed with the rename
--------------------------------------

- ``client_hello`` names the ClientHello being parsed: it is entered
  at the first byte of the message, so every fragment of a hello split
  over several TLS records is decided at ``client_hello`` (with the
  SNI and the other hello buffers filled only once the final fragment
  completes the message). Completion hands the track to ``client_cert``
  before a single certificate byte arrives, and the record that
  completes the hello is decided there; a Certificate message also
  names the ``client_cert`` phase at its own start, which keeps a track
  that begins mid-connection or after a failed hello coherent. Rules on hello data
  (``tls.sni``) still live in ``client_hello`` - that state owns the
  buffer - but their accept must carry the flow: the verdict of the
  completing record is rendered at ``client_cert``, so an
  ``accept:hook`` at ``client_hello`` alone does not let the flow
  through. A hello that fails to parse keeps the track in
  ``client_hello``: its data never existed. ``server_hello`` behaves
  identically for the ServerHello.
- ``server_data`` is entered on the first server (to_client) app-data
  record, or as soon as the server certificate is parsed (the
  subject/issuer shortcut that establishes the data phase
  mid-handshake) - not when the server flight ends. A session that
  completes the handshake but sends no server app data and no
  parseable certificate never reaches ``server_data``; app data no
  longer re-enters a completion state. The shortcut is per track: a
  track's own certificate data decides that track only. In
  particular, in mutual TLS the server certificate (which arrives
  before the CertificateRequest) does not push the client track
  through ``client_cert`` - the client certificate message is still
  evaluated at ``client_cert``.
- The ``server_hello_done`` milestone is gone. The server record
  progression between hello and data is ServerHello, the certificate
  messages, then the ChangeCipherSpec/Finished flight; the flight
  carries no inspectable data, which is why no state exists for it.
  A rule that wanted to act at "flight complete, before data" now
  belongs to the tail of ``server_cert`` or the head of
  ``server_data`` depending on intent - the rename hint
  (``server_hello_done`` -> ``server_data``) is approximate in the
  same way; at the old milestone the track was usually still in
  ``server_cert``.
- The firewall applies one decision per state: after an ``accept:hook``
  rule matches at a state, further rules at the same state are not
  evaluated. Remapping two old rules onto one new state therefore leaves
  the second one dead - keep at most one rule per state.
- The TLS event carrying the ``ja3``/``ja3s`` fingerprint fields is a
  session level event: it flushes as soon as everything it logs is
  final, that is once a certificate of the track has decoded (or the
  track advanced beyond the certificate phase, showing it carries
  none) and, when the server requested a client certificate, the same
  for the client certificate. A session that never reaches that point
  publishes the event at connection close. Its packet attribution
  matches the old model's, because the old logger gated on the same
  certificate material.
- TLS handshake records often share a TCP segment (e.g. Certificate,
  CertificateRequest and ServerHelloDone in one flight). Every state
  walked over by such a packet is evaluated in order, but the packet
  decision renders at the state the progress reaches: rules of the
  earlier states in the segment can only accept weakly (mid-walk).
- The state names are also exposed by the ``app-layer-state`` keyword
  and in the ``ts_progress``/``tc_progress`` output fields. The name
  table changed with this rename: rules using ``app-layer-state``
  against the old TLS state names no longer match, and consumers
  filtering on the progress fields see the new names.
- SSLv2: a v2 client hello moves the client track to
  ``client_hello``, a v2 server hello moves the server track to
  ``server_hello``, and a v2 client certificate message moves the
  client track to ``client_cert`` (the v2 certificate payload itself
  is not extracted, so cert keywords stay empty there). The old
  ``server_cert_done`` and ``server_hello_done`` milestones are gone.
  TLS records embedded in a v2 message are parsed by the regular v3
  state machine. A rule keyed on the post-hello v2 flight belongs to
  the state the track is in when it arrives.
- The state tracks are monotonic: once a track reaches ``*_data`` or
  ``*_finished``, a renegotiated handshake does not re-enter the
  hello/cert phases on that track; a second ClientHello does not
  re-evaluate the ``client_hello`` rules or re-expose the SNI.
- A ruleset that accepted the pre-hello state and then matched the SNI
  on the completing record now drops the first fragment of every
  fragmented hello: the fragment is decided at ``client_hello`` (not at
  the pre-hello state as before), it carries no data to match, and an
  unmatched packet falls on the implicit default policy (drop in
  firewall mode). If you accept fragmented handshake messages today,
  add a plain ``accept:hook tls:client_hello`` / ``tls:server_hello``
  rule for the fragments; only the SNI/other-data rules keep their
  content match.

Migration steps
---------------

1. **Rules.** Search the ruleset for the old names
   (``client_in_progress``, ``client_hello_done``, ``client_cert_done``,
   ``client_handshake_done``, ``server_in_progress``, ``server_hello_done``,
   ``server_cert_done``, ``server_handshake_done``) and update them to
   the new names. A rule with an unknown state fails to load with a
   ``does not support hook`` error and is **not enforced**, so check the
   load output after updating.
2. **Firewall config keys.** Config keys use the **dash** form
   (``firewall.policies.app.tls.client-hello-done``); rules use the
   underscore form (``tls:client_hello_done``). A key that no longer
   matches a state is reported at load: a key known to be a renamed
   state is an error (init aborts when ``init-failure-fatal`` is
   set), other unknown keys are a warning naming the replacement.
   Update the keys, or the state falls back to the implicit default
   policy (drop in firewall mode).
3. **Monitoring.** The ``ts_progress`` field in alert events now carries
   the new state names; update any correlation on the old values.
