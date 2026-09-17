Migrating from the old TLS state names
======================================

In this release the TLS state names changed from completion
milestones to active phases: a state now describes the phase the
handshake or data exchange is *in*, and it is entered when the phase's
first message is fully available - fully buffered, so the phase data
(SNI, certificates) exists when rules in the state are evaluated -
not at a later completion milestone. The state names used in rules
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
     - the phase is entered when the hello message is fully parsed
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

- ``client_hello`` is entered once the ClientHello message is fully
  buffered (all fragments consumed), not at the first hello byte; a
  hello fragmented over several TLS records is decided at
  ``client_started`` until its final fragment arrives, and a hello
  that fails to parse leaves the track in its current state.
- ``server_data`` is entered on the first server (to_client) app-data
  record, or as soon as the server certificate is parsed (the
  subject/issuer shortcut that establishes the data phase
  mid-handshake) - not when the server flight ends. A session that
  completes the handshake but sends no server app data and no
  parseable certificate never reaches ``server_data``; app data no
  longer re-enters a completion state.
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
- The TLS event carrying the ``ja3``/``ja3s`` fingerprint fields is
  emitted once the session reaches the data phase, instead of at the
  old flight-completion milestones (``client_handshake_done``,
  ``server_handshake_done``). For a session with a server certificate
  the data phase is established when the certificate is parsed, so the
  timing is close to the old one; a session with no server certificate
  and no application data publishes the event only at the end of the
  connection.
- SSLv2: a v2 client hello moves the client track to
  ``client_hello`` and a v2 server hello moves the server track to
  ``server_hello``; the later v2 records (key exchange, certificate)
  no longer advance a track - the old ``server_cert_done`` and
  ``server_hello_done`` milestones are gone. The server track stays at
  ``server_hello`` until the first app-data record, so cert keywords
  inspect from the app data on SSLv2 flows. A rule keyed on the
  post-hello v2 flight belongs to ``server_hello``.
- The state tracks are monotonic: once a track reaches ``*_data`` or
  ``*_finished``, a renegotiated handshake does not re-enter the
  hello/cert phases on that track; a second ClientHello does not
  re-evaluate the ``client_hello`` rules or re-expose the SNI.

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
