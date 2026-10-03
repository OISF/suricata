Migrating from the old SSH state names
======================================

In this release the SSH parser was rebuilt on per-direction active
phases: a state names the part of the handshake the state progression
of one direction is working through - it is entered when that unit
starts being parsed and left when the unit completes. The two
directions progress independently. The state names used in rules
(``accept:hook ssh:<state>``, ``alert ssh:<state>``) and in the
``firewall.policies.app.ssh`` config keys were renamed accordingly,
and the removed ``banner_wait_eol`` state has no replacement: a long
banner line now keeps its direction in the banner state. Rules using
an old state name fail to load.

Old and new names
-----------------

.. list-table::
   :header-rows: 1

   * - old state (milestone)
     - new state (phase)
     - note
   * - ``request_in_progress``
     - ``request_banner``
     - the banner (version) phase: the first packets of the direction
   * - ``request_banner_wait_eol``
     - ``request_banner``
     - the state is gone; a banner line that does not end within 256
       bytes keeps the direction in ``request_banner`` until the
       end-of-line arrives (the ``ssh.long_banner`` event)
   * - ``request_banner_done``
     - ``request_kex``
     - entered when the banner line completes; ``ssh.proto``,
       ``ssh.software`` and the hassh buffers are registered here
   * - ``request_finished``
     - ``request_session``
     - a ``new keys`` record was seen in this direction; the old top
       state required both directions to reach it
   * - ``response_in_progress``
     - ``response_banner``
     - the server-side banner phase
   * - ``response_banner_wait_eol``
     - ``response_banner``
     - as ``request_banner_wait_eol`` above, in the other direction
   * - ``response_banner_done``
     - ``response_kex``
     - as ``request_banner_done`` above, in the other direction
   * - ``response_finished``
     - ``response_session``
     - as ``request_finished`` above, in the other direction

``request_done`` / ``response_done`` is the registered completion
state. No direction ever reports it: a successful direction tops out
at ``session``, and a failed direction is frozen in the state the
failure occurred in. The completion state is neither hookable nor a
firewall policy key, so ``ssh:request_complete`` (and the
``request-complete`` policy key) matches nothing for a well-formed
flow - a session-admit rule like that no longer fires. Only a
disrupted flow (depth truncation or async reassembly) reports the
completion state, because the engine then returns it as the
transaction progress instead of querying the parser. Failures are
reported through the ``ssh.invalid_banner`` / ``ssh.invalid_record``
events instead.

Semantics that changed with the rename
--------------------------------------

- The scale is per direction: each direction reports its own raw
  phase, where the old progress accessor clamped both directions to
  one shared value. A rule hooking the old top state therefore meant
  "the flow completed", not "this direction completed the handshake".
  ``session`` is now set on the packet's own direction only, when that
  direction sees a ``new keys`` record; the two directions are
  independent.
- A parse failure freezes the failing direction in the state it
  occurred in: the direction neither advances nor regresses, and the
  frozen state is the last progress it reports. Nothing after the
  failing packet is parsed or delivered, mid-flow or at the flow-end
  flush. The failure reason is available through the
  ``ssh.invalid_banner`` / ``ssh.invalid_record`` app-layer events and
  the per-direction ``error`` / ``state`` fields of the eve ``ssh``
  object (``invalid_banner`` / ``invalid_record`` and the state the
  failure occurred in; a failed direction is logged even when it
  parsed no banner). A keyword registered at the failed state gets no
  eof run, so its flow-end evaluation stays non-terminal.
- A banner line of 256 bytes or more without an end-of-line keeps the
  direction in the banner state. The line is consumed greedily until
  the end-of-line arrives, and the direction then advances to ``kex``.
  The condition is observable through the ``ssh.long_banner`` event
  (the banner data is published when the long line first parses). If
  the line does not parse as a banner when it completes, the direction
  fails and is frozen in ``banner``.
- The firewall applies one decision per state, as for TLS: after an
  ``accept:hook`` rule matches at a state, further rules at the same
  state are not evaluated, and the verdict applies while the
  transaction stays at the hooked state. Remapping two old rules onto
  one new state therefore leaves the second one dead - keep at most
  one rule per state. The old milestones collapsed both directions
  onto one progress value; a rule now hooks one direction's phase.
- The state names are also exposed by the ``app-layer-state`` keyword
  and the ``ts_progress`` / ``tc_progress`` output fields. The name
  table changed with this rename: rules using ``app-layer-state``
  against the old SSH state names no longer match. ``done`` is out of
  both name tables, so ``app-layer-state:>request_session`` matches
  only a direction disrupted past ``session``; a successful direction
  stops at ``request_session`` and a failed one is frozen where it
  failed.
- The generic hook lists for the completion state run only at a
  disrupted flow end, so Lua hooks on SSH completion no longer fire
  for well-formed flows; before this change the accessor reported the
  terminal state once both directions had sent NewKeys.

Migration steps
---------------

1. **Rules.** Search the ruleset for the old names
   (``request_in_progress``, ``request_banner_wait_eol``,
   ``request_banner_done``, ``request_finished``, and the
   ``response_`` equivalents) and update them to the new names. A rule
   with an unknown state fails to load with a ``does not support
   hook`` error and is **not enforced**, so check the load output after
   updating. A rule that hooked ``request_banner_wait_eol`` maps to
   ``request_banner``; there is no separate long-line state.
2. **Firewall config keys.** Config keys use the **dash** form
   (``firewall.policies.app.ssh.request-banner-done``); rules use the
   underscore form (``ssh:request_banner_done``). Update the keys, or
   the state falls back to the implicit default policy (drop in
   firewall mode). Review ``request-complete`` policies: the
   completion state is never reported on a clean flow.
3. **``app-layer-state`` and hook users.** Rules and Lua hooks keyed on
   the old state names no longer match, and a hook on the completion
   state fires only for a disrupted flow. Use the ``ssh.invalid_*``
   events to observe parse failures.
4. **Monitoring.** The eve ``ssh`` object now carries the per-direction
   ``error`` / ``state`` fields for a parse failure; a failed
   direction is logged even when it parsed no banner. The
   ``ts_progress`` / ``tc_progress`` alert fields carry the new names.
