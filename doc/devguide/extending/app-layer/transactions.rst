************
Transactions
************

Table of Contents
=================
- `General Concepts`_
- `How the engine uses transactions`_
- `Progress Tracking`_
- `Examples`_
- `Common words and abbreviations`_

_`General Concepts`
===================

Transactions are abstractions that help detecting and logging in Suricata. They’ll also help during the dection phase,
when dealing with protocols that can have large PDUs, like TCP, in controlling state for partial rule matching, in case of rules that mention more than one field.

Transactions are implemented and stored in the per-flow state (To Server/ To Client). The engine interacts with it using a set of callbacks the parser registers.

_`How the engine uses transactions`
===================================

Suricata controls when logging should happen based on transaction completeness. For simpler protocols, that will most
likely happen once per transaction, by the time of its completion. In other cases, like with HTTP, this may happen also at intermediary states.

In ``OutputTxLog``, the engine will compare current state with the value defined for the logging to happen, per flow
direction (``logger->tc_log_progress``, ``logger->ts_log_progress``). If state is lesser than that value, the engine skips to
the next logger. Code snippet from: suricata/src/output-tx.c:

.. code-block:: c

    static TmEcode OutputTxLog(ThreadVars *tv, Packet *p, void *thread_data)
    {
        .
        .
        .
            if ((ts_eof && tc_eof) || last_pseudo) {
                SCLogDebug("EOF, so log now");
            } else {
                if (logger->LogCondition) {
                    int r = logger->LogCondition(tv, p, alstate, tx, tx_id);
                    if (r == FALSE) {
                        SCLogDebug("conditions not met, not logging");
                        goto next_logger;
                    }
                } else {
                    if (tx_progress_tc < logger->tc_log_progress) {
                        SCLogDebug("progress not far enough, not logging");
                        goto next_logger;
                    }

                    if (tx_progress_ts < logger->ts_log_progress) {
                        SCLogDebug("progress not far enough, not logging");
                        goto next_logger;
                    }
                }
             }
        .
        .
        .
    }

_`Progress Tracking`
====================

As a rule of thumb, transactions will follow a request-response model: if a transaction has had a request and a response, it is complete.

But if a protocol has situations where a request or response won’t expect or generate a message from its counter-part,
it is also possible to have uni-directional transactions. In such cases, transaction is set to complete at the moment of
creation.

For example, DNS responses may be considered as completed transactions, because they also contain the request data, so
all information needed for logging and detection can be found in the response.

In addition, for file transfer protocols, or similar ones where there may be several messages before the file exchange
is completed (NFS, SMB), it is possible to create a level of abstraction to handle such complexity. This could be achieved by adding phases to the protocol implemented model (e.g., protocol negotiation phase (SMB), request parsed (HTTP), and so on).

This is controlled by implementing states. In Suricata, those will be enums that are incremented as the parsing
progresses. A state will start at 0. The higher its value, the closer the transaction would be to completion.

The engine interacts with transactions state using a set of callbacks the parser registers. State is defined per flow direction (``STREAM_TOSERVER`` / ``STREAM_TOCLIENT``).

In Summary - Transactions and State
-----------------------------------

| Initial state value: ``0``
| Simpler scenarios: state is simply an int.  ``1`` represents transaction completion, per direction.
| Complex Transaction State in Suricata: ``enum`` (Rust: ``i32``). Completion is indicated by the highest enum value (some examples are: SSH, HTTP, DNS, SBM).

_`Examples`
===========

Enums
-----

Code snippet from: rust/src/ssh/ssh.rs:

.. code-block:: rust

    pub enum SSHConnectionState {
        SshStateInProgress = 0,
        SshStateBannerWaitEol = 1,
        SshStateBannerDone = 2,
        SshStateFinished = 3,
    }

From src/app-layer-ftp.h:

.. code-block:: c

    enum {
        FTP_STATE_IN_PROGRESS,
        FTP_STATE_PORT_DONE,
        FTP_STATE_FINISHED,
    };


API Callbacks
-------------

In Rust, this is done via the RustParser struct. As seen in rust/src/applayer.rs:

.. code-block:: rust

    /// Rust parser declaration
    pub struct RustParser {
            .
            .
            .
        /// Progress values at which the tx is considered complete in a direction
        pub tx_comp_st_ts:      c_int,
        pub tx_comp_st_tc:      c_int,
        .
        .
        .
    }

In C, the callback API is:

.. code-block:: c

    void AppLayerParserRegisterStateProgressCompletionStatus(
        AppProto alproto, const int ts, const int tc)

Simple scenario described, in Rust:

.. code-block:: rust

    rust/src/dhcp/dhcp.rs:

    tx_comp_st_ts: 1
    tx_comp_st_tc: 1

For SSH, this looks like this:

.. code-block:: rust

    rust/src/ssh/ssh.rs:

    tx_comp_st_ts: SSHConnectionState::SshStateFinished as i32,
    tx_comp_st_tc: SSHConnectionState::SshStateFinished as i32,

In C, callback usage would be as follows:

.. code-block:: c

    src/app-layer-dcerpc.c:

    AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_DCERPC, 1, 1);

    src/app-layer-ftp.c:

    AppLayerParserRegisterStateProgressCompletionStatus(
        ALPROTO_FTP, FTP_STATE_FINISHED, FTP_STATE_FINISHED);

_`Common words and abbreviations`
=================================

- al, applayer: application layer
- alproto: application layer protocol
- alstate: application layer state
- engine: refers to Suricata core
- PDU: Protocol Data Unit
- rs: rust
- tx: transaction
- ts: to server
- tc: to client
