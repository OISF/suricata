************
Transactions
************

Transactions are what guides when detecting and logging happen in Suricata. They’ll also help when dealing with protocols that can have large PDUs, like TCP, in controlling state for partial rule matching, for rules that mention more than one field.

The engine controls when logging should happen based on transaction completeness. for simpler protocols, that will most likely happen once per transaction by the time of its completion. In other cases, like with HTTP, this may happen also at intermediary states.

Code snippet from: suricata/src/output-tx.c

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


As a rule, transactions will follow a request-response model, meaning that if a transaction has had a request and a response, it is complete.

But if a protocol has situations where a request or response won’t expect or generate a message from its counter-part, it is also possible to have a uni-directional transaction.

For example, DNS responses may be considered as completed transactions, because they contain the request data, too, so all information needed for logging and detection can be found there.

In addition, for file transfer protocols, or similar ones where there may be several messages before the file exchange is completed (NFS, SMB), it is possible to create a level of abstraction to handle this complexity. This could be achieved by adding phases to the protocol implemented model (e.g., protocol negotiation phase (SMB), request parsed (HTTP), and so on).

This is controlled by implementing states. In Suricata, those will be enums that are incremented as the parsing progresses. A state will start at 0, and, the higher its value, the closer the transaction is to completion.

State: enum (Rust: i32) - initial state: 0
Simplest case scenario: 1 means transaction is completed
Other cases: completion will be indicated by the highest value in the enum
(examples: SBM, SSH, HTTP, then DNS)

.. code-block:: rust

    #[repr(u8)]
    #[derive(Copy, Clone, PartialOrd, PartialEq)]
    pub enum SSHConnectionState {
        SshStateInProgress = 0,
        SshStateBannerWaitEol = 1,
        SshStateBannerDone = 2,
        SshStateFinished = 3,
    }


This information is passed to the engine via the RustParser struct, and is defined per detection (TO SERVER/ TO CLIENT):
.. code-block:: rust

    tx_comp_st_ts
    tx_comp_st_tc

.. code-block:: rust

    /// Rust parser declaration
    #[repr(C)]
    pub struct RustParser {
            .
            .
            .

        /// Get the current transaction count
        pub get_tx_count:       StateGetTxCntFn,
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



Common words and abbreviations
==============================

- al, applayer: application layer 
- alproto: application layer protocol
- alstate: application layer state
- engine: refers to Suricata core
- rs: rust
- tx: transaction
- ts: to server
- tc: to client
