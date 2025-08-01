Application Layer Overview
##########################

.. contents:: Table of Contents

This section aims to give an overview of what is needed to add
an application-layer protocol to Suricata.

After a generic first step of collecting data about this application-layer protocol,
especially pcaps for testing, we can dive into the Suricata specifics.

An application-layer protocol has three logic components in Suricata:

- parser
- logger
- detecting keywords

Both detection engine and logger will depend on the processing done by the parser.

For security reasons, we now develop application-layer protocol code
only in Rust and not in C.

The script ``scripts/setup-app-layer.py`` may help you get started for adding
a new app-layer protocol.

Parser
******

The parser is described by an instance of the structure ``RustParser``.

A parser has:

- a name (where it is better to avoid dashes)
- an ipproto (if an app-layer is both over UDP and TCP, it needs to be registered with 2 RustParser)
- flags: only one flag ``APP_LAYER_PARSER_OPT_ACCEPT_GAPS``
- some app-layer detection logic see :ref:`Protocol detection`.
- some logic around (one) State and (one) Transaction structures
- some stringer functions (frames, events)

So each app-layer protocol needs to define two structures: one State and one Transaction.
A State will live throughout the flow (or until there is a protocol change in the flow).
As such, it is useful to retain data that needs such a scope (for example HTTP2 dynamic headers table).
And it is also useful if the parsing uses a state-machine logic, for example for file streaming.
A State will own a list of :doc:`transactions`.

Transactions
============

Transactions are the basic logical unit used by Suricata for an application-layer protocol.

The big decision is how to assemble PDUs into a transaction.
Simplest design is to have one transaction per PDU (like DNS).
But it may add value for example to combine request and response into a single transaction
(like HTTP).

The ``RustParser`` structure contains callbacks to parse network traffic in both directions.
These callbacks will create the transactions.

For protocols over TCP, this callback has to loop as one callback may run for a network traffic
containing multiple PDUs, and thus resulting in the creation of multiple transactions.

.. note::  If a protocol may have multiple long-lived transactions, it is good to enforce limits
  on the number of live transactions, and bound any other data owned by the State.

In case of parsing anomalies, a transaction can set anomaly events, which are specific
to the application-layer protocol. There is currently no good standardized way to have
this kind of event outside transactions.

Gap support
===========

It is good to develop an app-layer support first without gap support,
then improve it by adding gap support.

Pcaps for testing can be created by removing some packets in previous testing pcaps.

After adding the flag ``APP_LAYER_PARSER_OPT_ACCEPT_GAPS``, a generic way to handle this is:

- add two booleans to the State, like request_gap and response_gap
- have the parsing functions set these booleans ``if stream_slice.is_gap()``
- have the parsing functions test these booleans, and try to resync with a beginning of a PDU

.. note:: This generic best-effort approach is vulnerable to request/response smuggling.

Another less generic approach is to handle gaps only in the case the gap happens
in the middle of a known-length PDU (like HTTP1 content-length).

Logger
******

Besides the logging function, the logger also has a direction which may be
either ``LOG_DIR_PACKET`` or ``LOG_DIR_FLOW``.

UDP unidirectional transactions will be better interpreted using ``LOG_DIR_PACKET``
while TCP transactions are usually better interpreted using ``LOG_DIR_FLOW``.

The logging function returns a boolean which must be false if there is nothing to log,
for example if the resulting json object is empty.

Support for application-layer specific logging options is not yet standardized,
especially for alerts.

Detection engine
****************

A simple callback should register the keywords matching the log output fields.