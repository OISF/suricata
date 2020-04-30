*******
Parsers
*******

Callbacks
=========

The API calls callbacks that are registered at the start of the program.

The function prototype is:

.. code-block:: c

    typedef AppLayerResult (*AppLayerParserFPtr)(Flow *f, void *protocol_state,
            AppLayerParserState *pstate,
            const uint8_t *buf, uint32_t buf_len,
            void *local_storage, const uint8_t flags);

Examples
--------

A C example:

.. code-block:: c

    static AppLayerResult HTPHandleRequestData(Flow *f, void *htp_state,
            AppLayerParserState *pstate,
            const uint8_t *input, uint32_t input_len,
            void *local_data, const uint8_t flags);

In Rust, the callbacks are similar.

.. code-block:: rust

    #[no_mangle]
    pub extern "C" fn rs_dns_parse_response_tcp(_flow: *const core::Flow,
            state: *mut std::os::raw::c_void,
            _pstate: *mut std::os::raw::c_void,
            input: *const u8,
            input_len: u32,
            _data: *const std::os::raw::c_void,
            _flags: u8)
    -> AppLayerResult


Return Types
============

Parsers return the type `AppLayerResult`.

There are 3 possible results:
 - `APP_LAYER_OK` - parser consumed the data successfully
 - `APP_LAYER_ERROR` - parser encountered a unrecoverable error
 - `APP_LAYER_INCOMPLETE(c,n)` - parser consumed `c` bytes, and needs `n` more before being called again

Rust parsers follow the same logic, but can return
 - `AppLayerResult::ok()`
 - `AppLayerResult::err()`
 - `AppLayerResult::incomplete(c,n)`

For `i32` and `bool`, Rust parsers can also use `.into()`.

APP_LAYER_OK / AppLayerResult::ok()
-----------------------------------

When a parser returns "OK", it signals to the API that all data has been consumed. The parser will be called again when more data is available.

APP_LAYER_ERROR / AppLayerResult::err()
---------------------------------------

Returning "ERROR" from the parser indicates to the API that the parser encountered an unrecoverable error and the processing of the protocol should stop for the rest of this flow.

.. note:: This should not be used for recoverable errors. For those events should be set.

APP_LAYER_INCOMPLETE / AppLayerResult::incomplete()
---------------------------------------------------

Using "INCOMPLETE" a parser can indicate how much more data is needed. Many protocols use records that have the size as one of the first parameters. When the parser receives a partial record, it can read this value and then tell the API to only call the parser again when enough data is available.

`consumed` is used how much of the current data has been processed
`needed` is the number of bytes that the parser needs on top of what was consumed.

Example::

    [ 32 record 1 ][ 32 record 2 ][ 32 r.. ]
     0          31  32         63  64    72
                                ^   ^
    consumed: 64 ---------------/   |
    needed:   32 -------------------/

.. note:: "INCOMPLETE" is only supported for TCP

The parser will be called again when the `needed` data is available OR when the stream ends. In the latter case the data will be incomplete. It's up to the parser to decide what to do with it in this case.

Supporting incomplete data
^^^^^^^^^^^^^^^^^^^^^^^^^^

In some cases it may be preferable to actually support dealing with incomplete records. For example protocols like SMB and NFS can use very large records during file transfers. Completely queuing these before processing could be a waste of resources. In such cases the "INCOMPLETE" logic could be used for just the record header, while the record data is streamed into the parser.
