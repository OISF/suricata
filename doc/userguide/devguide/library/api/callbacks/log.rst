Log
===

Callback invoked for any log message. It can be registered to hook into the suricata engine logs
and, for instance, add additional client side information to the log messages.

The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every log message.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_log_cb(SuricataCtx *ctx, CallbackFuncLog callback);

This method allows to register a callback represented by the *CallbackFuncLog* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncLog)(
        int log_level, /* value corresponding to a SCLogLevel enum */
        int error_code, /* value corresponding to a SCError enum */
        const char *message
    );

Where:
    * *log_level* is the suricata log level (e.g Info, Notice...).
    * *error_code* is the error code (meaningful for error messages only).
    * *message* is the actual log message. The message does not contain format specifiers, as they
      are already expanded.
