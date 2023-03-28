Stats
=====

Callback invoked every time the client invokes :ref:`suricata_get_stats`
(equivalent of an EVE stats event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked every time `suricata_get_stats` is invoked.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param user_ctx       Pointer to a user-defined context object.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_stats_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncStats callback);

This method allows to register a callback represented by the *CallbackFuncStats* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncStats)(
        void *data,
        size_t len,
        void *user_ctx
    );

Where:
    * *data* is a JSON formatted string representing the event.
    * *len* is the length of the JSON string.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.
