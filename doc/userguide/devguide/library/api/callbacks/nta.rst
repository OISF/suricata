NTA
===

Callback invoked for any NTA (Network Traffic Analysis) event. The following events are currently
supported:

    * DHCP.
    * SMB.
    * TLS.

The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every NTA event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_nta_cb(SuricataCtx *ctx, CallbackFuncNta callback);

This method allows to register a callback represented by the *CallbackFuncNta* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncNta)(
        void *data,
        size_t len,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *data* is a JSON formatted string representing the event.
    * *len* is the length of the JSON string.
    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.