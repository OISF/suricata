Alert
=====

Callback invoked for any alert event (equivalent of an EVE alert event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every alert.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_alert_cb(SuricataCtx *ctx, CallbackFuncAlert callback);

This method allows to register a callback represented by the *CallbackFuncAlert* object, defined as:

.. code-block:: c

    typedef void (CallbackFuncAlert)(
        AlertEvent *alert_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *alert_event* is an object representing the alert. The prototype is:

        .. code-block:: c

            /* Struct representing an alert event. It will be passed along in the callback. */
            typedef struct AlertEvent {
                /* Fields common to all callbacks (5-tuple, timestamp...). */
                Common common;
                /* Alert specific informaiton. */
                Alert alert;

                /* App layer event information, if any */
                app_layer app_layer;
            } AlertEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.