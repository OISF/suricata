HTTP
====

Callback invoked for any HTTP event (equivalent of an EVE HTTP event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every HTTP event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_http_cb(SuricataCtx *ctx, CallbackFuncHttp callback);

This method allows to register a callback represented by the *CallbackFuncHttp* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncHttp)(
        HttpEvent *http_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *http_event* is an object representing the HTTP transaction. The prototype is:

        .. code-block:: c

            typedef struct HttpEvent {
                /* Fields common to all callbacks (5-tuple, timestamp...). */
                Common common;
                /* HTTP specific information. */
                HttpInfo http;
            } HttpEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.