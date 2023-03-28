Flow
====

Callback invoked for any expired flow (equivalent of an EVE flow event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every flow.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_flow_cb(SuricataCtx *ctx, CallbackFuncFlow callback);

This method allows to register a callback represented by the *CallbackFuncFlow* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncFlow)(
        FlowEvent *flow_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *flow_event* is an object representing the flow. The prototype is:

        .. code-block:: c

            /* Struct representing a flow event. It will be passed along in the callback. */
            typedef struct FlowEvent {
                /* Fields common to all callbacks (5-tuple, timestamp...). */
                Common common;
                /* Flow specific information. */
                FlowInfo flow;
            } FlowEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.
