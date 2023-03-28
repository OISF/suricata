FlowSnip
========

Callback invoked for any flowsnip event (equivalent of an EVE flow-snip event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every FlowSnip event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_flowsnip_cb(SuricataCtx *ctx, CallbackFuncFlowSnip callback);

This method allows to register a callback represented by the *CallbackFuncFlowSnip* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncFlowSnip)(
        FlowSnipEvent *flowsnip_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *flowsnip_event* is an object representing the flowsnip event. The prototype is:

        .. code-block:: c

            /* Struct representing a flow snip event. It will be passed along in the callback. */
            typedef struct FlowSnipEvent {
                /* Fields common to all callbacks (5-tuple, timestamp...). */
                Common common;
                /* Flow specific information. */
                FlowInfo flow;

                /* FlowSnip id */
                uint32_t snip_id;
                /* Number of packets in the pcap */
                uint16_t num_packets;
                /*Counter of the first packet of the snip relative to the flow */
                uint16_t pkt_cnt;
                /* Timestamp of the first packet */
                char timestamp_first[TIMESTAMP_LEN];
                /* Timestamp of the last packet */
                char timestamp_last[TIMESTAMP_LEN];

                /* Array of alerts and corresponding size (<= PACKET_ALERT_MAX). */
                uint16_t alerts_size;
                Alert alerts[PACKET_ALERT_MAX];
            } FlowSnipEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.