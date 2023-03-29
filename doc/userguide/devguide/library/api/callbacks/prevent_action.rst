Prevent Action
==============

Callback invoked for any PreventAction event. A PreventAction event is invoked for every packet triggering a
drop or a reject signature and allows the client to drop/reject the connection in multiple ways.

All the subsequent packets belonging to the same flow will trigger this callback (in case the
flow is not dropped or rejected at first attempt) but they will not be inspected by libsuricata.
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every PreventAction event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_prevent_action_cb(SuricataCtx *ctx, CallbackFuncPreventAction callback);


This method allows to register a callback represented by the *CallbackFuncPreventAction* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncPreventAction)(
        PreventActionEvent *prevent_action_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *prevent_action_event* is an object containing the information to reject the connection. The prototype is:

        .. code-block:: c

            /* Drop/Reject information included in PreventActionEvent events. */
            typedef struct PreventActionInfo {
                /* The signature action that triggered the callback (drop|reject). */
                const char *action;
                /* Indicates whether the packet is IPv6. */
                bool pkt_is_ipv6;
                /* TCP info. */
                struct {
                    /* Payload length. */
                    uint16_t payload_len;
                    /* Packet sequence number. */
                    uint32_t seq;
                    /* Packet ACK number. */
                    uint32_t ack;
                    /* Window. */
                    uint16_t win;
                } tcp;
                /* ICMP info. */
                struct {
                    /* Payload (IP header + at most first 8 bytes of IP payload). */
                    uint8_t *payload;
                    /* Payload length. */
                    uint16_t payload_len;
                } icmp;
                /* DNS info. */
                struct {
                    /* Transaction id. */
                    uint16_t query_tx_id;
                    /* Query rrtype. */
                    uint16_t query_rrtype;
                    /* Query rrname. */
                    const uint8_t *query_rrname;
                    /* Query rrname length. */
                    uint32_t query_rrname_len;
                } dns;
            } PreventActionInfo;

            /* Struct representing a PreventAction event. It will be passed along in the callback. */
            typedef struct PreventActionEvent {
                Common common;
                PreventActionInfo prevent_action;
            } PreventActionEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.