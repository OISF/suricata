Input
=====

The library can receive as input both packets (like the regular Suricata binary) and reassembled
stream segments. This is achieved invoking the following methods.

suricata_handle_packet
~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
    * \brief Feed a packet to the library.
    *
    * \param tv                    Pointer to the per-thread structure.
    * \param data                  Pointer to the raw packet.
    * \param datalink              Datalink type.
    * \param ts                    Timeval structure.
    * \param len                   Packet length.
    * \param ignore_pkt_checksum   Boolean indicating if we should ignore the packet checksum.
    * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
    * \param tenant_id             Tenant id of the detection engine to use.
    * \param flags                 Packet flags (currently only used for rule profiling).
    * \param user_ctx              Pointer to a user-defined context object.
    * \return                      Error code.
    */
    int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
                               uint32_t len, int ignore_pkt_checksum, uint64_t *tenant_uuid,
                               uint32_t tenant_id, uint32_t flags, void *user_ctx);

This method feeds a packet to the Suricata engine. It *must* be invoked from within a Suricata
worker after it has been initialized.

It is possible to specify flags to apply to the packet. These flags are defined in
*suricata-interface.h* (currently the only one available is used to enable rule profiling).

After the packet is processed any relevant registered callback will be invoked.

suricata_handle_stream
~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /** \brief Feed a single stream segment to the library.
    *
    * \param tv                    Pointer to the per-thread structure.
    * \param finfo                 Pointer to the flow information.
    * \param data                  Pointer to the raw packet.
    * \param len                   Packet length.
    * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
    * \param tenant_id             Tenant id of the detection engine to use.
    * \param flags                 Packet flags (currently only used for rule profiling).
    * \param user_ctx              Pointer to a user-defined context object.
    * \return                      Error code.
    */
    int suricata_handle_stream(ThreadVars *tv, FlowStreamInfo *finfo, const uint8_t *data,
                               uint32_t len, uint64_t *tenant_uuid, uint32_t tenant_id, uint32_t flags,
                               void *user_ctx);

This method feeds a reassembled stream segment to the Suricata engine. The input parameters are
similar to the packet processing method, except that this method requires a *FlowStreamInfo*
object, defined in the "suricata-interface-stream.h".

This method *must* be invoked from within a thread creating a Suricata worker after it has been
initialized.

After the stream segment is processed any relevant registered callback will be invoked.

This method accepts the same flags as *suricata_handle_packet*.
