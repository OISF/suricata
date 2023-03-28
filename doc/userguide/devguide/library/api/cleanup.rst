Cleanup
=======

suricata_deinit_worker_thread
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Cleanup a Suricata worker.
     *
     * \param ctx Pointer to the Suricata context.
     * \param tv  Pointer to the worker context.
     */
    void suricata_deinit_worker_thread(SuricataCtx *ctx, ThreadVars *tv);

This method cleans up the memory associated to a packet processing thread. It *must* be invoked
from within a packet processing thread at the end of the routine.

suricata_shutdown
~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Shutdown the Suricata engine.
     *
     * \param ctx Pointer to the Suricata context.
     */
    void suricata_shutdown(SuricataCtx *ctx);

This method cleans up the memory associated to the Suricata context. It *must* be invoked from the same thread
that invoked :ref:`suricata_create_ctx`, i.e not from a thread creating a Suricata worker.
