Context Creation
================

.. _suricata_create_ctx:

suricata_create_ctx
~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Create a Suricata context.
     *
     * \param n_workers    Number of packet processing threads that the engine is expected to support.
     * \return SuricataCtx Pointer to the initialized Suricata context.
     */
    SuricataCtx *suricata_create_ctx(int n_workers);

The above method will create a *SuricataCtx* object, which represents an instance of the library.
This method requires to specify in advance the number of packet processing threads the client
intends to use to proper handle synchronization with the management threads created by the library
(at this time the suricata management threads cannot be handled via the library API but they are
internally managed by the engine).
