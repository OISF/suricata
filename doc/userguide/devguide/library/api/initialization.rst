Initialization
==============

After the library is properly configured, the engine can be initialized with the following methods.

.. _suricata_init:

suricata_init
~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
    * \brief Initialize a Suricata context.
    *
    * \param ctx  Pointer to SuricataCtx.
    */
    void suricata_init(SuricataCtx *ctx);

This method initializes the internal Suricata engine using the configuration object created by the
configuration API methods.

suricata_initialise_worker_thread
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Initialize a Suricata worker.
     *
     * This function is meant to be invoked by a thread in charge of processing packets. The thread
     * is not managed by the library, i.e it needs to be created and destroyed by the user.
     * This function has to be invoked before "suricata_handle_packet" or "suricata_handle_stream".
     *
     * \param ctx Pointer to the Suricata context.
     * \return    Pointer to the worker context.
     */
    ThreadVars *suricata_initialise_worker_thread(SuricataCtx *ctx);

This method will return a pointer to an object representing a Suricata worker, in charge of
packet/stream processing. Due to the internal Suricata structure, the client *must* invoke this
method from a separate thread (created and managed by the client).
The library expects that the client creates a number of threads equal to the number of the
*n_workers* parameter provided in the :ref:`suricata_create_ctx` method and that each of these
threads invoke the above API in their routine.

suricata_post_init
~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Suricata post initialization tasks.
     *
     * \param ctx Pointer to the Suricata context.
     */
    void suricata_post_init(SuricataCtx *ctx);

This method performs all the post initialization tasks. It *must* be invoked from the same thread
that invoked :ref:`suricata_create_ctx`, i.e not from a thread creating a Suricata worker.

