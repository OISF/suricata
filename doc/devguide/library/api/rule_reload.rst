Rule Reload
===========

suricata_engine_reload
~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
    * \brief Reload the detection engine (rule set).
    *
    * \param ctx Pointer to the Suricata context.
    */
    void suricata_engine_reload(SuricataCtx *ctx);

The above method allows to reload the suricata signature set.
Notice that this method should be invoked by the main thread (**NOT** from a worker thread).