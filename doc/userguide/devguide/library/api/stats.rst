Stats
=====

.. _suricata_get_stats:

suricata_get_stats
~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
    * \brief Retrieve suricata stats.
    *
    */
    void suricata_get_stats(void);

The above method allows to compute the engine stats and invoke the corresponding callback.

Counters API
~~~~~~~~~~~~

This set of methods allows to register and manage suricata counters from outside the library.
These counters will be included in the stats reported by :ref:`suricata_get_stats`.

Counters Registration
---------------------

.. code-block:: c

    /**
    * \brief Register a per worker counter.
    *
    *
    * \param tv           Pointer to the per-thread structure.
    * \param counter_name The counter name.
    * \return id          Counter id for the newly registered counter, or the already present counter.
    */
    uint16_t suricata_register_worker_counter(ThreadVars *tv, const char *counter_name);

.. code-block:: c

    /**
    * \brief Register a per worker average counter.
    *
    * The registered counter holds the average of all the values assigned to it.
    *
    * \param tv           Pointer to the per-thread structure.
    * \param counter_name The counter name.
    * \return id          Counter id for the newly registered counter, or the already present counter.
    */
    uint16_t suricata_register_worker_avg_counter(ThreadVars *tv, const char *counter_name);

.. code-block:: c

    /**
    * \brief Register a per worker max counter.
    *
    * The registered counter holds the maximum of all the values assigned to it.
    *
    * \param tv           Pointer to the per-thread structure.
    * \param counter_name The counter name.
    * \return id          Counter id for the newly registered counter, or the already present counter.
    */
    uint16_t suricata_register_worker_max_counter(ThreadVars *tv, const char *counter_name);

The above methods allow to register a per worker regular/average/max counter. These methods return
the id of the registered counter, which is needed to modify the inner value.

A global counter is instead register via the following method:

.. code-block:: c

    /**
    * \brief Register a global counter.
    *
    * The registered counter is managed by the client application (not the library). Thread safety
    * needs to be taken care of if the counter is accessed by multiple threads.
    *
    * \param counter_name The counter name.
    * \param func         Function pointer used to retrieve the counter (uint64_t).
    */
    void suricata_register_global_counter(const char *counter_name, uint64_t (*Func)(void));

The library expects the global counter to be managed by the client. A function to retrieve the
counter value needs to be provided in order for the library to log it properly.

Counters Handling
-----------------

The following methods are used to manage a per worker counter, allowing to add to/increase/set/reset
the counter value.

.. code-block:: c

    /**
    * \brief Adds a value to the worker counter.
    *
    *
    * \param tv           Pointer to the per-thread structure.
    * \param id           The counter id.
    * \param value        The value to add.
    */
    void suricata_worker_counter_add(ThreadVars *tv, uint16_t id, uint64_t value);

.. code-block:: c

    /**
    * \brief Increase the value of the worker counter.
    *
    *
    * \param tv           Pointer to the per-thread structure.
    * \param id           The counter id.
    */
    void suricata_worker_counter_increase(ThreadVars *tv, uint16_t id);

.. code-block:: c

    /**
    * \brief Set the value of the worker counter.
    *
    *
    * \param tv           Pointer to the per-thread structure.
    * \param id           The counter id.
    * \param value        The value to set.
    */
    void suricata_worker_counter_set(ThreadVars *tv, uint16_t id, uint64_t value);

.. code-block:: c

    /**
    * \brief Reset the value of the worker counter.
    *
    *
    * \param tv           Pointer to the per-thread structure.
    * \param id           The counter id.
    */
    void suricata_worker_counter_reset(ThreadVars *tv, uint16_t id);

**Notice** that these methods only work for per worker counters, as global counters are expected to
be managed by the client.