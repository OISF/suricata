flow.tcp
~~~~~~~~

Type: *cumulative*

Source: *Flow Worker thread(s)*

Number of TCP flows tracked.

flow.udp
~~~~~~~~

Type: *cumulative*

Source: *Flow Worker thread(s)*

Number of UDP flows tracked.

flow.icmpv4
~~~~~~~~~~~

Type: *cumulative*

Source: *Flow Worker thread(s)*

Number of ICMPv4 flows tracked.

flow.icmpv6
~~~~~~~~~~~

Type: *cumulative*

Source: *Flow Worker thread(s)*

Number of ICMPv6 flows tracked.

flow.memuse
~~~~~~~~~~~

Type: *snapshot*

Source: *Global*

Value in bytes of the current memory use by the flow engine. This includes the
space needed for the hash table itself and the preallocated flows in the pool(s).

flow.tcp_reuse
~~~~~~~~~~~~~~

Problem indicator: *if significant share of `flow.tcp`*.

Number of times a flow was part of a TCP reuse. In the reuse case a new TCP session
reuses the same flow but is tracked as if it is new.

flow.get_used
~~~~~~~~~~~~~

Problem indicator: *yes*.

Number of times a flow worker thread got a flow directly from the hash table. This
happens when the pool is empty and there is no memcap budget to allocate a new
flow directly.

flow.mgr.full_hash_pass
~~~~~~~~~~~~~~~~~~~~~~~

Type: *cumulative*

Source: *FlowManager thread(s)*

Number of times the flow hash table has been fully scanned for timed out flows.

The flow manager normally scans it in small steps (slices).

flow.mgr.rows_maxlen
~~~~~~~~~~~~~~~~~~~~

The flow hash table is set up as an array of lists. There is a linked list at
each bucket. The length of this list affects lookup performance, so it should
be short. In the ideal case it will have a length of 1. If this number gets
high, say > 30, its possible the hash table size needs to be increased.

flow.mgr.flows_checked
~~~~~~~~~~~~~~~~~~~~~~

Number of flows checked by the flow manager to see if they are timed out.

flow.mgr.flows_notimeout
~~~~~~~~~~~~~~~~~~~~~~~~

Number of flows that were checked, but did not reach their timeout time yet.

flow.mgr.flows_timeout
~~~~~~~~~~~~~~~~~~~~~~~~

Number of flows that were checked, and did their timeout time.

flow.mgr.flows_evicted
~~~~~~~~~~~~~~~~~~~~~~

Number of flows evicted from the flow hash by the flow manager.

flow.wrk.flows_evicted
~~~~~~~~~~~~~~~~~~~~~~

Number of flows evicted from the flow hash by a packet worker thread. The
workers check the timeout value of flows in the same hash bucket during
flow lookup.

flow.mgr.flows_evicted_needs_work
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Counts flows that have been evicted from the hash, but still need some work.
This usually means some logging is still to be done or there still is TCP
data that hasn't been processed.

flow.wrk.flows_evicted_needs_work
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As `flow.mgr.flows_evicted_needs_work`, but for flows evicted by the worker.

flow.wrk.flows_injected
~~~~~~~~~~~~~~~~~~~~~~~

If the flow manager decided an evicted flow needs more work, it hands this
flow off to the worker thread that processed the flows packets originally.

This counter counts how often this hand off happened.

flow.wrk.flows_evicted_pkt_inject
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a worker processed a flow that needs more work, it will create either
one or two pseudo packets to flush out the remaining work. This counter
counts how many of those packets have been injected/processed.

flow.wrk.spare_sync
~~~~~~~~~~~~~~~~~~~

Number of times a worker thread requested a new pool of flows from the central
flow pool. It keeps these flows in a thread local storage to avoid synchronization.

flow.wrk.spare_sync_avg
~~~~~~~~~~~~~~~~~~~~~~~

A running of average of how many flows the worker got from the central pool during
a sync. If this number starts going down it means there is pressure on the flow
engine, with not enough `memcap` budget available or the flow manager not keeping
up with keeping the pool filled.

flow.wrk.spare_sync_incomplete
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Number of times the worker thread got fewer flows from the central pool than
requested. This is an indicator of flow engine pressure.

flow.wrk.spare_sync_empty
~~~~~~~~~~~~~~~~~~~~~~~~~

As `flow.wrk.spare_sync_incomplete`, but especially counting the times the pool was
completely empty.

