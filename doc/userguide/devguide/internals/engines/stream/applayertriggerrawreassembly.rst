Triggering Raw Stream Reassembly from Application Layer
-------------------------------------------------------

Function ``AppLayerParserTriggerRawStreamReassembly``

This is a call for immediate reassembly of raw stream data by the Application Layer to make
more data available for detection e.g. upon completion of an HTTP request as the
Application Layer may not have access to all the data that has been seen by the stream engine
at a point in time.

The stream engine provides the following parameters for the stream to be tracked by the different
subsystems of Suricata.

* app layer progress
* raw reassembly progress
* streaming logger progress

These parameters are used to track the progress of the stream in the respective subsystems.
This serves as a communication between the different subsystems about how far they have
already looked into the stream. They are all relative to the base offset of the streaming
buffer region.

For a given streaming buffer region as follows

.. image:: stream-engine/trigger_reassembly_before.png

If a call to ``AppLayerParserTriggerRawStreamReassembly`` was made, things would change as follows
allowing the Detection Engine to see a bigger part of the stream until the last ACK as seen by the
stream engine.

.. image:: stream-engine/trigger_reassembly_after.png

Note that there could be any amount of data in the stream but we're only concerned about the
last ACK'd data.

Terms displayed in the diagrams:

* ``Base offset``: Offset of the streaming buffer region w.r.t. the actual stream.
* ``ACK'd data``: The indicator of position in the streaming buffer region till which the last ACK was seen.
* ``Raw Stream Progress``: This indicates where in the stream the detection engine has already inspected, so it's a "bookmark" of sorts to keep track of where the last inspection left off and from what offset a next call should consider inspection.

Please note that the above scenario does not hold as-is for:

* Inline mode
* Gaps in the TCP stream
* Minimum inspection depth setting

The data is evaluated differently for these cases.
