AppLayerParserTriggerRawStreamReassembly
----------------------------------------

This is a call for immediate reassembly of raw stream data by the Application Layer in case
there is a requirement e.g. upon completion of an HTTP request.

The stream engine provides the following parameters for the stream to be tracked by the different
subsystems of Suricata. These parameters are used to track the progress of the stream in
the respective subsystems. This serves as a communication between the different subsystems
about how far they have already looked into the stream.
They are all relative to the base offset of the streaming buffer region.

* app layer progress
* raw reassembly progress
* streaming logger progress

For a given streaming buffer as follows and a raw stream progress as seen by the detection
engine

.. image:: stream-engine/trigger_reassembly_before.png

Note that there could be any amount of data in the stream but we're only concerned about the
last ACK'd data.

If a call to ``AppLayerParserTriggerRawStreamReassembly`` was made, things would change as follows
allowing the Detection Engine to see a bigger part of the stream until the last ACK was
made.

.. image:: stream-engine/trigger_reassembly_after.png

Please note that the above scenario does not hold as-is for:

* Inline mode
* Gaps in the TCP stream
* Minimum inspection depth setting

There is difference in how the data will be evaluated for these cases.
