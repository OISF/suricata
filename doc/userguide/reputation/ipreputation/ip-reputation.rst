IP Reputation
=============

.. toctree::

   ip-reputation-config
   ip-reputation-rules
   ip-reputation-format

The purpose of the IP reputation component is the ranking of IP Addresses within the Suricata Engine.  It will collect, store, update and distribute reputation intelligence on IP Addresses.  The hub and spoke architecture will allows the central database (The Hub) to collect, store and compile updated IP reputation details that are then distributed to user-side sensor databases (Spokes) for inclusion in user security systems.  The reputation data update frequency and security action taken, is defined in the user security configuration.

The intent of IP Reputation is to allow sharing of intelligence regarding a vast number of IP addresses. This can be positive or negative intelligence classified into a number of categories. The technical implementation requires three major efforts; engine integration, the hub that redistributes reputation, and the communication protocol between hubs and sensors.  The hub will have a number of responsibilities. This will be a separate module running on a separate system as any sensor. Most often it would run on a central database that all sensors already have communication with. It will be able to subscribe to one or more external feeds.   The local admin should be able to define the feeds to be subscribed to, provide authentication credentials if required, and give a weight to that feed. The weight can be an overall number or a by category weight. This will allow the admin to minimize the influence a feed has on their overall reputation if they distrust a particular category or feed, or trust another implicitly. Feeds can be configured to accept feedback or not and will report so on connect. The admin can override and choose not to give any feedback, but the sensor should report these to the Hub upstream on connect.  The hub will take all of these feeds and aggregate them into an average single score for each IP or IP Block, and then redistribute this data to all local sensors as configured. It should receive connections from sensors. The sensor will have to provide authentication and will provide feedback. The hub should redistribute that feedback from sensors to all other sensors as well as up to any feeds that accept feedback.  The hub should also have an API to allow outside statistical analysis to be done to the database and fed back in to the stream. For instance a local site may choose to change the reputation on all Russian IP blocks, etc.


For more information about IP Reputation see :doc:`ip-reputation-config`, :doc:`ip-reputation-rules` and :doc:`ip-reputation-format`.
