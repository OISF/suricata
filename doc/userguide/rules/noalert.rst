Alert Keywords
==============

.. role:: example-rule-options

In addition to the action, alerting behavior can be controlled in the rule body using the ``noalert`` and ``alert`` keywords.
Additionally, alerting behavior is controlled by :doc:`thresholding`.

noalert
-------

A rule that specifies ``noalert`` will not generate an alert when it matches, but rule actions will still be performed.

``noalert`` is often used in rules that set a ``flowbit`` for common patterns.

``noalert`` is meant for use with rule actions ``alert``, ``drop``, ``reject`` that all explicitly or implicitly include ``alert``.

.. container:: example-rule

   alert http any any -> any any (http.user_agent; content:"Mozilla/5.0"; startwith; endswith; \
   flowbits:set,mozilla-ua; :example-rule-options:`noalert;` sid:1;)

This example sets a flowbit "mozilla-ua" on matching, but does not generate an alert due to the presence of ``noalert``.

.. note:: this option is also used as ``flowbits:noalert;``, see :doc:`flow-keywords`

alert
-----

A rule that specifies ``alert`` will generate an alert, even if the rule action doesn't imply alerting.

This keyword can be used to implement an "alert then pass"-logic.

.. container:: example-rule

   pass http any any -> any any (http.user_agent; content:"Mozilla/5.0"; startwith; endswith; \
   :example-rule-options:`alert;` sid:1;)

This example would pass the rest of the HTTP flow with the Mozilla/5.0 user-agent, generating an alert for the "pass" event.
