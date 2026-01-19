.. _devguide-exception-policies:

Exception Policies
##################

This section offers an overview on the Suricata Exception Policies from a
development perspective, for those interested in extending them. For more on
usage, configuration etc, see the chapter `Exception Policies
<https://docs.suricata.io/en/latest/configuration/exception-policies.html>`_.

Exception Policies allow control on how the engine will behave when it reaches
exception scenarios where it could lose visibility into traffic being processed,
for instance.

Briefly, they give the ability to fail close or open, for a set of known
conditions, currently related to (This may be expanded by future work):

    - hitting memory capacity limits;
    - encountering application layer protocol errors;
    - picking a TCP session midstream.

When failing close or open, the chosen policies may affect:

    - individual packets, or
    - the whole flow.

In the Suricata documentation, it is common to refer to anything in this scope
as Exception Policies, but more strictly, what the engine proactively does when
it reaches any of those conditions is an Exception Policy.

Extending
*********

The policy scope should be decided based on what is the setting about, as well
as on its possible impacts. Allowing for a midstream pickup policy to affect
individual packets of a flow, for instance, would only lead to the policy being
effectively applied to every single packet, and thus this isn't allowed.

Besides those aspects, there are differences in impacts when the engine is
running in `IDS` or `IPS` mode.

There are two main ways to extend Suricata adding new Exception Policies:

    - add a new *policy*, that is, a new possible behavior;
    - add a new *exception policy*, that is, covering another exception scenario.

The next sections will cover what are the steps and files to take into account
when extending Suricata Exception Policies.

Adding a New Policy
*******************

This section indicates the main steps and entry points for changes when adding
a new policy.

Currently Suricata supports the following exception policies:

.. literalinclude:: ../../../../../src/util-exception-policy-types.h
    :caption: src/util-exception-policy-types.h
    :language: c
    :start-after: // exception policy docs tag start: exception policy types
    :end-before: // exception policy docs tag end: exception policy types

If a new policy is needed, once it is clear what the new policy type and
nomenclature, will be, the following give an overview of where to go to add
the patch.

For the behavior type and logic:

    - src/util-exception-policy-types.h
    - src/util-exception-policy.c

To indicate whether the new policy is valid for each scenario

    - src/app-layer.c
    - src/decode.c
    - src/stream-tcp.c

Don't forget to document:

    - suricata.yaml.in
    - doc/userguide/configuration/suricata-yaml.rst
    - doc/userguide/configuration/exception-policies.rst

Ensure the new policy is valid in the JSON logs, by adding it to:

    - etc/schema.json

For an example PR on adding a new policy, see:
https://github.com/OISF/suricata/pull/14225/files

Adding a New Exception Policy
*****************************

When the goal is to expand the exception scenarios that the exception policies
cover, the files to modify will depend on what the exception is.

Consider:

    - What is the exception;
    - When to get the Exception Policy setting;
    - At what moment should the policy be applied.

Once you know how it should work, the related function calls are::

    - ExceptionPolicyParse
    - ExceptionPolicyApply

It will also be necessary to update:

    - suricata.yaml.in - to add the new setting options;
    - src/decode.h - ``PacketDropReason`` to add the corresponding drop reason.

Documentation updates:

    - Exception Policy section: add new scenario to tables, add explanations;
    - This DevGuide section, in case new files or exception conditions should be
      listed;
    - Corresponding suricata-yaml section.

For an example PR on adding a new exception policy, see:
https://github.com/OISF/suricata/pull/7791, especially commit
`aa5bb2c329aff5 <https://github.com/OISF/suricata/pull/7791/commits/aa5bb2c329aff59b7811b43258ffd4d95fe7364f>`_.

Testing
*******

For any significant fixes or new features, tests are required. For Exception
Policies, please add Suricata-Verify tests. To learn more about testing Suricata
refer to:

    - :ref:`Suricata Testing: Suricata Verify<testing-suricata-verify>`
    - Suricata-verify: https://github.com/OISF/suricata-verify/blob/master/README.md
    - Suricata Testing 101 - Building Robust Security Tools (SuriCon 2024 talk
      by Haleema Khan and Modupe Falodun): https://www.youtube.com/watch?v=9gOGkrSIcXQ
