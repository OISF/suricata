************************
Contributing to Suricata
************************

This guide describes what steps to take if you want to contribute a patch or
patchset to Suricata.
Before you start, please review and sign our `Contribution Agreement
<https://suricata.io/contribution-agreements/>`_.

Open (or claim) a ticket
========================

For features and bugs we need `tickets <https://redmine.openinfosecfoundation.org/projects/suricata/issues>`_. Tickets
help us keep track of the work done, indicate when changes need backports etc.

They are also important if you would like to see your new feature officially
added to our tool: the ticket documents your ideas so  we can analyze how do they
fit in our plans for Suricata, and, if the feature is accepted, we can properly
track progress etc...

For really trivial fixes or cleanups we won't need that.

Assign the ticket to yourself. For this you will need to have the "developer"
role. Please get in touch with us to request this role.

If a ticket is already assigned to someone, please reach out on the ticket or 
ask the person first.
You can reach out to other community members via the `Suricata Discord server
<https://discord.com/invite/t3rV2x7MrG>`_.

Expectations
------------

If you submit a new feature that is not part of Suricata's core functionalities,
it will have the `community supported`_ status. This means we would expect some
commitment from you, or the organization who is sponsoring your work, before we 
could approve the new feature, as the Suricata development team is pretty lean 
(and many times overworked).

This means we expect that:

    * the new contribution comes with a set of Suricata-verify tests (and
      possibly unit tests, where those apply), before we can approve it;
    * proof of compatibility with existing keywords/features is provided,
      when the contribution is for replacing an existing feature;
    * you would maintain the feature once it is approved - or some other 
      community member would do that, in case you cannot.

.. note::

    Regardless of contribution size or complexity, we expect that you respect 
    our guidelines and processes. We appreciate community contributors: 
    Suricata wouldn't be what it is without them; and the value of our tool and
    community also comes from how seriously we take all this, so we ask that 
    our contributors do the same! ;)

.. _community supported:

What does "community supported" and  "supporting a feature" mean?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If a feature is ``community supported``, the Suricata team will try to spend
minimal time on it - to be able to focus on the core functionalities. If for any
reason you're not willing or able to commit to supporting a feature, please
indicate this.

The team and/or community members can then consider offering help. It is best 
to indicate this prior to doing the actual work, because we will reject features
if no one steps up.

It is also important to note that ``community supported`` features  will be
disabled by default, and if it brings in new dependencies (libraries or Rust
crates) those will also be optional and disabled by default.

**Supporting a feature** means to actually *maintain* it:

* fixing bugs
* writing documentation
* keeping it up to date


What branch to work on
======================

There are 2 or 3 active branches:

    * master-x.x.x (e.g. master-6.x.y)
    * master

The former is the stable branch. The latter the development branch. 

The stable branch should only be worked on for important bug fixes. Those are
mainly expected from more experienced contributors.

Development of new features or large scale redesign is done in the development 
branch. New development and new contributors should work with ``master`` except
in very special cases - which should and would be discussed with us first.

If in doubt, please reach out to us on the `Suricata forum 
<https://forum.suricata.io/c/developers/8>`_ or the already mentioned Discord server first.


Create your own branch
======================

It's useful to create descriptive branch names. If you're working on ticket 123
to improve GeoIP? Name your branch "geoip-feature-123-v1". The "-v1" addition 
for feedback. When incorporating feedback you will have to create a new branch
for each pull request. So when you address the first feedback, you will work in
"geoip-feature-123-v2" and so on.

More guidance on creating branches via:

GitHub: `Creating a branch to do your changes <https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Github_work_flow#Creating-a-branch-to-do-your-changes>`_

Git: `Create your branch <https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Git_work_flow#Create-your-branch>`_


Coding Style
============

We have a :ref:`Coding Style` that must be followed.

Commit locally
--------------

Please consider the :ref:`Commits` before submitting.

Send a pull request
-------------------

The pull request is used to request inclusion of your patches into the main 
repository. Before it is merged, it will be reviewed and pushed through a QA
process.

Please consider our :ref:`Pull Requests Criteria` when submitting.

On GitHub we have 'travis-ci' integration enabled. This means some automated 
build and unit tests are performed on the pull request. Generally this is ready
after a few minutes. If the test fails, the pull request won't be considered.

Feedback
--------

You'll likely get some feedback. Even our most experienced devs do, so don't 
feel bad about it.

After discussing the feedback on GitHub or by email, it's time to go back to 
(create your own branch) and do it all again. This process can iterate quite 
a few times.


Merged! Cleanup
---------------

Congrats! Your change has been merged into the main repository. Lets clean up.

You can now delete your branches, both locally and at GitHub.


Update ticket
-------------

You can now put the url of the *merged* pull request in the Redmine ticket.
Next, mark the ticket as "Closed" or "Resolved".
