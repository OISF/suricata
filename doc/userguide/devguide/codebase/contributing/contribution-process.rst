************************
Contributing to Suricata
************************

This guide describes what steps to take if you want to contribute a patch or
patchset to Suricata.

Essentially, these are:

#. Agree to and sign our :ref:`Contribution Agreement<contribution-agreement>`
#. Communicate early, and use the :ref:`preferred channels <communication-channels>`
#. :ref:`claim-ticket`
#. :ref:`Fork from master <what-branch-to-work-on>`
#. Follow our :ref:`Coding Style`
#. Use our :ref:`documentation-style`
#. Stick to our :ref:`commit guidelines<commits>`
#. Add version numbers to your :ref:`Pull Requests <send-a-pull-request>`
#. Incorporate :ref:`feedback` into new PRs
#. [Work merged] :ref:`Wrap up! <wrap-up>`

The rest of this document will cover those in detail.

.. _contribution-agreement:

.. note:: Important!

    Before contributing, please review and sign our `Contribution Agreement
    <https://suricata.io/contribution-agreements/>`_.

.. _communication-channels:

Communication is Key!
=====================

To clarify questions, discuss or suggest new features, talk about bugs and
optimizations, and/or ask for help, it is important to communicate.

These are our main channels:

- `Suricata's issue tracker <https://redmine.openinfosecfoundation.org/
  projects/suricata/issues>`_
- `Suricata's forum <https://forum.suricata.io/c/developers/8>`_
- `Suricata's Discord server <https://discord.com/invite/t3rV2x7MrG>`_


.. _claim-ticket:

Claim (or open) a ticket
========================

For features and bugs we need `tickets <https://redmine.openinfosecfoundation.
org/projects/suricata/issues>`_. Tickets help us keep track of the work done,
indicate when changes need backports etc.

They are also important if you would like to see your new feature officially
added to our tool: the ticket documents your ideas so  we can analyze how do they
fit in our plans for Suricata, and, if the feature is accepted, we can properly
track progress etc.

.. note:: If you want to add new functionalities (e.g. a new application layer
    protocol), please ask us first whether we see that being merged into
    Suricata or not. This helps both sides understand how the new feature will
    fit in our roadmap, and prevents wasting time and motivation with
    contributions that we may not accept. Therefore, `before` starting any code
    related to a new feature, do request comments from the team about it.

For really trivial fixes or cleanups we won't need that.

Once work on the issue has been agreed upon:

Assign the ticket to yourself. For this, you will need to have the "developer"
role. You can ask for that directly on the ticket you want to claim or mention
that you are interested in working on `ticket number` on our `Developer's
channel on Discord <https://discord.com/channels/864648830553292840/
888087709002891324>`_.

If a ticket is already assigned to someone, please reach out on the ticket or
ask the person first.

You can reach out to other community members via `Suricata's Discord server
<https://discord.com/invite/t3rV2x7MrG>`_.


Expectations
============

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
    our contributors do the same!

.. _community supported:

What does "community supported" and  "supporting a feature" mean?
-----------------------------------------------------------------

If a feature is *community supported*, the Suricata team will try to spend
minimal time on it - to be able to focus on the core functionalities. If for any
reason you're not willing or able to commit to supporting a feature, please
indicate this.

The team and/or community members can then consider offering help. It is best
to indicate this prior to doing the actual work, because we will reject features
if no one steps up.

It is also important to note that *community supported* features  will be
disabled by default, and if it brings in new dependencies (libraries or Rust
crates) those will also be optional and disabled by default.

**Supporting a feature** means to actually *maintain* it:

* fixing bugs
* writing documentation
* keeping it up to date
* offering end-user support via forum and/or Discord chat

.. _what-branch-to-work-on:

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

If in doubt, please reach out to us via :ref:`Redmine, Discord or
forum <communication-channels>`.

.. _create-your-own-branch:

Create your own branch
======================

It's useful to create descriptive branch names. You're working on ticket 123 to
improve GeoIP? Name your branch "geoip-feature-123-v1". The "-v1" addition is
for feedback. When incorporating feedback you will have to create a new branch
for each pull request. So, when you address the first feedback, you will work in
"geoip-feature-123-v2" and so on.

For more details check: `Creating a branch to do your changes <https://redmine.
openinfosecfoundation.org/projects/suricata/wiki/Github_work_flow#Creating-a-
branch-to-do-your-changes>`_


Coding Style
============

We have a :ref:`Coding Style` that must be followed.

.. _documentation-style:

Documentation Style
===================

For documenting *code*, please follow Rust documentation and/or Doxygen
guidelines, according to what your contribution is using (Rust or C).

If you are writing or updating *documentation pages*, please:

* wrap up lines at 79 (80 at most) characters;
* when adding diagrams or images, we prefer alternatives that can be generated
  automatically, if possible;
* bear in mind that our documentation is published on `Read the Docs <https:/
  /suricata.readthedocs.io/en/latest/#suricata-user-guide>`_ and can also be
  built to pdf, so it is important that it looks good in such formats.


Commit History matters
======================

Please consider our :ref:`Commit guidelines <commits>` before submitting your PR.

.. _send-a-pull-request:

Send a Pull Request
===================

The pull request is used to request inclusion of your patches into the main
repository. Before it is merged, it will be reviewed and pushed through a QA
process.

Please consider our :ref:`Pull Requests Criteria <pull-requests-criteria>` when
submitting.

We have 'GitHub-CI' integration enabled. This means some automated build check,
suricata-verity and unit tests are performed on the pull request. Generally,
this is ready after a few minutes. If the test fails, the pull request won't be
considered. So please, when you submit something, keep an eye on the checks,
and address any failures - if you do not understand what they are, it is fine to
ask about them on the failing PR itself.

Before merge, we also perform other integration tests in our private QA-lab. If
those fail, we may request further changes, even if the GitHub-CI has passed.

.. _feedback:

Feedback
========

You'll likely get some feedback. Even our most experienced devs do, so don't
feel bad about it.

After discussing what needs to be changed (usually on the PR itself), it's time
to go back to ":ref:`create-your-own-branch`" and do it all again. This process
can iterate quite a few times, as the contribution is refined.

.. _wrap-up:

Wrapping up
===========

Merged! Cleanup
---------------

Congrats! Your change has been merged into the main repository. Many thanks!

We strongly suggest cleaning up: delete your related branches, both locally and
on GitHub - this helps you in keeping things organized when you want to make new
contributions.

.. _update-ticket:

Update ticket
-------------

You can now put the URL of the *merged* pull request in the Redmine ticket.
Next, mark the ticket as "Closed" or "Resolved".

Well done! You are all set now.
