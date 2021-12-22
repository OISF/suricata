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
-------------

If you submit a new feature that is not part of Suricata's core
functionalities, we would expect some commitment from you or the organization
who is sponsoring your work, before we could approve the new feature, as the
Suricata development team is pretty lean (and many times overworked).

This means we expect that

    * the new contribution comes with a set of Suricata-verify tests (and
      possibly unittests, where those apply), before we can approve it;
    * proof of compability with existing keywords/features is provided,
      when the contribution is for replacing an existing feature;
    * you would maintain the feature once it is approved - or find someone who
      can do that, in case you cannot;
    * you respect our guidelines and processes. We appreciate community
      contributors: Suricata wouldn't be what it is without them; and the
      value of our tool and community also comes from how seriously we take all
      this, and we ask that our contributors do the same! ;)


What branch to work on
======================

There are 2 active branches:

    * master-x.x.x (e.g. master-6.x.y)
    * master

The former is the stable branch. The latter the development branch. The stable 
branch should only be worked on for important bug fixes.

Development of new features or large scale redesign is done in the development 
branch.

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

Github: `Creating a branch to do your changes <https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Github_work_flow#Creating-a-branch-to-do-your-changes>`_

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

You can read more about our `Github workflow <https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Github_work_flow#Pushing-your-branch-to-your-github-repo>`_.

On github we have 'travis-ci' integration enabled. This means some automated 
build and unittests are performed on the pull request. Generally this is ready
after a few minutes. If the test fails, the pull request won't be considered.

Feedback
--------

You'll likely get some feedback. Even our most experienced devs do, so don't 
feel bad about it.

After discussing the feedback on github or by email, it's time to go back to 
(create your own branch) and do it all again. This process can iterate quite 
a few times.


Merged! Cleanup
---------------

Congrats! Your change has been merged into the main repository. Lets clean up.

You can now delete your branches, both locally and at GitHub.


Update ticket
-------------

You can now put the url of the *merged* pull request in the redmine ticket.
Next, mark the ticket as "Closed" or "Resolved".
