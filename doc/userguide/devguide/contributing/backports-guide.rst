========================
Suricata Backports Guide
========================

This document describes the processes used to backport content to current stable
Suricata releases. Most often, this means security and/or bug fixes;
however, in some cases, features may be backported to previous Suricata releases.

There are multiple versions of Suricata at any given time:
    * Master
    * Major stable release
    * Old stable release

For example, at the moment, there are 3 releases based on these Suricata branches:
    * master: 8.0.0-dev, current development branch
    * main-7.0.x: major stable release (note we're changing our naming conventions)
    * master-6.0.x: old stable release

For Suricata's release cadence and *end of life* policies, please check
https://suricata.io/our-story/eol-policy/.

The next sections discuss when and what to backport, and some guidelines when
doing so.

What should be backported?
--------------------------

Usually, when the team creates a ticket, we'll add the *Needs backport* related
labels, so necessary backporting tickets will be automatically created. If you
are working on a ticket that doesn't have such labels, nor backporting tasks
associated, it probably doesn't need backporting. If you understand that the
issue should be backported, please let us know in the ticket or related PR. But
sometimes we'll miss those.

The general principle used to determine what will be backported is:
    * security fixes (please see our `Security Policy <https://github.com/OISF/suricata/blob/master/SECURITY.md>`_)
    * bug fixes
    * in some cases, new features are backported if there are sufficient reasons to
      backport a new feature.

.. Note:: Exceptions

    There can be cases where backports may be "missed" -- some issues may not be
    labeled as needing backports and some PRs may be merged without an issue.

    This guide may be insufficient for some situations. When in doubt, please reach
    out to the team on the backport ticket or PR.

Selection overview
------------------

All items considered for backports should be reviewed with the following:
    * risk estimate: will the change introduce new bugs? Consider the scope and
      items affected by the change.
    * behavioral change: how much will the behavior of the system be changed by the
      backport. For example, a small change to decode additional encapsulation
      protocols may result in more traffic being presented to Suricata.
    * default settings: if the issue alters behavior, can it be made optional, and
      at what cost?

Creating backport tickets -- new issues
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Redmine: for security and bug fixes, when creating a new Redmine issue,
label the Redmine issue with "Needs backport to x.0", where x.0 is a supported
Suricata release, e.g, 7.0.x.

Creating backports tickets -- existing issues/PRs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We want to minimize the occurrence of "missed backports" -- that is, work that
should be backported but wasn't. Sometimes this happens when there is no Redmine
issue, or the Redmine issue wasn't labeled as needing a backport.

Therefore, we will be periodically reviewing:
    * Redmine issues without backport labels, including recently closed issues, to
      see which require backport labels.
    * PRs without associated Redmine issues. Those requiring backports should be
      labeled with *needs backport*.

Then, also periodically, we will create backport issues from those items
identified in the previous steps. When doing so, we will evaluate what are the
relevant target backport releases. Some issues reported against master or the
current Suricata release may not apply to older releases.

Git Backport Workflow
---------------------

If you are working on a task that needs to be backported, only start the
backporting process once the PR for master has been merged. Then:

    * *Identify the commit(s) needed* for the backport. Start with the PR that merged
      the commits into master and select only the commits from the issue being
      backported.
    * *Bring each commit into the new branch,* one at a time -- starting with the
      oldest commit. Use ``git cherry-pick -x commit-hash``, where ``commit-hash``
      is the hash to the commit already in master or main-7.0x that is being
      backported, as it maintains the linkage with said cherry-picked commit.
    * *Resolve conflicts:* Some of the cherry-picked commits may contain merge
      conflicts. If the conflicts are small, include the corrections in the
      cherry-picked commit.
    * *Add additional commits*, if any are needed (e.g., to adjust cherry-picked code
      to old behavior).

.. Note:: Commit hashes

   We have a CI check that ensures the validity of the cherry-pick line.

.. Note:: Exceptions

   Sometimes, the fix for master will not work for the stable or old releases.
   In such cases, the backporting process won't be through cherry-picking, but
   through actually implementing a fix for the specific version.

Create a PR:
~~~~~~~~~~~~

Please indicate in the title that this is a backport PR, with something like
*(7.0.x-backport)*, and add the related milestone label.

In the PR description, indicate the backport ticket.

QA
--

Add suricata-verify PRs when needed. Some existing suricata-verify tests may require
version specification changes.

