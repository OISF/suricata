Code Submission Process
=======================

.. _commits:

Commits
~~~~~~~

#. Commits need to be logically separated. Don't fix unrelated things in one commit.
#. Don't add unnecessary commits, if commit 2 fixes commit 1 merge them together (squash)
#. Commits need to have proper messages, explaining anything that is non-trivial
#. Commits should not, at the same time, change, rename and/or move code. Use
   separate commits for each of this, e.g, a commit to rename files, then a commit
   to change the code.
#. If your code changes or adds new behavior, add the related documentation
   updates in their own commit, but make sure to add the same ticket number to
   both commit messages.
#. Commit messages need to be properly formatted (check the example further below in this section).
      * Meaningful and short (50 chars max) subject line followed by an empty line
      * Naming convention: prefix message with sub-system (**"rule parsing: fixing foobar"**). If
        you're not sure what to use, look at past commits to the file(s) in your PR.
      * Description, wrapped at ~72 characters
#. Commits should be individually compilable, starting with the oldest commit. Make sure that
   each commit can be built if it and the preceding commits in the PR are used.
#. Commits should be authored with the format: "FirstName LastName <name@example.com>"

We recommend that you use git commit message template with the following command:
``git config commit.template /path/to/suricata/git-template/commit-template.txt``
The template lists items that help describe the context and include requisite information in
the commit message. We reserve the right to strictly enforce the template in the future:

Information that needs to be part of a commit (if applicable):

#. Ticket it fixes. E.g. "Fixes Bug #123."
#. Compiler warnings addressed.
#. Coverity Scan issues addressed.
#. Static analyzer error it fixes (cppcheck/scan-build/etc)

.. note::

    When in doubt, check our git history for other messages or changes done to the
    same module your're working on. This is a good example of a `commit message
    <https://github.com/OISF/suricata/commit/33fca4d4db112b75ffa22eb2e6f14f038cbcc1f9>`_::

       pcap/file: normalize file timestamps

       Normalize the timestamps that are too far in the past to epoch.

       Bug: #6240.

.. _pull-requests-criteria:

Pull Requests
~~~~~~~~~~~~~

A github pull request is actually just a pointer to a branch in your tree. GitHub provides a review interface that we use.

#. A branch can only be used in for an individual PR.
#. A branch should not be updated after the pull request
#. A pull request always needs a good description (link to issue tracker if related to a ticket).
#. Incremental pull requests need to link to the prior iteration
#. Incremental pull requests need to describe changes since the last PR
#. Link to the ticket(s) that are addressed to it.
#. When fixing an issue, update the issue status to ``In Review`` after submitting the PR.
#. Pull requests are automatically tested using github actions (https://github.com/OISF/suricata/blob/master/.github/workflows/builds.yml).
   Failing builds won't be considered and should be closed immediately.
#. Pull requests that change, or add a feature should include a documentation update commit

Tests and QA
~~~~~~~~~~~~

As much as possible, new functionality should be easy to QA.

#. Add ``suricata-verify`` tests for verification. See https://github.com/OISF/suricata-verify
#. Add unittests if a ``suricata-verify`` test isn't possible.
#. Provide pcaps that reproduce the problem. Try to trim as much as possible to the pcap includes the minimal
   set of packets that demonstrate the problem.
#. Provide example rules if the code added new keywords or new options to existing keywords
