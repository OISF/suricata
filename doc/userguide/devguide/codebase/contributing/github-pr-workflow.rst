GitHub PRs workflow
===================

Draft PRs
~~~~~~~~~

A PR should be marked as `draft` if it is not intended to be merged as is,
but is waiting for some sort of feedback.
The author of the PR should explicit what kind of feedback is expected (CI/QA
run, discussion on the code, etc...)

GitHub filter is ``is:pr is:open draft:true sort:updated-asc``

A draft may be closed if it has not been updated in two months.

Mergeable PRs
~~~~~~~~~~~~~

When a Pull Request is intended to be merged as is, the workflow is the following:
 1. get reviewed, and either request changes or get approved
 2. if approved, get staged in a next branch (with other PRs), wait for CI validation
    (and eventually request changes if CI finds anything)
 3. get merged and closed

A newly created PR should match the filter
``is:pr is:open draft:false review:none sort:updated-asc no:assignee``
The whole team is responsible to assign a PR to someone precise within 2 weeks.

When someone gets assigned a PR, the PR should get a review status within 2 weeks:
either changes requested, approved, or assigned to someone else if more expertise is needed.

GitHub filter for changes-requested PRs is ``is:pr is:open draft:false sort:
updated-asc review:changes-requested``

Such a PR may be closed if it has not been updated in two months.
It is expected that the author creates a new PR with a new version of the patch
as described in :ref:`Pull Requests Criteria <pull-requests-criteria>`.

#TODO filter does not work cf https://github.com/OISF/suricata/pull/8898

GitHub filter for approved PRs that should go in a next branch is ``is:pr is:open draft:false sort:updated-asc review:approved``

Command to get approved PRs is ``gh pr list --json number,reviewDecision --search "state:open type:pr -review:none" | jq '.[] | select(.reviewDecision=="")'``

Once in approved state, the PRs are in the responsibility of the merger, along
with the next branches/PRs.
