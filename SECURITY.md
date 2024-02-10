# Security Policy

Being a security tool itself, the security of Suricata itself is naturally of
great importance. This document describes the policy around security issues as
well as how to report them.

If you believe you found a vulnerability, please report it to us as described
in this document.


## Severity Levels

We will determine the severity of each issue, taking into account our
experience dealing with past issues, versions affected, common defaults,
our estimate of exploitation complexity, part of the code affected,
and use cases. We use the following severity categories:

* **CRITICAL** Severity. This affects Tier 1 features that are enabled by default
where the issue disrupts availability of the service, leading to severe
loss of visibility and/or availability. Remotely triggerable traffic
based code execution, crashes, or evasions with a wide scope are considered to be
in-scope for this severity. These issues will be kept private and will trigger a
new release of all supported versions. We will attempt to address these as soon
as possible.

* **HIGH** Severity. This includes issues that are of a lower risk than critical,
perhaps due to being disabled by default Tier 1 or affecting Tier 2 and
Community features, or which are less likely to be exploitable. These issues
will be kept private and will trigger a new release of all supported versions.
We will attempt to keep the time these issues are private to a minimum; our
aim would be no longer than a month where this is something under our control.

* **MODERATE** Severity. This includes issues like crashes or evasion in Tier 2 and
Community features that are not enabled by default. These will in general be
kept private until the next release, and that release will be scheduled so
that it can roll up several such flaws at one time.

* **LOW** Severity. This includes issues such as those that only affect the
Suricata command line utilities, or unlikely configurations. These will in
general be fixed as soon as possible in latest development versions, and may be
backported to older versions that are still getting updates. These will be
part of the Changelog as a security ticket, but they may not trigger new
releases.

Note that we'll be refining the levels based on our experiences with applying them
to actual issues.

## CVE ID's and Github Security Advisories (GHSA)

We will request a CVE ID for an issue if appropriate. Note that multiple
issues may share the same CVE ID.

We work with the Github CNA, through the Github Security Advisory (GHSA) facility.

The GHSA's will be published at least 2 weeks after the public release addressing
the issue, together with the redmine security tickets.

## Support Status of affected code

4 levels are defined: Tier 1, Tier 2, Community and Unmaintained.

These are documented in https://docs.suricata.io/en/latest/support-status.html


## Reporting Issues

For reporting security issues, please use `security@oisf.net`.

If you report a security issue to us, please share as much detail about the issue
as possible: pcaps, attack scripts, potential fixes, etc. If you share pcaps or
other data, please clearly state if these can (eventually) enter our public CI/QA.

We will assign a severity and will share our assessment with you.

We will create a security ticket, which will be private until at least 2 weeks after
a public release addressing the issue.

We will acknowledge you in the release notes, release announcement and GHSA. If you
do not want this, please clearly state this. For the GHSA credits, please give us
your github handle.

Please let us know if you've requested a CVE ID. If you haven't, we can do it.

OISF does not participate in bug bounty programs, or offer any other rewards
for reporting issues.
