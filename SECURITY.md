# Security Policy

Being a security tool itself, the security of Suricata itself is naturally of
great importance. This document describes the policy around security issues.


## Severity Levels

We will determine the severity of each issue, taking into account our
experience dealing with past issues, versions affected, common defaults,
and use cases. We use the following severity categories:

* **CRITICAL** Severity. This affects Tier 1 features that are enabled by default
where the issue disrupts availability of the service, leading to severe
loss of visibility and/or availability. RCE, remotely triggerable traffic
based crashes, or evasions with a wide scope are considered to be in-scope
for this severity. These issues will be kept private and will trigger a new
release of all supported versions. We will attempt to address these as soon
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
part of the Changelog as a security ticket and may contain a CVE in the changelog
and commit message, but they may not trigger new releases.


## Support Status of affected code

4 levels are defined: Tier 1, Tier 2, Community and Unmaintained.

These are documented in https://docs.suricata.io/en/latest/support-status.html


## Reporting Issues

For reporting security issues, please use `security@oisf.net`.

If you report a security issue to us, please share as much detail about the issue
as possible: pcaps, attack scripts, potential fixes, etc. If you share pcaps or
other data, please clearly state if these can (eventually) enter our public CI/QA.

We will assign a severity and will share our assessment with you.

We will create a security ticket, which will be private until a few weeks after
a public release addressing the issue.

We will acknowledge you in the release notes, release announcement. If you do not
want this, please clearly state this.

We will not request a CVE, but if you do please let us know the CVE ID.

OISF does not participate in bug bounty programs, or offer any other rewards
for reporting issues.
