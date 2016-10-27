Suricata
========

Introduction
------------

Suricata is a network IDS, IPS and NSM engine.


Installation
------------

https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation

User Guide
----------

You can follow the [Suricata user guide](http://suricata.readthedocs.io/en/latest/) to get started.

Our deprecated (but still useful) user guide is also [available](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_User_Guide).


Contributing
------------

We're happily taking patches and other contributions. Please see https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Contributing for how to get started.

Suricata is a complex piece of software dealing with mostly untrusted input. Mishandling this input will have serious consequences:

* in IPS mode a crash may knock a network offline;
* in passive mode a compromise of the IDS may lead to loss of critical and confidential data;
* missed detection may lead to undetected compromise of the network.

In other words, we think the stakes are pretty high, especially since in many common cases the IDS/IPS will be directly reachable by an attacker.

For this reason, we have developed a QA process that is quite extensive. A consequence is that contributing to Suricata can be a somewhat lengthy process.

On a high level, the steps are:

1. Travis-CI based build & unit testing. This runs automatically when a pull request is made.

2. Review by devs from the team and community

3. QA runs



### Overview of Suricata's QA steps

Trusted devs and core team members are able to submit builds to our (semi) public Buildbot instance. It will run a series of build tests and a regression suite to confirm no existing features break.

The final QA run takes a few hours minimally, and is started by Victor. It currently runs:

- extensive build tests on different OS', compilers, optimization levels, configure features
- static code analysis using cppcheck, scan-build
- runtime code analysis using valgrind, DrMemory, AddressSanitizer, LeakSanitizer
- regression tests for past bugs
- output validation of logging
- unix socket testing
- pcap based fuzz testing using ASAN and LSAN

Next to these tests, based on the type of code change further tests can be run manually:

- traffic replay testing (multi-gigabit)
- large pcap collection processing (multi-terabytes)
- AFL based fuzz testing (might take multiple days or even weeks)
- pcap based performance testing
- live performance testing
- various other manual tests based on evaluation of the proposed changes


It's important to realize that almost all of the tests above are used as acceptance tests. If something fails, it's up to you to address this in your code.


One step of the QA is currently run post-merge. We submit builds to the Coverity Scan program. Due to limitations of this (free) service, we can submit once a day max.
Of course it can happen that after the merge the community will find issues. For both cases we request you to help address the issues as they may come up.




### FAQ

__Q: Will you accept my PR?__

A: That depends on a number of things, including the code quality. With new features it also depends on whether the team and/or the community think the feature is useful, how much it affects other code and features, the risk of performance regressions, etc.


__Q: When will my PR be merged?__

A: It depends, if it's a major feature or considered a high risk change, it will probably go into the next major version.


__Q: Why was my PR closed?__

A: As documented in the Suricata Github workflow here https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Github_work_flow, we expect a new pull request for every change.

Normally, the team (or community) will give feedback on a pull request after which it is expected to be replaced by an improved PR. So look at the comments. If you disagree with the comments we can still discuss them in the closed PR.

If the PR was closed without comments it's likely due to QA failure. If the Travis-CI check failed, the PR should be fixed right away. No need for a discussion about it, unless you believe the QA failure is incorrect.


__Q: the compiler/code analyser/tool is wrong, what now?__

A: to assist in the automation of the QA, we're not accepting warnings or errors to stay. In some cases this could mean that we add a suppression if the tool supports that (e.g. valgrind, DrMemory). Some warnings can be disabled. In some exceptional cases the only 'solution' is to refactor the code to work around a static code checker limitation false positive. While frusterating, we prefer this over leaving warnings in the output. Warnings tend to get ignored and then increase risk of hiding other warnings.


__Q: I think your QA test is wrong__

A: If you really think it is, we can discuss how to improve it. But don't come to this conclusion to quickly, moreoften it's the code that turns out to be wrong.


__Q: do you require signing of a contributor license agreement?__

A: Yes, we do this to keep the ownership of Suricata in one hand: the Open Information Security Foundation. See http://suricata-ids.org/about/open-source/ and http://suricata-ids.org/about/contribution-agreement/
