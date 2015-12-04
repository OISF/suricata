Live Rule Reloads
=================

As of revision - Suricata version 1.3dev (rev 7109a05), Suricata
supports live rule swap.  In other words if you decide to
change/update/remove/add rules you can do it on the fly without
stopping Suricata.  This is how you can do it.

The live rule reload is available by default without any additional
config changes needed.  Lets say you have started Suricata the regular
way with about 11000 rules:

::

  root@LTS-64-1:~ # suricata -c /etc/suricata/suricata.yaml -v --af-packet
  ....
  [9907] 13/7/2015 -- 14:53:03 - (detect.c:520) <Info> (SigLoadSignatures) -- 50 rule files processed. 16659 rules successfully loaded, 0 rules failed
  [9907] 13/7/2015 -- 14:53:04 - (detect.c:2912) <Info> (SigAddressPrepareStage1) -- 16667 signatures processed. 989 are IP-only rules, 6019 are inspecting packet payload, 12447 inspect application layer, 72 are decoder event only
  [9907] 13/7/2015 -- 14:53:04 - (detect.c:2915) <Info> (SigAddressPrepareStage1) -- building signature grouping structure, stage 1: preprocessing rules... complete
  [9907] 13/7/2015 -- 14:53:04 - (detect.c:3548) <Info> (SigAddressPrepareStage2) -- building signature grouping structure, stage 2: building source address list... complete
  [9907] 13/7/2015 -- 14:53:05 - (detect.c:4194) <Info> (SigAddressPrepareStage3) -- building signature grouping structure, stage 3: building destination address lists... complete
  [9907] 13/7/2015 -- 14:53:06 - (util-threshold-config.c:1176) <Info> (SCThresholdConfParseFile) -- Threshold config parsed: 0 rule(s) found
  [9907] 13/7/2015 -- 14:53:06 - (util-coredump-config.c:122) <Info> (CoredumpLoadConfig) -- Core dump size set to unlimited.
  [9907] 13/7/2015 -- 14:53:06 - (util-logopenfile.c:227) <Info> (SCConfLogOpenGeneric) -- fast output device (regular) initialized: fast.log
  [9907] 13/7/2015 -- 14:53:06 - (util-logopenfile.c:227) <Info> (SCConfLogOpenGeneric) -- eve-log output device (regular) initialized: eve.json
  [9907] 13/7/2015 -- 14:53:06 - (runmodes.c:774) <Info> (RunModeInitializeOutputs) -- enabling 'eve-log' module 'alert'
  [9907] 13/7/2015 -- 14:53:06 - (runmodes.c:774) <Info> (RunModeInitializeOutputs) -- enabling 'eve-log' module 'http'
  [9907] 13/7/2015 -- 14:53:06 - (runmodes.c:774) <Info> (RunModeInitializeOutputs) -- enabling 'eve-log' module 'dns'
  [9907] 13/7/2015 -- 14:53:06 - (runmodes.c:774) <Info> (RunModeInitializeOutputs) -- enabling 'eve-log' module 'tls'
  [9907] 13/7/2015 -- 14:53:06 - (runmodes.c:774) <Info> (RunModeInitializeOutputs) -- enabling 'eve-log' module 'files'
  ....
  ...

But there is a new ruleset update and you have made some changes to
some rules and/or added new ones and you would like to do a live swap.

Find what is the PID of Suricata:

::

  root@LTS-64-1:~ # ps aux |grep suricata
  root      9907 56.9 15.9 840624 410544 pts/0   Sl+  14:52   0:06 suricata -c /etc/suricata/suricata.yaml -v --af-packet
  root@LTS-64-1:~ #

Send the signal:

::

  root@LTS-64-1:~ # kill -USR2 9907

Suricata will now reload the rules:

::

  [9907] 13/7/2015 -- 14:57:11 - (detect.c:520) <Info> (SigLoadSignatures) -- 50 rule files processed. 16659 rules successfully loaded, 0 rules failed
  [9907] 13/7/2015 -- 14:57:11 - (detect.c:2912) <Info> (SigAddressPrepareStage1) -- 16667 signatures processed. 989 are IP-only rules, 6019 are inspecting packet payload, 12447 inspect application layer, 72 are decoder event only
  [9907] 13/7/2015 -- 14:57:11 - (detect.c:2915) <Info> (SigAddressPrepareStage1) -- building signature grouping structure, stage 1: preprocessing rules... complete
  [9907] 13/7/2015 -- 14:57:12 - (detect.c:3548) <Info> (SigAddressPrepareStage2) -- building signature grouping structure, stage 2: building source address list... complete
  [9907] 13/7/2015 -- 14:57:13 - (detect.c:4194) <Info> (SigAddressPrepareStage3) -- building signature grouping structure, stage 3: building destination address lists... complete
  [9907] 13/7/2015 -- 14:57:14 - (util-threshold-config.c:1176) <Info> (SCThresholdConfParseFile) -- Threshold config parsed: 0 rule(s) found
  [9907] 13/7/2015 -- 14:57:14 - (detect-engine.c:543) <Notice> (DetectEngineReloadThreads) -- rule reload starting
  [9907] 13/7/2015 -- 14:57:14 - (detect-engine.c:622) <Info> (DetectEngineReloadThreads) -- Live rule swap has swapped 2 old det_ctx's with new ones, along with the new de_ctx
  [9907] 13/7/2015 -- 14:58:31 - (detect-engine.c:694) <Notice> (DetectEngineReloadThreads) -- rule reload complete
  [9907] 13/7/2015 -- 14:58:31 - (detect.c:4226) <Info> (SigAddressCleanupStage1) -- cleaning up signature grouping structure... complete
