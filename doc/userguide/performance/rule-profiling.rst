Rule Profiling
==============

::

  --------------------------------------------------------------------------
  Date: 9/5/2013 -- 14:59:58
  --------------------------------------------------------------------------
   Num      Rule         Gid      Rev      Ticks        %      Checks   Matches  Max Ticks   Avg Ticks   Avg Match   Avg No Match
  -------- ------------ -------- -------- ------------ ------ -------- -------- ----------- ----------- ----------- --------------
  1        2210021      1        3        12037        4.96   1        1        12037       12037.00    12037.00    0.00
  2        2210054      1        1        107479       44.26  12       0        35805       8956.58     0.00        8956.58
  3        2210053      1        1        4513         1.86   1        0        4513        4513.00     0.00        4513.00
  4        2210023      1        1        3077         1.27   1        0        3077        3077.00     0.00        3077.00
  5        2210008      1        1        3028         1.25   1        0        3028        3028.00     0.00        3028.00
  6        2210009      1        1        2945         1.21   1        0        2945        2945.00     0.00        2945.00
  7        2210055      1        1        2945         1.21   1        0        2945        2945.00     0.00        2945.00
  8        2210007      1        1        2871         1.18   1        0        2871        2871.00     0.00        2871.00
  9        2210005      1        1        2871         1.18   1        0        2871        2871.00     0.00        2871.00
  10       2210024      1        1        2846         1.17   1        0        2846        2846.00     0.00        2846.00

The meaning of the individual fields:

* Ticks -- total ticks spent on this rule, so a sum of all inspections
* % -- share of this single sig in the total cost of inspection
* Checks -- number of times a signature was inspected
* Matches -- number of times it matched. This may not have resulted in an alert due to suppression and thresholding.
* Max ticks -- single most expensive inspection
* Avg ticks -- per inspection average, so "ticks" / "checks".
* Avg match -- avg ticks spent resulting in match
* Avg No Match -- avg ticks spent resulting in no match.

The "ticks" are CPU clock ticks: http://en.wikipedia.org/wiki/CPU_time
