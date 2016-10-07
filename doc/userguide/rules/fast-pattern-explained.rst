Suricata Fast Pattern Determination Explained
=============================================

If the 'fast_pattern' keyword is explicitly set in a rule, Suricata
will use that as the fast pattern match.  The 'fast_pattern' keyword
can only be set once per rule.  If 'fast_pattern' is not set, Suricata
automatically determines the content to use as the fast pattern match.

The following explains the logic Suricata uses to automatically
determine the fast pattern match to use.

Be aware that if there are positive (i.e. non-negated) content
matches, then negated content matches are ignored for fast pattern
determination.  Otherwise, negated content matches are considered.

The fast_pattern selection criteria are as follows:

#. Suricata first identifies all content matches that have the highest
   "priority" that are used in the signature.  The priority is based
   off of the buffer being matched on and generally 'http_*' buffers
   have a higher priority (lower number is higher priority).  See
   :ref:`Appendix B <fast-pattern-explained-appendix-b>` for details
   on which buffers have what priority.
#. Within the content matches identified in step 1 (the highest
   priority content matches), the longest (in terms of character/byte
   length) content match is used as the fast pattern match.
#. If multiple content matches have the same highest priority and
   qualify for the longest length, the one with the highest
   character/byte diversity score ("Pattern Strength") is used as the
   fast pattern match.  See :ref:`Appendix C
   <fast-pattern-explained-appendix-c>` for details on the algorithm
   used to determine Pattern Strength.
#. If multiple content matches have the same highest priority, qualify
   for the longest length, and the same highest Pattern Strength, the
   buffer ("list_id") that was *registered last* is used as the fast
   pattern match.  See :ref:`Appendix B
   <fast-pattern-explained-appendix-b>` for the registration order of
   the different buffers/lists.
#. If multiple content matches have the same highest priority, qualify
   for the longest length, the same highest Pattern Strength, and have
   the same list_id (i.e. are looking in the same buffer), then the
   one that comes first (from left-to-right) in the rule is used as
   the fast pattern match.

It is worth noting that for content matches that have the same
priority, length, and Pattern Strength, 'http_stat_msg',
'http_stat_code', and 'http_method' take precedence over regular
'content' matches.

Appendices
----------

.. _fast-pattern-explained-appendix-a:

Appendix A - Buffers, list_id values, and Registration Order for Suricata 1.3.4
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This should be pretty much the same for Suricata 1.1.x - 1.4.x.

======= ============================== ======================== ==================
list_id Content Modifier Keyword       Buffer Name              Registration Order
======= ============================== ======================== ==================
1       <none> (regular content match) DETECT_SM_LIST_PMATCH    1 (first)
2       http_uri                       DETECT_SM_LIST_UMATCH    2
6       http_client_body               DETECT_SM_LIST_HCBDMATCH 3
7       http_server_body               DETECT_SM_LIST_HSBDMATCH 4
8       http_header                    DETECT_SM_LIST_HHDMATCH  5
9       http_raw_header                DETECT_SM_LIST_HRHDMATCH 6
10      http_method                    DETECT_SM_LIST_HMDMATCH  7
11      http_cookie                    DETECT_SM_LIST_HCDMATCH  8
12      http_raw_uri                   DETECT_SM_LIST_HRUDMATCH 9
13      http_stat_msg                  DETECT_SM_LIST_HSMDMATCH 10
14      http_stat_code                 DETECT_SM_LIST_HSCDMATCH 11
15      http_user_agent                DETECT_SM_LIST_HUADMATCH 12 (last)
======= ============================== ======================== ==================

Note: registration order doesn't matter when it comes to determining the fast pattern match for Suricata 1.3.4 but list_id value does.

.. _fast-pattern-explained-appendix-b:

Appendix B - Buffers, list_id values, Priorities, and Registration Order for Suricata 2.0.7
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This should be pretty much the same for Suricata 2.0.x.

========================================== ================== ============================== ============================= =======
Priority (lower number is higher priority) Registration Order Content Modifier Keyword       Buffer Name                   list_id
========================================== ================== ============================== ============================= =======
3                                          11                 <none> (regular content match) DETECT_SM_LIST_PMATCH         1
3                                          12                 http_method                    DETECT_SM_LIST_HMDMATCH       12
3                                          13                 http_stat_code                 DETECT_SM_LIST_HSCDMATCH      9
3                                          14                 http_stat_msg                  DETECT_SM_LIST_HSMDMATCH      8
2                                          1 (first)          http_client_body               DETECT_SM_LIST_HCBDMATCH      4
2                                          2                  http_server_body               DETECT_SM_LIST_HSBDMATCH      5
2                                          3                  http_header                    DETECT_SM_LIST_HHDMATCH       6
2                                          4                  http_raw_header                DETECT_SM_LIST_HRHDMATCH      7
2                                          5                  http_uri                       DETECT_SM_LIST_UMATCH         2
2                                          6                  http_raw_uri                   DETECT_SM_LIST_HRUDMATCH      3
2                                          7                  http_host                      DETECT_SM_LIST_HHHDMATCH      10
2                                          8                  http_raw_host                  DETECT_SM_LIST_HRHHDMATCH     11
2                                          9                  http_cookie                    DETECT_SM_LIST_HCDMATCH       13
2                                          10                 http_user_agent                DETECT_SM_LIST_HUADMATCH      14
2                                          15 (last)          dns_query                      DETECT_SM_LIST_DNSQUERY_MATCH 20
========================================== ================== ============================== ============================= =======

Note: list_id value doesn't matter when it comes to determining the
fast pattern match for Suricata 2.0.7 but registration order does.

.. _fast-pattern-explained-appendix-c:

Appendix C - Pattern Strength Algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

From detect-engine-mpm.c.  Basically the Pattern Strength "score"
starts at zero and looks at each character/byte in the passed in byte
array from left to right.  If the character/byte has not been seen
before in the array, it adds 3 to the score if it is an alpha
character; else it adds 4 to the score if it is a printable character,
0x00, 0x01, or 0xFF; else it adds 6 to the score.  If the
character/byte has been seen before it adds 1 to the score.  The final
score is returned.

.. code-block:: c

   /** \brief Predict a strength value for patterns
    *
    *  Patterns with high character diversity score higher.
    *  Alpha chars score not so high
    *  Other printable + a few common codes a little higher
    *  Everything else highest.
    *  Longer patterns score better than short patters.
    *
    *  \param pat pattern
    *  \param patlen length of the patternn
    *
    *  \retval s pattern score
    */
    uint32_t PatternStrength(uint8_t *pat, uint16_t patlen) {
	uint8_t a[256];
	memset(&a, 0 ,sizeof(a));
	uint32_t s = 0;
	uint16_t u = 0;
	for (u = 0; u < patlen; u++) {
	    if (a[pat[u]] == 0) {
		if (isalpha(pat[u]))
		    s += 3;
		else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
		    s += 4;
		else
		    s += 6;
		a[pat[u]] = 1;
	    } else {
		s++;
	    }
	}
	return s;
    }
