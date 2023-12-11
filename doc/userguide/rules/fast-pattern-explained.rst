Suricata Fast Pattern Determination Explained
=============================================

If the 'fast_pattern' keyword is explicitly set in a rule, Suricata
will use that as the fast pattern match. The 'fast_pattern' keyword
can only be set once per rule. If 'fast_pattern' is not set, Suricata
automatically determines the content to use as the fast pattern match.

The following explains the logic Suricata uses to automatically
determine the fast pattern match to use.

Be aware that if there are positive (i.e. non-negated) content
matches, then negated content matches are ignored for fast pattern
determination. Otherwise, negated content matches are considered.

The fast_pattern selection criteria are as follows:

#. Suricata first identifies all content matches that have the highest
   "priority" that are used in the signature.  The priority is based
   off of the buffer being matched on and generally application layer buffers
   have a higher priority (lower number is higher priority). The buffer
   `http_method` is an exception and has lower priority than the general 
   `content` buffer.
#. Within the content matches identified in step 1 (the highest
   priority content matches), the longest (in terms of character/byte
   length) content match is used as the fast pattern match.
#. If multiple content matches have the same highest priority and
   qualify for the longest length, the one with the highest
   character/byte diversity score ("Pattern Strength") is used as the
   fast pattern match.  See :ref:`Appendix A
   <fast-pattern-explained-appendix-a>` for details on the algorithm
   used to determine Pattern Strength.
#. If multiple content matches have the same highest priority, qualify
   for the longest length, and the same highest Pattern Strength, the
   buffer ("list_id") that was *registered last* is used as the fast
   pattern match.
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

Appendix A - Pattern Strength Algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

From detect-engine-mpm.c. Basically the Pattern Strength "score"
starts at zero and looks at each character/byte in the passed in byte
array from left to right. If the character/byte has not been seen
before in the array, it adds 3 to the score if it is an alpha
character; else it adds 4 to the score if it is a printable character,
0x00, 0x01, or 0xFF; else it adds 6 to the score. If the
character/byte has been seen before it adds 1 to the score. The final
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
    *  \param patlen length of the pattern
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
