Making sense out of Alerts
==========================

When alert happens it's important to figure out what it means. Is it
serious? Relevant? A false positive?

To find out more about the rule that fired, it's always a good idea to
look at the actual rule.

The first thing to look at in a rule is the description that follows
the "msg" keyword. Lets consider an example:

::

  msg:"ET SCAN sipscan probe";

The "ET" indicates the rule came from the Emerging Threats
project. "SCAN" indicates the purpose of the rule is to match on some
form of scanning. Following that a more or less detailed description
is given.

Most rules contain some pointers to more information in the form of
the "reference" keyword.

Consider the following example rule:

::


  alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS \
    (msg:"ET CURRENT_EVENTS Adobe 0day Shovelware"; \
    flow:established,to_server; content:"GET "; nocase; depth:4; \
    content:!"|0d 0a|Referer\:"; nocase; \
    uricontent:"/ppp/listdir.php?dir="; \
    pcre:"/\/[a-z]{2}\/[a-z]{4}01\/ppp\/listdir\.php\?dir=/U"; \
    classtype:trojan-activity; \
    reference:url,isc.sans.org/diary.html?storyid=7747; \
    reference:url,doc.emergingthreats.net/2010496; \
    reference:url,www.emergingthreats.net/cgi-bin/cvsweb.cgi/sigs/CURRENT_EVENTS/CURRENT_Adobe; \
    sid:2010496; rev:2;)

In this rule the reference keyword indicates 3 url's to visit for more
information:

::

  isc.sans.org/diary.html?storyid=7747
  doc.emergingthreats.net/2010496
  www.emergingthreats.net/cgi-bin/cvsweb.cgi/sigs/CURRENT_EVENTS/CURRENT_Adobe

Some rules contain a reference like: "reference:cve,2009-3958;" should
allow you to find info about the specific CVE using your favourite
search engine.

It's not always straight forward and sometimes not all of that
information is available publicly. Usually asking about it on the
signature support lists helps a lot then.

For the Emerging Threats list this is:
http://lists.emergingthreats.net/mailman/listinfo/emerging-sigs

For the VRT ruleset:
https://lists.sourceforge.net/lists/listinfo/snort-sigs

In many cases, looking at just the alert and the packet that triggered
it won't be enough to be conclusive. When running an IDS engine like
Suricata, it's always recommended to combine it with full packet
capturing. Using tools like Sguil or Snorby, the full TCP session or
UDP flow can be inspected.

For example, if a rule fired that indicates your web application is
attacked, looking at the full TCP session might reveal that the web
application replied with 404 not found. This will usually mean the
attack failed. Usually, not always.

Obviously there is a lot more to Incidence Response, but this should
get you started.
