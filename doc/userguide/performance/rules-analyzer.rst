Analyzing Rules and Rulesets
============================

To analyze how rules are affecting performance in Suricata there are a number of tools available.

`--engine-analysis` dumps `rules.json` and `rule_groups.json`.


Finding optimization opportunities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A general rule of thumb is that matching in a more specific buffer is better than a less specific buffer or even in the raw stream.

As an example, lets have a look at the `rule_group.json` from a recent 'ET open' set:

`cat rules.json | jq -c 'select(.app_proto=="http" and .mpm.buffer=="payload")|.raw'`

This outputs all rules that match on the `http` protocol, either because of `alert http` or due to a http keyword such as `http.uri` being in used. Furthermore, it matches on rules where the `fast_pattern` is in the raw payload/stream. Generally stream matching has the highest overhead, so its worth trying to avoid it.

Two examples from the output::

    alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"ET INFO Packed Executable Download\"; flow:established,to_client; content:\"|0d 0a 0d 0a|MZ\"; isdataat:100,relative; content:\"This program \"; distance:0; content:\"PE|00 00|\"; distance:0; content:!\"data\"; within:400; content:!\"text\"; within:400; content:!\"rsrc\"; within:400; classtype:misc-activity; sid:2014819; rev:3; metadata:created_at 2012_05_30, updated_at 2012_05_30;)
    alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"ET POLICY Suspicious Windows Executable WriteProcessMemory\"; flow:established,to_client; content:\"|0d 0a 0d 0a|MZ\"; byte_jump:4,58,relative,little; content:\"PE|00 00|\"; distance:-64; within:4; content:\"WriteProcessMemory\"; nocase; reference:url,sans.org/reading_room/whitepapers/malicious/rss/_33649; reference:url,jessekornblum.livejournal.com/284641.html; reference:url,msdn.microsoft.com/en-us/library/windows/desktop/ms681674%28v=vs.85%29.aspx; classtype:misc-activity; sid:2015588; rev:5; metadata:created_at 2012_08_07, former_category POLICY, updated_at 2012_08_07;)

Both of these match on the end of the headers to make sure the response body starts with `MZ`. There is a simpler and more efficient way to do this: `file.data; content:"MZ"; startswith;`. A change like this is both more performant and more accurate, as it will also work for chunked or compressed HTTP bodies.

If the list is long, it's worth trying to narrow down the list. Since smaller patterns are generally more costly, due the increased likelihood of a match leading to expensive extra validation work, looking at smaller patterns may be worthwhile.

`cat rules.json | jq -c 'select(.app_proto=="http" and .mpm.buffer=="payload" and .mpm.length<5)|.id'`

This gives output like::

    2011499
    2012813
    2012906
    2012907
    2011519
    2003924
    2009897
    2009909
    2012139
    2012969
    2012970
    2013995
    2015045

Lets look at the first:
`cat rules.json | jq -c 'select(.app_proto=="http" and .mpm.buffer=="payload" and .mpm.length<5)'|head -n1|jq`

This gives something like::

    {
        "raw": "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"ET WEB_CLIENT PDF With Embedded Adobe Shockwave Flash Possibly Related to Remote Code Execution Attempt\"; flow:established,to_client; content:\"PDF-\"; depth:300; content:\".swf\"; fast_pattern; nocase; distance:0; flowbits:set,ET.flash.pdf; flowbits:noalert; reference:url,feliam.wordpress.com/2010/02/11/flash-on-a-pdf-with-minipdf-py/; reference:cve,2010-1297; reference:cve,2010-2201; classtype:bad-unknown; sid:2011499; rev:5; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2010_09_27, deployment Perimeter, former_category WEB_CLIENT, signature_severity Major, tag Web_Client_Attacks, updated_at 2017_05_11;)",
        "id": 2011499,
        "gid": 1,
        "rev": 5,
        "msg": "ET WEB_CLIENT PDF With Embedded Adobe Shockwave Flash Possibly Related to Remote Code Execution Attempt",
        "app_proto": "http",
        "requirements": [
            "payload",
            "flow"
        ],
        "flags": [
            "sp_any",
            "dp_any",
            "noalert",
            "applayer",
            "need_packet",
            "need_stream",
            "toclient",
            "prefilter"
        ],
        "pkt_engines": [
        {
            "name": "payload",
            "is_mpm": true,
        },
        {
            "name": "packet",
            "is_mpm": false,
        }
        ],
        "lists": {
            "packet": {
                "matches": [
                {
                    "name": "flow"
                }
                ]
            },
            "packet/stream payload": {
                "matches": [
                {
                    "name": "content",
                    "content": {
                        "pattern": "PDF-",
                        "length": 4,
                        "nocase": false,
                        "negated": false,
                        "starts_with": false,
                        "ends_with": false,
                        "is_mpm": false,
                        "depth": 300,
                        "fast_pattern": false
                    }
                },
                {
                    "name": "content",
                    "content": {
                        "pattern": ".swf",
                        "length": 4,
                        "nocase": true,
                        "negated": false,
                        "starts_with": false,
                        "ends_with": false,
                        "is_mpm": true,
                        "distance": 0,
                        "fast_pattern": true
                    }
                }
                ]
            },
            "post-match": {
                "matches": [
                {
                    "name": "flowbits"
                }
                ]
            }
        },
        "mpm": {
            "buffer": "payload",
            "pattern": ".swf",
            "length": 4,
            "nocase": true,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "distance": 0,
            "fast_pattern": true
        }
    }

Two inefficencies should catch our attention:

1. even though its clear from the sig that the intent is to match on a HTTP response body, on a PDF file even, the matching happens on the raw TCP stream. There is no port limiting, so this pattern will be looked for in all stream data in the toclient direction for every stream on every port.

2. in the `flags` array the presence of `need_packet` is interesting. As the signature uses a pattern with a depth, the pattern will be looked for both in individual packets as well as in the stream data, essentially looking for it in the TCP data twice.

The obvious thing to do here is to change the signature to look for the patterns in the `file.data` buffer::

    file.data; content:"PDF-"; depth:300; content:".swf"; fast_pattern; nocase; distance:0;

After this modification, the analyzer shows a much better result::

    {
        "raw": "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"ET WEB_CLIENT PDF With Embedded Adobe Shockwave Flash, Possibly Related to Remote Code Execution Attempt\"; flow:established,to_client; file.data; content:\"PDF-\"; depth:300; content:\".swf\"; fast_pattern; nocase; distance:0; flowbits:set,ET.flash.pdf; flowbits:noalert; reference:url,feliam.wordpress.com/2010/02/11/flash-on-a-pdf-with-minipdf-py/; reference:cve,2010-1297; reference:cve,2010-2201; classtype:bad-unknown; sid:2011499; rev:4;)",
        "id": 2011499,
        "gid": 1,
        "rev": 4,
        "msg": "ET WEB_CLIENT PDF With Embedded Adobe Shockwave Flash, Possibly Related to Remote Code Execution Attempt",
        "app_proto": "http",
        "requirements": [
            "flow"
        ],
        "flags": [
            "sp_any",
            "dp_any",
            "noalert",
            "applayer",
            "toclient",
            "prefilter"
        ],
        "pkt_engines": [
        {
            "name": "packet",
            "is_mpm": false,
        }
        ],
        "engines": [
        {
            "name": "file_data",
            "direction": "toclient",
            "is_mpm": true,
            "app_proto": "http",
            "progress": 3,
            "matches": [
            {
                "name": "content",
                "content": {
                    "pattern": "PDF-",
                    "length": 4,
                    "nocase": false,
                    "negated": false,
                    "starts_with": false,
                    "ends_with": false,
                    "is_mpm": false,
                    "depth": 300,
                    "fast_pattern": false
                }
            },
            {
                "name": "content",
                "content": {
                    "pattern": ".swf",
                    "length": 4,
                    "nocase": true,
                    "negated": false,
                    "starts_with": false,
                    "ends_with": false,
                    "is_mpm": true,
                    "distance": 0,
                    "fast_pattern": true
                }
            }
            ]
        }
        ],
        "lists": {
            "packet": {
                "matches": [
                {
                    "name": "flow"
                }
                ]
            },
            "post-match": {
                "matches": [
                {
                    "name": "flowbits"
                }
                ]
            }
        },
        "mpm": {
            "buffer": "file_data",
            "pattern": ".swf",
            "length": 4,
            "nocase": true,
            "negated": false,
            "starts_with": false,
            "ends_with": false,
            "is_mpm": true,
            "distance": 0,
            "fast_pattern": true
        }
    }

The `fast_pattern` is now in the `file_data` buffer. In `flags` we see that the `need_packet` and `need_stream` flags are gone.

One thing to keep in mind is that this signature sets a flowbit that other sigs check. Matching the HTTP bodies has bit of a different mechanic than stream data, in that it by default buffers more data before doing the inspection. This means the `set` might occur a bit later in the stream than before. In this particular case this does not seem to be as issue. Better even, it looks like all the related sigs can be converted to using `file.data`, which should improve both performance and accuracy of the set.

