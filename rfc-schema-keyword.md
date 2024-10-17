# Schema-Keyword mapping

This work has started to address an ever-lasting problem of imparity between detection keywords and eve.json outputs. The result of this work should give an overview what fields that are matched by keywords needs to be available in eve.json and vice-versa, on what fields Suricata should do the detection that are already in the output. It can then warn if a keyword/output field is added without proper mapping.
In the end stage this would show keywords by which a user can access the individual eve.json fields. 

## Inputs / Outputs

IN (ground truth):

- `suricata --list-keywords` output for the keywords
- `etc/schema.json` for the eve.json output fields

OUT:

- Primary point for the discussion is the datastructure that will hold the information about keyword-schema relationships and not the "presentation" tool itself. The structure should be simple enough to be hand-editable and maintable. 

To bring this to awareness we might think that http.uri is present in alert, drop, etc. but we need to distinguish an alert event from an alert JSON object. Alert event that is produced to eve.json is composed of miscellaneous objects - e.g. alert (same name), http, flow and other fields. 

## Problem definition

### N-N relationships

Keyword-Schema pairing can have many-to-many relationships. As an example:

- http.uri (eve.json field) is accessed by keywords:
  - http.uri
  - http.uri.raw
  - http.urilen

- fileinfo.filename (eve.json field) is accessed by keywords:
  - file.name
  - filename
  - fileext

- file.name, filename, fileext can access eve.json fields:
  - nfs.filename
  - ftp_data.filename
  - files[].filename
  - fileinfo.filename

### Exceptions

The datastructure should support a case when the pairing is intentionally not done from either side i.e. no need to pair transaction IDs, stats, and other eve.json fields with keywords.

### Extensibility

(Soft requirement?)
Provide a possibility to further alter/extend the relationships in the datastructure.

# Proposed solution (etc/schema-proposal.json)

Considering schema.json already contains the output fields, I believe it can be the most suitable place to hold information about these relationships. Detection keywords can be added to individual output fields, possibly with the use of JSON references. The information can then be centralized and no extra file needs to be created. At the same time, it is simple enough to be hand-editable and it is easy to extend. 

To make it managable in a text editor I thought of describing the relationship primarily in one direction e.g. what eve.json fields are described by what keywords. The other direction, what fields are affected by what keywords, can be obtained by inversing the data structure.

The keyword and the eve.json fields can be in three states (somewhat similar to Git) - tracked, unassigned, ignored.

Currently I think this would be sufficient to add to schema fields (detect-keywords array). Value `ignored` would be used to suppress tracking and reporting of the schema field by the developer-facing tool. A missing `detect-keywords` field / empty array / array containg `unassigned` keyword would signify the field needs to be decided upon or it needs to be paired with a keyword.

```json
properties.http.properties {
                "true_client_ip": {
                    "type": "string"
                },
                "url": {
                    "type": "string",
                    "exact-match": "http.uri.raw",
                    "detect-keywords": [
                        "http.uri.raw",
                        "http.uri",
                        "http.urilen"
                    ]
                },
                "version": {
                    "type": "string"
                },
                ...
}
```

### To detect unassigned schema objects
1) Scan all schema objects and check if they have detect-keywords field and it contains "untracked" or a known keyword
2) Report all that don't have detect-keywords field or it contains "unassigned"

### To detect unassigned keywords
1) Scan all keywords from "suricata --list-keywords" and check if they are assigned to any schema object
2) Report all that are not assigned to any schema object and report all that are assigned but not in the original list


#### Extension

Below I was experimenting with extending the structure and using references. I liked the use of references because it allowed to keep keywords in one place. However as `$ref` objects cannot be extended with extra fields I found it troublesome for the real use. By e.g. exact-match I wanted to describe that the keyword exactly describes the eve.json field and what is seen in the field is matched by the rule (effectively containing the same format, if the buffer is normalized, the content in the keyword is matching also on the normalized variant, etc.) Sometime rules contain integer keywords but eve.json contain the converted string (`dns.rcode`). So I would suggest to rather embed JSON keyword objects into schema fields repetively.


```json
{
    "properties": {
        "files": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "end": {
                        "type": "integer"
                    },
                    "filename": {
                        "type": "string",
                        "detect-keywords": [
                            {
                                "$ref": "#/$keywords/file.name"
                            },
                            {
                                "$ref": "#/$keywords/filename"
                            },
                            {
                                "$ref": "#/$keywords/fileext"
                            }
                        ]
                    },
                    ...
                }
            }
        }
        ...
    },
    "$keywords": {
        "dns.query.name": {
            "type": "string"
        }
        "dns.opcode": {
            "exact-match": true,
            "lua-available": true,
            "type": "integer"
        },
        "dns.rcode": {
            "exact-match": true,
            "lua-available": true,
            "type": "integer"
        },
        "file.name": {
            "type": "string"
        },
        "filename": {
            "type": "string"
        },
        "fileext": {
            "type": "string"
        }


    }
}
```

Note that the exact-match / lua-supported fields are there as an experiment of the relationship enhancement and datastructure extensibility - it is not in the current requirements.

# Other considered solutions

## Database

N-N relationships and extensibility impulsively pushed me towards entering the database design. The task could have been accomplished by setting up separate tables for keywords and schema fields. The third table would describe the relationship between these where additional detail about the relationship can be added. One row might look like `keyword1,schema.field2,exact-match-yes`.

## YAML file

Considering YAML might be a better choice for hand-maintaible information-keeping projects I did gave it a chance. However I was not fond of keeping track of yet another data file. This was the main argument to push for a different approach.
An example of the pairing is below. The exact-match field is an experiment of the relationship enhancement and datastructure extensibility - it is not in the current requirements.

```yaml

keywords:
  - keyword: http.uri
    exact-match: false # if the content of this buffer matches exactly the content of the schema field
    schema-field:
      - http.uri
  - keyword: http.uri.raw
    exact-match: true
    schema-field:
      - http.uri
  - keyword: http.urilen
    exact-match: false
    schema-field:
      - http.uri
  - keyword: unassigned
    schema-field:
      - fileinfo.storing
  - keyword: ignored
    schema-field:
      - stats.capture_packets
      - flow.bypass
```
