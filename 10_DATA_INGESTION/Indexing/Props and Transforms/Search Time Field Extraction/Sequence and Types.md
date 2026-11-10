props.conf documentation: https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/props.conf
# 1. Field Filters
https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/field_filters.conf
*field_filters.conf*
-> Example to be added.
# 2. Inline Field Extraction
``` props.conf
# The following stanza extracts an ip address from _raw
[my_sourcetype]
EXTRACT-extract_ip = (?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```
# 3. Transforms Field Extraction
```props.conf
REPORT-db_object_INSERT = extract_insert_table
* Used for creating extracted fields (search-time field extractions) that
  reference one or more transforms.conf stanzas.
  
TRANSFORMS-<class> = <transform_stanza_name>, <transform_stanza_name2>,...
* Used for creating indexed fields (index-time field extractions).
```

```transforms.conf
[extract_insert_table]
SOURCE_KEY = Full Sql
REGEX = (?i)insert\s+into\s+(?<db_object_INSERT>[a-zA-Z0-9_\$\.@]+)
MV_ADD = true
```

### Why use REPORT if EXTRACT will do?
* Reuse the same field-extracting regular expression across multiple
  sources, source types, or hosts. If you find yourself using the same regex
  to extract fields across several different sources, source types, and
  hosts, set it up as a transform, and then reference it in REPORT
  extractions in those stanzas. If you need to update the regex you only
  have to do it in one place. Handy!
* Apply more than one field-extracting regular expression to the same
  source, source type, or host. This can be necessary in cases where the
  field or fields that you want to extract from a particular source, source
  type, or host appear in two or more very different event patterns.
* Set up delimiter-based field extractions. Useful if your event data
  presents field-value pairs (or just field values) separated by delimiters
  such as commas, spaces, bars, and so on.
* Configure extractions for multivalued fields. You can have Splunk software
  append additional values to a field as it finds them in the event data.
* Extract fields with names beginning with numbers or underscores.
  Ordinarily, the key cleaning functionality removes leading numeric
  characters and underscores from field names. If you need to keep them,
  configure your field transform to turn key cleaning off.
* Manage formatting of extracted fields, in cases where you are extracting
  multiple fields, or are extracting both the field name and field value.

**Precedence rules for TRANSFORMS, REPORT, and EXTRACT field extraction types**
* For each field extraction, Splunk software takes the configuration from the
  highest precedence configuration stanza (see precedence rules at the
  beginning of this file).
* If a particular field extraction is specified for a source and a source
  type, the field extraction for source wins out.
* Similarly, if a particular field extraction is specified in ../local/ for
  a \<spec\>, it overrides that field extraction in ../default/.

# 4. Automatic KV Field Extraction
``` props.conf
KV_MODE = [none|auto|auto_escaped|multi|multi:<multikv.conf_stanza_name>|json|xml]
```

# 5. Field Aliasing
```props.conf
# The following shows how to specify field aliases
FIELDALIAS-foo = user AS myuser id AS myid
```

# 6. Calculated Fields

# 7. Lookups Fields
```props.conf
# The following example shows how to configure lookup tables
[my_lookuptype]
LOOKUP-foo = mylookuptable userid AS myuserid OUTPUT username AS myusername
```

# 8. Event types

# 9. Tags

1. `EXTRACT-<class>` in a stanza in props.conf
2. `REPORT-<class>` in a stanza in props.conf
3. In stanzas in the props.conf file, where `KV_MODE` is set to a valid value other than `none`. If no `KV_MODE` value is specified for a stanza, it is set to `auto` by default.
4. `FIELDALIAS-<class>` in a stanza in the props.conf file.
5. `EVAL-<fieldname>` in a stanza in the props.conf file.
6. `LOOKUP-<class>` in a stanza in the props.conf file.
7. In a stanza in the eventtypes.conf file.
8. In a stanza in the tags.conf file.