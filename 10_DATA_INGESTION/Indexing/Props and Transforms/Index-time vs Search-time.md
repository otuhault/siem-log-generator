# Index-time
Index-time processes take place between the point when the data is consumed and the point when it is written to disk.
- [Default field extraction](https://help.splunk.com/?resourceId=Splunk_Data_Aboutdefaultfields) (such as `host`, `source`, `sourcetype`, and `timestamp`)
- [Static or dynamic host assignment for specific inputs](https://help.splunk.com/?resourceId=Splunk_Data_Setadefaulthostforaninput)
- [Default host assignment overrides](https://help.splunk.com/?resourceId=Splunk_Data_Overridedefaulthostassignments)
- [Source type customization](https://help.splunk.com/?resourceId=Splunk_Data_Bypassautomaticsourcetypeassignment)
- [Custom index-time field extraction](https://help.splunk.com/?resourceId=Splunk_Data_Configureindex-timefieldextraction)
- [Structured data field extraction](https://help.splunk.com/?resourceId=Splunk_Data_Extractfieldsfromfileswithstructureddata)
- [Event timestamping](https://help.splunk.com/?resourceId=Splunk_Data_Handleeventtimestamps)
- [Event linebreaking](https://help.splunk.com/?resourceId=Splunk_Data_Configureeventlinebreaking)
- [Event segmentation](https://help.splunk.com/?resourceId=Splunk_Data_Abouteventsegmentation) (also happens at search time)

# Search-time
Search-time processes take place while a search is run, as events are collected by the search.
- [Event segmentation](https://help.splunk.com/?resourceId=Splunk_Data_Abouteventsegmentation) (also happens at index time)
- [Event type matching](https://help.splunk.com/?resourceId=Splunk_Knowledge_Abouteventtypes)
- [Search-time field extraction](https://help.splunk.com/?resourceId=Splunk_Knowledge_Aboutfields) (automatic and custom field extractions, including multivalue fields and calculated fields)
- [Field filters](https://help.splunk.com/?resourceId=Splunk_Security_fieldfilters)
- [Field aliasing](https://help.splunk.com/?resourceId=Splunk_Knowledge_Addaliasestofields)
- [Addition of fields from lookups](https://help.splunk.com/?resourceId=Splunk_Knowledge_Addfieldsfromexternaldatasources)
- [Source type renaming](https://help.splunk.com/?resourceId=Splunk_Data_Renamesourcetypes)
- [Tagging](https://help.splunk.com/?resourceId=Splunk_Knowledge_Abouttagsandaliases)
# Field Extraction
Use the TRANSFORMS field extraction type to create index-time field
extractions. Use the REPORT or EXTRACT field extraction types to create
search-time field extractions.
## Search Time
1. `fieldFilterName` stanza in field_filters.conf
2. `EXTRACT-<class>` in a stanza in props.conf
3. `REPORT-<class>` in a stanza in props.conf
4. In stanzas in the props.conf file, where `KV_MODE` is set to a valid value other than `none`. If no `KV_MODE` value is specified for a stanza, it is set to `auto` by default.
5. `FIELDALIAS-<class>` in a stanza in the props.conf file.
6. `EVAL-<fieldname>` in a stanza in the props.conf file.
7. `LOOKUP-<class>` in a stanza in the props.conf file.
8. In a stanza in the eventtypes.conf file.
9. In a stanza in the tags.conf file.
# Indexing
Inputs > parsingQueue > Parsing Pipeline > indexQueue > Indexing Pipeline