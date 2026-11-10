### Saved Searches and cron
```
| rest /servicesNS/-/-/saved/searches splunk_server=local
| where is_scheduled=1 
| table title, cron_schedule 
| rename title as "Saved Search Name"
```

### Index vs Tstats
```
| rest /services/saved/searches splunk_server=local count=0
| eval uses_tstats=if(match(search, "^\|\s*(?:`)?tstats(?:`)?"), "Yes", "No")
| table title, uses_tstats, search, eai:acl.owner, disabled
| sort uses_tstats
```

### List Enabled Correlation Searches with CRON
```
| rest splunk_server=local count=0 /services/saved/searches 
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]") AND disabled=0 
| table title, cron_schedule, action.correlationsearch.enabled
```