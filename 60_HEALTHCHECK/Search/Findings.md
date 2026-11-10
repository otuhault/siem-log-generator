# List license volume by Retention's index
```
index=_internal source=*license* 
| stats sum(b) as Bytes by index 
| eval BytesMB=round(Bytes/1024/1024, 2) 
| join type=inner Index 
	[ | rest splunk_server=YOURINDEXER /services/data/indexes 
	| eval Retention=frozenTimePeriodInSecs/60/60/24 
	| eval RetentionRange=case( Retention > 0 AND Retention <= 95, "0 et 3 mois", Retention > 95 AND Retention <=175 , "3 mois et 6 mois", Retention > 175 AND Retention <=400 , "6 mois et +", true(), "Autre") 
	| rename title as index ] 
| stats sum(BytesMB) as TotalSizeMB by RetentionRange
```
# Find Crash Logs
```
index=_internal sourcetype=splunkd_crash_log 
| rex "^\[build\s+(?<splunk_build>\w+)" 
| rex "Cause:\s+(?<crash_cause>[^\n\r]+)" 
| rex "Crashing\sthread:\s+(?<crash_thread>\S+)" 
| search crash_thread=* | table _time, host, splunk_build, crash_thread, crash_cause 
| lookup assets.csv host OUTPUT search_group 
| stats count by host
```

# Malformed Saved Searches
ALERT_SavedSearches_with_Error

```
index=_internal host!=monitoringconsole[| rest splunk_server=* splunk_server_group=dmc_group_search_head /services/server/info | fields host] source=*scheduler.log NOT INFO
| rex field=savedsearch_id "^(?<owner>[^;]+);(?<app>[^;]+);(?<savedsearch_name>[^;]+)"
| rex field=event_message "message=\"(?<message>[^\"]*)"
| dedup owner app savedsearch_name message
| table owner app savedsearch_name message
| join type=left owner
[ | rest /services/authentication/users | rename title as owner | table owner email ]
| eval email=if(isnotnull(email), email, "equipesoc2mail.com") 
```
