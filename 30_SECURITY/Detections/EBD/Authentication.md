```
| tstats count as failure_count, dc(Authentication.src) as unique_sources, values(Authentication.src) as source_ips FROM datamodel=Authentication.Authentication WHERE Authentication.src!=unknown Authentication.action=failure Authentication.app=ssh BY _time span=60m, Authentication.user, Authentication.dest index
| rex field=index "(?<perimeter>[^_]+)"
| `drop_dm_object_name(Authentication)`
```