### Admission Rules
- Alltime
```
search_time_range=alltime AND NOT (app=splunk_instance_monitoring OR role=sc_admin OR role=ABCDEF)
```
- Wildcard
```
index=* AND ( NOT (role=sc_admin OR role=ABCDEF))
```

