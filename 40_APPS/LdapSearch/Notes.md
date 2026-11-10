https://splunkbase.splunk.com/app/1151

ldapsearch command:
https://docs.splunk.com/Documentation/SA-LdapSearch/3.2.0/User/Theldapsearchcommand

### Configuration
- Domain name
- Alternate domain name
- Base DN
- Hostname
- Port
- SSL
- Bind DN
- Password
- NTLMv2

### Search
```
| ldapsearch domain="DomainName" search="(&(objectClass=user)(!(objectClass=computer)))"
```


### | collect issue
I very often encountered the problem that, when indexing via the `collect` command, the chunk size was exceeded and too many events had exactly the same timestamp . Particularly in very large environments, this can cause issues with the `LDAPSearch` if the data is to be indexed as `_raw` events.  
Here is the workaround:  
```spl-splunk
| ldapsearch domain=default limit=0 search="(&(objectClass=user)(!(objectClass=computer)))" attrs="*"
| eval memberOf = mvjoin(memberOf,"|")
| rex field=whenChanged ":(?P[0-9]+)+"
| eval event_date = strftime(relative_time(now(),"-0s"), "%Y.%m.%d %H:%M:%S.%3N")
| eval _time = strptime(event_date,"%Y.%m.%d %H:%M:%S.%3N"), _time = _time - (random() % 1000)
| fields - event_date,sec
| eval time_str = strftime(_time, "%Y.%m.%d %H:%M:%S.%3N"), _raw = replace(_raw, "^{", "{"event_time":"" + time_str + "", ")
| collect index=main source="lhm_business_identity_user_collection" addtime=false
```
- get the seconds from the when_changed field
- event_date = just a simple timestamp
- _time = event_date - random value of seconds
- _raw = add the event_time to the _raw json data_
- addtime=false
- source = as identifier of information like user, computer, groups