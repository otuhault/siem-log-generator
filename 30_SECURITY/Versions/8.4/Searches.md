# Suivi des Changements de Detection Searches (ES 8.4)
```
index=_configtracker host=XXX "*- Rule" ConfigChange sourcetype=splunk_configuration_change 
| spath data.changes{}.properties{} output=data_path  
| rename data.changes{}.properties{}.* AS *, data.changes{}.* AS *, data.* AS *  
| stats count by _time stanza data_path new_checksum old_checksum modtime  
| rex field=data_path "name\"\:\"(?P<option_name>.*?)\"\,\"new_value\"\:\"(?P<option_new>.*?)\"\,\"old_value\"\:\"(?P<option_old>.*?)\"\}"  
| rex field=option_new mode=sed "s/\"|\\\\//g"  
| rex field=option_new "\sversion\:\s(?P<version>[0-9\.]+)\,\sparent_detection_version\:\s(?P<pre_version>[0-9\.]+)\,"  
| rex field=option_new "\screate_time\:\s(?P<create_time>[0-9\.]+)\,\spublish_time\:\s(?P<publish_time>[0-9\.]+)\,\suser\:\s(?P<user>[A-Za-z0-9\-\_]+)\,"  
| rex field=option_new "\s\[\{\'value\'\:\s\'(?P<change_note>.*?)\'\,\s"  
| rex field=option_new "\sapp_name\:\s(?P<app>.*?)\}"  
| sort 0 stanza option_name _time  
| fields _time stanza modtime option_name new_checksum old_checksum option_new option_old version pre_version change_note user app  
| eval checksum = case(match(option_new,"\w"), old_checksum, match(option_old,"\w"), new_checksum)  
| stats values(*) AS * by option_name checksum  
| eval hash_new = sha1(tostring(option_new)), hash_old = sha1(tostring(option_old))  
| eventstats values(version) AS version values(pre_version) AS pre_version values(change_note) AS change_note values(app) AS app values(user) AS user by stanza checksum  
| where !match(hash_new,hash_old) AND match(hash_new,"\w") AND match(hash_old,"\w")  
| search NOT option_name IN ("*keyindicator.invert*","*.verbose*")  
| eval publish_time = strftime(publish_time,"%Y-%m-%d %H:%M:%S"), create_time = strftime(create_time,"%Y-%m-%d %H:%M:%S")  
| fields user stanza modtime version pre_version change_note option_name option_old option_new  app  
| lookup identity_lookup_expanded identity AS user output name  
| eval user = coalesce(name,user)  
| fields - name  
| rename stanza AS "Detection Name", modtime AS whenChanged, option_name AS OptionName, option_new AS "New Value", option_old AS "Old Value", app AS App, change_note AS "Change Notes", version AS Version, pre_version AS "PreVersion", user AS "Change Owner"
```
