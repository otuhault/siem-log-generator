```
| rest /services/apps/local splunk_server=local 
| table title, version, update.version 
| rename title AS "Application", version AS "Version actuelle", update.version AS "Version disponible"
| search "Version disponible"=*
```