```
| rest splunk_server=frparsplunkess1.corp.company.com /services/search/distributed/bundle/replication/config 
| eval replicationThreads = case(isnull(replicationThreads), "N/A", isnotnull(replicationThreads), replicationThreads) 
| eval GB = round(26843545600/ 1024 /1024/ 1024, 2 )
```