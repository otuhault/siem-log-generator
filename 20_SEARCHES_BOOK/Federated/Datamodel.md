### Search remote datamodel
```splunk-spl
| tstats count from datamodel = federated:remote_dm_1
WHERE index=index_fs_1 OR index=index_fs_2
```
