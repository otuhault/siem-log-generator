#### org_indexer_volume_indexes
```indexes.conf
[volume:primary]
path = /path/to/index/storage/partition
# ~5 TB
maxVolumeDataSizeMB = 5000000

[volume:_splunk_summaries]
path = /path/to/index/storage/partition
# ~ 100GB
maxVolumeDataSizeMB = 100000
```
#### org_all_indexes
```
[default]
...
[index1]
homePath = volume:primary/index1/db
coldPath = volume:primary/index1/colddb
thawedPath = volume:primary/index1/thaweddb
```

