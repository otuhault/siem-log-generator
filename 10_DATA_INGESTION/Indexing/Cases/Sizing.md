# Measuring the .35 and .15 Factors

• If there is a non-searchable copy of a data bucket within a cluster, youcan measure the size of the "searchable artifacts"
	– Non-searchable copy has only the raw data
• Bucket size is in dbinspect: sizeOnDiskMB, rawSize (bytes)
`splunk search "| dbinspect index=_internal span=1d"`

• Non-searchable copies report 0 for raw size
	– Group by bucketId, compare the two sizeOnDiskMB values
	– Difference shows delta to add "searchability"

# Measuring the 35% - Search
```
| dbinspect index=<INDEX>
| stats max(eval(if(rawSize!=0, sizeOnDiskMB, 0))) AS searchable,
max(eval(if(rawSize=0, sizeOnDiskMB, 0))) AS replica,
max(rawSize) AS raw by bucketId
| search replica!=0
| eval tsidx=searchable - replica, raw_mb=raw / 1024 / 1024
| eval tsidx_pct=round(tsidx/raw_mb * 100, 2), replica_pct=round(replica/raw_mb * 100, 2)
```

# Measuring the 35% - REST
```
| dbinspect index=*
| search path=*/db_*
| join type=outer bucketId
[ | rest splunk_server=local /services/cluster/master/buckets
| fields title bucket_size
| rename title AS bucketId]
| eval compressionRatio=rawSize/bucket_size
| eval journalOnDiskMB=bucket_size/1024/1024
| eval metaOnDiskMB=sizeOnDiskMB-journalOnDiskMB| rename bucket_size AS journal_gz
| table bucketId index journal_gz
```

# Measuring the Size of DMA
```
| rest /services/data/summaries
| search type=data_model_acceleration
| fields name, total_bucket_count, total_size
| rename name AS "Model Title",
total_bucket_count AS "Bucket Count",
total_size AS "Cumulative Usage (MB)"
```
• Model is accelerated per search head GUID
	– Must run on search head where the model is accelerated
# Measuring the Size of RA
```
| rest /services/data/summaries
| search type=report_acceleration
| fields name, total_bucket_count, total_size
| rename name AS "Model Title",
total_bucket_count AS "Bucket Count",
total_size AS "Cumulative Usage (MB)"
```
