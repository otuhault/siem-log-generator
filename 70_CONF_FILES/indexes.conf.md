# tsidxReduction
The [tsidx reduction](https://docs.splunk.com/Documentation/Splunk/9.3.1/Indexer/Reducetsidxdiskusage) process eliminates the full-size tsidx files and replaces them with mini versions of those files that contain essential metadata. The rawdata files and some other metadata files remain untouched.
``` indexes.conf
[myIndex]
enableTsidxReduction = true
timePeriodInSecBeforeTsidxReduction = <value in Secondes>

tsidxWritingLevel = [1|2|3|4]
```

```
[myIndex]
frozenTimePeriodInSec - sets the maximum age, in seconds, of data. Once
# *all* of the events in an index bucket are older than this age, the
# bucket will be frozen

maxTotalDataSizeMB - sets the maximum size of the index data, in MBytes,
# over all stages (hot, warm, cold). DEFAULTS TO 500GB - BE SURE TO RAISE FOR LARGE ENVIRONMENTS!

maxDataSize - this constrains how large a *hot* bucket can grow;
# "auto" means 750MB
# "auto_high_volume" means 10GB on 64-bit systems, and 1GB on 32-bit.
# Otherwise, the number is given in MB
# (Default: auto)

maxGlobalDataSizeMB - max size for all warm buckets in a SmartStore index.

maxHotBuckets - sets maximum number of hot buckets that can exist per index.
# default is auto (3) - don't exceed 11 without call with Splunk

maxHotSpanSecs - time before hot rolls to warm. Default: 90days

maxWarmDBCount - max number of warm buckets. Default:300

homePath.maxDataSizeMB - max size of homePath. If exceeded, splunk moves the 
# oldest bucket to coldPath. Default: 0


```


# Volumes
```
[volume1]
path = /splunkdata/hot/
maxVolumeDataSizeMB = 
```

