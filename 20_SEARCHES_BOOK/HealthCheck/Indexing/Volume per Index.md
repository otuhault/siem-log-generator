```
index=_introspection sourcetype=splunk_disk_objects component=Indexes earliest=-7d@d latest=@d 
| bin _time span=1d 
| stats max(data.total_size) as daily_size by _time, data.name, host 
| stats sum(daily_size) as total_cluster_size by _time, data.name 
| delta total_cluster_size as daily_growth 
| where daily_growth > 0 
| eval daily_GB = round(daily_growth / 1024, 2) 
| stats avg(daily_GB) as avg_GB_per_day, max(daily_GB) as peak_GB_per_day by data.name 
| where avg_GB_per_day >= 10 
| eval avg_GB_per_day = round(avg_GB_per_day, 2), peak_GB_per_day = round(peak_GB_per_day, 2) 
| sort - avg_GB_per_day 
| rename data.name as "Index", avg_GB_per_day as "Moyenne Go/jour", peak_GB_per_day as "Pic Go/jour"
```
