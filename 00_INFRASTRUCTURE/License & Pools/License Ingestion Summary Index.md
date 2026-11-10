```
index=_internal source=*license_usage.log* type=Usage
| stats sum(b) as total_bytes by idx,st 
| rename idx as index, st as sourcetype
| eval total_mb = round(total_bytes / 1024 / 1024, 2)
| eval total_gb = round(total_bytes / 1024 / 1024 / 1024, 4)
| fields index sourcetype total_bytes total_mb total_gb
| collect index=summary_license_daily marker="report='volume_by_sourcetype'"
```
