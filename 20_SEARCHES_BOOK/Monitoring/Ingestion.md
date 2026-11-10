### Monitoring data loss
```splunk-spl
| tstats latest(_time) as lastTime where index=* earliest=-30d by host, sourcetype
| eval gap_minutes = round((now() - lastTime)/60, 0)
| eval status = if(gap_minutes > 60, "MISSING", "OK")
| where status = "MISSING"
```

