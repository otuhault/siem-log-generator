
| index | sourcetype | drop_percentage | enabled | severity |
| ----- | ---------- | --------------- | ------- | -------- |
| main  | syslog     | 90              | true    | medium   |

```
| tstats count WHERE [ | inputlookup indexes_monitoring.csv | search enabled=true | fields index | format ] earliest=-35m latest=-20m by index
| eval period="baseline"
| append [
    | tstats count WHERE [ | inputlookup indexes_monitoring.csv | search enabled=true | fields index | format ] earliest=-20m latest=-5m by index
    | eval period="current"
]
| stats values(count) as count by index, period
| xyseries index period count
| eval baseline=coalesce(baseline, 0), current=coalesce(current, 0)
| eval drop_percentage=if(baseline>0, round(((baseline-current)/baseline)*100, 2), 0)
| lookup indexes_monitoring.csv index OUTPUT drop_percentage as threshold, severity
| eval threshold=coalesce(threshold, 90)
| eval severity=coalesce(severity, "medium")
| where drop_percentage > threshold OR (baseline > 0 AND current == 0)
| table index, baseline, current, drop_percentage, threshold, severity, owner
```


```spl
| lookup whitelist_horizontal_scan src_ip, dest_port OUTPUT whitelist
| where isnull(whitelist)
| fields - whitelist
```

### Replace Macro for Datamodels

```
[| inputlookup ma_lookup.csv | fields index sourcetype ]
```

```
[| inputlookup ma_lookup.csv
 | eval sourcetype=split(sourcetype, ";")
 | fields index sourcetype ]
```
