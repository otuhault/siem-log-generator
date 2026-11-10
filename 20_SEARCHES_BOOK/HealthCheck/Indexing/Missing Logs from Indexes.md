```
| tstats count WHERE index=* earliest=-30m latest=-20m by index
| eval period="baseline"
| append [
    | tstats count WHERE index=*)  earliest=-20m latest=-10m by index
    | eval period="current"
]
| stats values(count) as count by index, period
| xyseries index period count
| eval baseline=coalesce(baseline, 0), current=coalesce(current, 0)
| eval drop_percentage=if(baseline>0, round(((baseline-current)/baseline)*100, 2), 0)
| where drop_percentage > 90 OR (baseline > 0 AND current == 0)
| table index, baseline, current, drop_percentage
```
