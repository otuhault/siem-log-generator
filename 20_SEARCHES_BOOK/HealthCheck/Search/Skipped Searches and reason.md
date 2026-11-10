```
index=_internal sourcetype=scheduler status=skipped | stats count values(alert_actions) by savedsearch_name, reason
```

Average run time, skipped and deferred
```
index=_internal sourcetype=scheduler earliest=-24h
| eval dispatch_delay=dispatch_time-scheduled_time
| stats count(eval(status="success")) as success
        count(eval(status="skipped")) as skipped
        count(eval(status="deferred")) as deferred
        avg(run_time) as avg_runtime max(run_time) as max_runtime
        avg(dispatch_delay) as avg_dispatch_delay
        by savedsearch_name
| sort - max_runtime
```