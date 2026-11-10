```
index=_introspection sourcetype=splunk_resource_usage component=* earliest=-24h 
| eval swap_used = 'data.mem' - 'data.mem_used' 
| where swap_used > 0 
| stats avg(swap_used) as avg_swap_used max(swap_used) as max_swap_used  by host, component 
| eval avg_swap_used_MB = round(avg_swap_used / 1024 / 1024, 2) , max_swap_used_MB = round(max_swap_used / 1024 / 1024, 2) 
| where avg_swap_used_MB > 0 
| sort -avg_swap_used_MB, max_swap_used_MB
| rename host as "Serveur", component as "Composant", avg_swap_used_MB as "Swap utilisé (MB)", max_swap_used_MB as "Max Swap utilisé(MB)"
| fields - max_swap_used avg_swap_used
```

