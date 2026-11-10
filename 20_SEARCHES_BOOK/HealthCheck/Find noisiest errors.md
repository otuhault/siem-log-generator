```
index=_internal sourcetype=splunkd log_level=ERROR 
| stats values(host) as host dc(host) as nb_host first(_raw) count by punct 
| sort - count , nb_host
```
