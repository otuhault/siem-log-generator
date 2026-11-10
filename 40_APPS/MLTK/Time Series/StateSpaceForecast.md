```
| fit StateSpaceForecast TotalMB forecast_k=14 conf_interval=95 holdback=0 as prediction
````



### Predict Futur Ingestion
```
index=summary_license_daily 
| timechart span=1d sum(total_mb) as TotalMB 
| fit StateSpaceForecast TotalMB forecast_k=14 conf_interval=95 holdback=0 as prediction | eval prediction = if(isnotnull(TotalMB), null(), prediction) 
| search prediction=* 
| appendcols 
[ | inputlookup license_usage_configuration.csv 
| head 1 | eval limit_mb=license_mb, limit_gb=license_gb 
| eval license_limit=if("$tok_size$"="MB", limit_mb, limit_gb) 
| fields license_limit ] 
| filldown license_limit 
| eval license_limit=if("$tok_license$"="yes", license_limit, null()) 
| fields _time TotalMB prediction license_limit
```



