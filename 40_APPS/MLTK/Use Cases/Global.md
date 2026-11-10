# Predict Future Ingestion Volume by Index
### With | predict
```
index=summary_license_daily orig_sourcetype=$tok_st$ 
| rename orig_index as Index 
| eval volume=if("$tok_size$"="MB", total_mb, total_gb) 
| stats count by Index 
| map search="search index=summary_license_daily orig_index=\"$$Index$$\" 
    | eval volume=if(\"$tok_size$\"=\"MB\", total_mb, total_gb)
    | timechart span=1d sum(volume) as usage 
    | predict usage algorithm=LLP5 future_timespan=14 holdback=0 
    | eval Index=\"$$Index$$\"" 
| rename prediction(usage) as prediction 
| where _time > now() 
| eval final_value = coalesce(usage, prediction) 
| timechart span=1d min(final_value) as Volume by Index 
| appendcols 
    [| inputlookup license_usage_configuration.csv 
    | head 1 
    | eval limit_mb=license_mb, limit_gb=license_gb 
    | eval license_limit=if("$tok_size$"="MB", limit_mb, limit_gb) 
    | fields license_limit
        ] 
| filldown license_limit 
| eval license_limit=if("$tok_license$"="yes", license_limit, null())
```
### With | fit & | apply
```
index=summary_license_daily orig_sourcetype=$tok_st$ 
| rename orig_index as Index 
| eval volume=if("$tok_size$"="MB", total_mb, total_gb) 
| stats count by Index 
| map search="search index=summary_license_daily orig_index=\"$$Index$$\" 
    | eval volume=if(\"$tok_size$\"=\"MB\", total_mb, total_gb)
    | timechart span=1d sum(volume) as usage 
    | fillnull value=0 
    | fit StateSpaceForecast usage forecast_k=14 conf_interval=95 holdback=0 as prediction 
    | eval Index=\"$$Index$$\"" 
| rename prediction as prediction 
| where _time > now() 
| eval final_value = coalesce(usage, prediction) 
| timechart span=1d min(final_value) as Volume by Index 
| appendcols 
    [| inputlookup license_usage_configuration.csv 
    | head 1 
    | eval limit_mb=license_mb, limit_gb=license_gb 
    | eval license_limit=if("$tok_size$"="MB", limit_mb, limit_gb) 
    | fields license_limit
        ] 
| filldown license_limit 
| eval license_limit=if("$tok_license$"="yes", license_limit, null())
```

```
index=summary_license_daily orig_sourcetype=$tok_st$ 
| rename orig_index as Index 
| eval volume=if("$tok_size$"="MB", total_mb, total_gb) 
| stats count by Index 
| map search="search index=summary_license_daily orig_index=\"$$Index$$\" 
    | eval volume=if(\"$tok_size$\"=\"MB\", total_mb, total_gb)
    | timechart span=1d sum(volume) as usage 
    | fillnull value=0 
    | fit StateSpaceForecast usage forecast_k=14 conf_interval=95 holdback=0 as prediction 
    | eval Index=\"$$Index$$\"" 
| rename prediction as prediction 
| where _time > now() 
| eval final_value = coalesce(usage, prediction) 
| timechart span=1d min(final_value) as Volume by Index 
| appendcols 
    [| inputlookup license_usage_configuration.csv 
    | head 1 
    | eval limit_mb=license_mb, limit_gb=license_gb 
    | eval license_limit=if("$tok_size$"="MB", limit_mb, limit_gb) 
    | fields license_limit
        ] 
| filldown license_limit 
| eval license_limit=if("$tok_license$"="yes", license_limit, null())
```