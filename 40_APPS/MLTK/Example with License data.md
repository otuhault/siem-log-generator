### Forecasting
- **Purpose**: To know when you will exceed your licence or predict next week's volume.
- **Recommended algorithm**: StateSpaceForecast (This is the most robust for time series in Splunk, it handles seasonality well, such as the fact that there are fewer logs at the weekend).

```splunk
index=summary_license_daily 
| timechart span=1d sum(total_gb) as total_gb
| fit StateSpaceForecast total_gb holdback=0 forecast_k=7 conf_interval=95 as prediction
| eval "Limite Licence" = 500
| fields _time total_gb prediction "Limite Licence"
```