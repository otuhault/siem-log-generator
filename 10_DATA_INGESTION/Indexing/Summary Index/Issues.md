Wrong timestamp when using | collect being overriden 
```
| eval _time = strptime(time, "%Y/%m/%d %H:%M:%S")  
| fields - info_min_time info_max_time info_search_time info_sid
```