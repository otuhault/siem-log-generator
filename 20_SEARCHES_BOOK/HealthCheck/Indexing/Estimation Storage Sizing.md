
```
| rest /services/data/indexes 
| eval Retention=frozenTimePeriodInSecs/60/60/24 
| rename title as Index 
| join type=inner Index [
    | search index=_internal source=*license* 
    | stats sum(b) as Bytes by index 
    | eval BytesMB=round(Bytes/1024/1024, 2) 
    | rename index as Index
]
| stats sum(BytesMB) as TotalMB by Retention 
| eval RetentionRange=case(
    Retention > 0 AND Retention <= 95, "0 et 3 mois",
    Retention > 95 AND Retention <=175 , "3 mois et 6 mois",
    Retention > 175 AND Retention <=400 , "6 mois et +",
    true(), "Autre"
)
| stats sum(TotalMB) as TotalSizeMB by RetentionRange
```

