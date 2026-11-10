```
index=xxx your search
| table a b c d e field1 field2
| stats values(*) as * min(_time) as _time by field1 field2
| table a b c d e field1 field2
```
Group the events together reducing the number of events by merging field values in the **by**.
