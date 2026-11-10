### Add origin_uf metadata field 
*inputs.conf*
```
[monitor:///var/log/mylogs/*]
index = xxx
sourcetype = yyy
_meta = origin_uf::StaticValueHere
```

### Set host from a value in the event log
*props.conf*
```
[sourcetype]
TRANSFORMS-extract_host = extract_host
```
*transforms.conf*
```
[extract_host]
SOURCE_KEY = _raw
REGEX = Host:\s(\w+)\s
DEST_KEY = MetaData:Host
FORMAT = host::$1
```
