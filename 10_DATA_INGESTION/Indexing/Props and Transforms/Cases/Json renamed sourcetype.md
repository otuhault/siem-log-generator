Logs ingested via HEC coming with `_json` sourcetype need to be renamed based on a field value.
*props.conf*
```
[host::linux*]
TRANSFORMS-routing = st_linux

[source::dynatrace*]
TRANSFORMS-routing = st_linux
```
*transforms.conf*
```
[st_linux]
REGEX = (?i)"log_type"\s*:\s*"(audit|application)"
DEST_KEY = MetaData:Sourcetype
FORMAT = sourcetype::openshift:k8s::$1
```


On HF:
```
[host::your_hosts*]
sourcetype = openshift_for_idx
```


