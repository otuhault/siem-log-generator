transforms.conf
```
[tr_linux_secure]   
REGEX    = .   
DEST_KEY = _SYSLOG_ROUTING   
FORMAT   = gr_p10_linux_secure

[secure_routing_disable_to_splunk]
REGEX    = .   
DEST_KEY = _TCP_ROUTING   
FORMAT   =
```

props.conf
```
[linux_secure]   
TRANSFORMS-cl_linux_secure = secure_routing_disable_to_splunk, tr_linux_secure
```

outputs.conf
```
[syslog:gr_p10_linux_secure]   
server = 10.20.30.40:514
type = tcp   
syslogSourceType = sourcetype::linux_secure
```

On HF, linux_secure sourcetype coming through 9997 won't be send to the indexers or default outputs, but will be sent to the syslog output.