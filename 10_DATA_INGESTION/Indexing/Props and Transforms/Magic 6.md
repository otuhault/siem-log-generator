On Indexers and HFs
```
TIME_PREFIX=
TIME_FORMAT=
MAX_TIMESTAMP_LOOKAHEAD=
LINE_BREAKER=
SHOULD_LINEMERGE=
TRUNCATE=
```
On Forwarders:
```
EVENT_BREAKER_ENABLE = true
EVENT_BREAKER =
```

```
TIME_PREFIX=^
TIME_FORMAT=%b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD=15
LINE_BREAKER=([\r\n]+)
SHOULD_LINEMERGE=false
TRUNCATE=10000

EXTRACT-milter_action = \bMilter\b.*\b(?P<milter_action>discard)\b
EXTRACT-pid,qid = ^[^\[\n]*\[(?P<pid>\d+)\]:\s+(?P<qid>\w+)
EXTRACT-spam_pct = Probability(:|=)(?P<spam_pct>\d+)%
```