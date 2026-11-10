*props.conf*
```
[sourcetype_name]
TRANSFORMS-anonymize = anonymizer

[sourcetype_name]
SEDCMD-anonymizer = s/(Card: )(\d{2})\d{12}(\d{2})/\1\2XXXXXXXXXXXX\3/g

SEDCMD-anonymize = s/Card:\s(\d{2})\d+\s/Card: \1xxxxxxxx/g
```
*transforms.conf*
```
[anonymizer]
REGEX = (.*Card: )(\d{2})\d{12}(\d{2})(.*)
FORMAT = $1$2XXXXXXXXXXXX$3$4
DEST_KEY = _raw
```
