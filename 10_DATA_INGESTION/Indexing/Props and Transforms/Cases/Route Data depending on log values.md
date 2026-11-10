*transforms.conf*
```
[sherlock_routing] 
REGEX = Sherlock 
DEST_KEY = _MetaData:Index 
FORMAT = sherlock 

[watson_routing] 
REGEX = Watson
DEST_KEY = _MetaData:Index 
FORMAT = Watson
```
*props.conf* 
```
[sherlock] 
TRANSFORMS-routing=sherlock_routing, watson_routing
```
