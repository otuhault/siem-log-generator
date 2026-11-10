There are six broad categorizations for almost all of the search commands
- distributable streaming
- centralized streaming
- transforming
- generating
- orchestrating
- dataset processing
To optimize your searches, place non-streaming commands as late as possible in your search string.
**Streaming**: Processes events one by one, as they occur (e.g. eval, where).
**Non-streaming**: Requires all data before processing (e.g. stats, sort).
**Distributable**: Can run on indexers in parallel (e.g. eval, search).
**Non-distributable**: Run only on the search head (e.g. stats, eventstats).
### Streaming Command
Operates on each event as it is returned by a search.
- search
- lookup
- where
- eval
#### Distributable Streaming
https://docs.splunk.com/Documentation/Splunk/9.4.1/SearchReference/Commandsbytype#Streaming_commands
Order of the events doesn't matter. 
- rex
- fields
- makemv
- rename
- regex
- replace
- strcat
- typer
- where
-> Streaming commands. One event at a time.
-> Distributable. If all of the commands before can be run on the indexer, the distributable streaming command is run on the indexer.
If any one of the commands before the distributable streaming command must be run on the search head, the remaining commands in the search must be run on the search head. When the search processing moves to the search head, it can't moved back to the indexer.
#### Centralised Streaming Commands
- streamstats
- head
- dedup (certains modes)
- cluster (certains modes)
-> Streaming command. Process one event at a time, event order matters. 
-> Non-distributable commands. Only execute on search head.
#### Generating Commands
- search
- inputlookup
- datamodel
- gentimes
Can be Streaming or Non-Streaming commands.
Can be distributable or not.
### Non-streaming Command
Requires the events from all of the indexers before the command can operate on the entire set of events. Many transforming commands are non-streaming commands.
Several commands that are not transforming but also non-streaming, are most often dataset processing commands.
- sort
- stats
- top
Forces the entire set of events to the search head. Lot of data movement and a loss of parallelism.
#### Transforming Commands
Transform events into data table for statistics or visualisation.
- stats
- chart
- timechart
- top
- rare
-> Non-streaming commands
-> Non-distributable commands. Only execute on search head because requires all the events on the same place.
-> Place these commands after filters.
#### Orchestrating Commands
- noop
- fields
- localize
Does not modify directly the results, but control the search process.
-> Non-streaming
-> Non-distributable
#### Generating Commands
- search
- inputlookup
- datamodel
- gentimes
Can be Streaming or Non-Streaming commands.
Can be distributable or not.
#### Dataset Processing Commands
- sort
- eventstats
- dedup
- fillnull
-> Non-streaming
-> Non-distributable