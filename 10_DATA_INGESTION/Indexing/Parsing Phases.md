What Pipelines do...
- **Input:** Inputs data from source. Source-wide keys, such as source/sourcetypes/hosts, are annotated here. The output of these pipelines are sent to the parsingQueue.
- **Parsing:** Parsing of UTF8 decoding, Line Breaking, and header is done here. This is the first place to split data stream into a single line event. Note that in a Universal Forwarder (UF), this parsing pipeline does "NOT" do parsing jobs. 
- **Merging:** Line Merging for multi-line events and Time Extraction for each event are done here.
- **Typing:** Regex Replacement, Punct. Extractions are done here.
- **IndexPipe:** Tcpout to another Splunk, syslog output, and indexing are done here. In addition, this pipeline is responsible for bytequota, block signing, and indexing metrics such as thruput etc.

Main queues and processors for indexing events
```
[inputs] 
   -> parsingQueue 
   -> Parsing Pipeline [utf8 processor, line breaker, header parsing] 

   -> aggQueue 
   -> Marging Pipeline [date parsing and line merging] 

   -> typingQueue 
   -> Typing Pipeline [regex replacement, punct:: addition] 

   -> indexQueue 
   -> Index Pipeline [tcp output, syslog output, http output, block signing, indexing, indexing metrics]

   -> Disk
```

*NullQueue could be connected from any queueoutput processor by configuration of outputs.conf