![[Pasted image 20260713145935.png]]

### 1. Streaming Entity Discovery Sources
- Use *eventtypes* in the format **ea_source_\<id>**
	- index=windows sourcetype=WinEventLogs source=System

I created 2 discovery sources, and then it creates 2 event types:
- ea_source_01 - FwdType -> default search
- ea_source_02 (Streaming Discovery) - index=\_internal sourcetype=splunkd 

### 2. Scheduled Entity Discovery Sources





### Ephemeral Assets and Users
Off by default.
![[Pasted image 20260721151727.png]]
### Field Aging Rules




![[Pasted image 20260721152010.png]]


![[Pasted image 20260721152152.png]]