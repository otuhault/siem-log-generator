All Splunk Technology Add-Ons should be installed on the ES Search Head.
- False

When running a | tstats search against a datamodel without summariesonly=true, which behavior will be observed?
- All datamodel results appear, even if they have not been accelerated yet, but it takes longer to run.

Enterprise Security requires a dedicated search head.
- True
- 
Why is | datamodel search slower than regular search?
- It is not based on summarized data.
- It consumes more memory in all cases.
-FAUX **It returns results instead of events.**
- It only runs against cold and thawed data.

-> It load everything into memory and then filters
- for very large datasets, this will always be slower
-> BUT
- There is flexibility
- Returns events using a normalized query


Why does Enterprise Security use | datamodel instead of regular search?
- FAUX**Enterprise Security can not identify available sourcetypes and indexes.**
- Enterprise Security prefers raw events over reports and results from regular search.
- Enterprise Security performs faster with the | datamodel than with regular search.
- -> Je pense celle-ci est juste: Enterprise Security needs advanced users, and the tstats learning curve is steep.

What type of controls provide safeguards or countermeasures to avoid, detect, counteract, or minimize security risks to physical property, information, computer systems, or other assets?
- Security Controls

How are risk rules best defined?
- **Correlation searches that leverage the risk index to surface potential system/user compromises**
- Rules contained only in the SA-RBA app
- None of the above
- Narrowly defined detections/correlations that populate the risk index, can be found in SSE, ES, or ESCU

What is the maximum number of background scheduled searches that will run at once on a system with 16 cores and no hyperthreading, using default settings?
- 8
- **11**

Which of the following is NOT an Enterprise Security Data Model?
	Maleware
	Access
	Authentication
	Network_Traffic


**source** field of a summary index is the name of the search that ran to populate it