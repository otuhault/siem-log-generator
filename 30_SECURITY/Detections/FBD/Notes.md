1. What are the differences between "Findings Risk Threshold Exceeded for Entity Over 24 Hour Period" and "Finding Group Template - Entity Exceeded Risk Threshold" - which should we start using? [8.4 docs](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/detections/finding-based-detections-available-in-splunk-enterprise-security) only reference the former.
-> Use **Finding Group Template - Entity Exceeded Risk Threshold**. The other stays for customers already using it pre 8.4.

2. Regarding the maximum overlap of 50%.. Assuming we save the detection at 3pm.
    1. What happens (assuming a 100 threshold based detection) if we have a risk score of 60 at 2:59am, and a risk score of 60 at 3:01pm for an entity, we would not get an alert for this, right?
    2. With EBD, we would, because we are looking back last 24hrs (running every 5mins) and throttling
    3. What happens if we subsequently update and save the detection at, say, 5pm. Does the max_append_time window get reset to 5pm? Or do we retain the original window from when the detection was first saved?
3. For customers who may want to wait until max_append_time is finished before deciding to investigate a Finding Group, is there any indication in the Finding Group in AQ that the max_append_time window is "closed"? (and thus ready to be investigated without risk of new things getting added)
4. Why would I want an already-created Finding to be added to a Finding Group? Assuming all Findings are already reviewed and triaged as atomic alerts.
    1. In this case, does the Finding get "copied" (with status/disposition etc retained) into the Finding Group, or is it moved?


5. 1. This is always the edge case of FBDs because of the bucketing concept. Overlap helps to address but does not solve.
    2. So yes you can still use traditional RBA RIRs to work in the previous way, the annoying part about them is the not-so-edge-case-but-pretty-frequent-case of an entity that has surpassed a threshold getting another event and creating a new notable, and every event after that until the threshold drops creating a notable. There are approaches on the [RBA github](https://splunk.github.io/rba/searches/deduplicate_notables/) for solving this but I would only recommend for a real SPL ninja. I have some other approaches I'm working on...
    3. The window adapts to when the new detection is saved every time ¯\_(ツ)_/¯
6. Nothing like that; for that approach I would create an AQ filter that looks for _time + 1d or what have you.
7. I think the why is to consolidate investigation/research into one place. Generally I'm more of the mind that RBA+FBDs thrives on risk events / intermediate findings, but also an entity setting off three findings and then the finding group seeing for example this was three separate MITRE tactics later might reveal the interconnection of events that individual investigations might miss.
    1. AFAIK there is a setting that hides findings once they are part of a finding group which can be utilized. As far as maintaining status/disposition I am really not sure, [@Jozef Krakora](https://splunk.enterprise.slack.com/team/U06419DFCUQ) or [@Benjamin Tedesco](https://splunk.enterprise.slack.com/team/U086X3DUPQQ) might know.

splunk.github.io

[Deduplicate Notables - Splunk RBA](https://splunk.github.io/rba/searches/deduplicate_notables/)

# FBD Creation Form
#### Max Append Time (e.g. 1d or 7d)
This is the maximum `lifespan` of a Finding Group (the incident created).
- The benefit: If a user exceeds a score of 100 today, a Finding Group is created. If tomorrow (in 24 hours) they generate a new risk, Splunk looks at the ‘Max Append Time’ .
- If the new risk occurs before the end of the Max Append Time, it is added to the existing group instead of creating a new alert.
- Difference: The Time Picker defines what we are looking for, while the Max Append Time defines how long we keep the incident open to add new elements to it.
#### Finding Group Overlap (Percent vs Time)
This option defines how Splunk decides whether new search results should be merged with an existing group or whether a new one should be created.
- Overlap by Time: If the time window of the new results overlaps with that of an existing group, they merge. This is useful for ongoing attacks.    
- Overlap by Percent: This is more subtle. If, for example, 50% of the findings (individual risk events) detected in the current run are already present in an existing finding group, Splunk considers them to be the same and merges them.
- How to use it effectively?
	- Use Time for detections based on score thresholds (as in your example), as the risk is often cumulative over a period of time.
	- Use Percent to avoid ‘noise’ if a rule repeatedly triggers on the exact same events.


Translated with DeepL.com (free version)
#### Toggle Reopen Finding Groups
- **The scenario:** An analyst investigated a Finding Group and marked it as ‘Closed’.
- **If the button is disabled:** If new risk events occur for this entity, Splunk will create a new Finding Group (a new incident).
- **If the button is enabled (Reopen):** If new events occur, Splunk will reopen the previous incident.
- **The benefit:** This allows you to immediately see that a threat you thought had been dealt with is reappearing on the same target. It is very effective in combating reinfection or incomplete remediation.

