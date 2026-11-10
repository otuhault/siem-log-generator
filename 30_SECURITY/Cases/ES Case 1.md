#incident #investigation #openfindings
**To cut a long story short:**  
my current client wanted specific reports for incident handling, and it had repeatedly come to their attention that open findings within a closed investigation were skewing the statistics. As it isn’t possible to find these specific open findings in Mission Control, I wrote a small search tool to make this easier.  
  
```splunk-spl
| inputlookup mc_findings_lookup
| fields create_time parent_incidents assignee  notable_id source status name
| stats values(*) AS * by parent_incidents
| lookup mc_investigations_lookup _key AS parent_incidents OUTPUT display_id , status AS investigation_status, name AS Investigation_Name
| fields create_time parent_incidents display_id assignee Investigation_Name  status investigation_status notable_id source name
| lookup local=true user_realnames_lookup user as assignee OUTPUTNEW realname
| lookup local=true reviewstatuses_lookup _key as status OUTPUTNEW label as incident_label
| lookup local=true reviewstatuses_lookup _key as investigation_status OUTPUTNEW label as investigation_label
| eval validation = case(status=investigation_status, "OK", match(incident_label,"Closed") AND match(investigation_label,"Closed"), "OK",  true(), "ISSUE")
| search validation="ISSUE" AND investigation_label="*Closed*"
| fields create_time realname Investigation_Name display_id notable_id source name incident_label investigation_label
| `ctime(create_time)`
| rename investivation_label AS Investigation_Status, incident_label AS Finding_Status, name AS Finding_Name, notable_id AS Finding_ID, realname AS Analyst, create_time AS Investigation_Start, source AS Detection, display_id AS Investigation_ID, investigation_label AS Investigation_Status
```
