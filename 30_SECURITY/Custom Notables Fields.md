**Notable Customisation**
```splunk-spl
| makeresults 
| eval rule_name="Excessive Failed Logins", 
rule_title="Excessive Failed Logins", 
security_domain="access", 
urgency="low", 
severity="medium", 
signature="Excessive Failed Logins", 
app="OpenVPN", 
category=mvappend("Zero Trust", "Lateral Movement", "IAM Analytics"), drilldown_name="View all login failures by system $src$ for the application $app$", 
drilldown_search="| from datamodel:\"Authentication\".\"Failed_Authentication\" | search src=$src|s$ app=$app|s$", rule_description="The system $src$ has failed $app$ authentication $count$ times using $user_count$ username(s) against $dest_count$ target(s) in the last hour", savedsearch_description="Detects excessive number of failed login attempts (this is likely a brute force attack)", src="92.63.197.94", dest="10.0.1.4", risk_score=45, count=12, dest_count=1, user_count=1, killchain="None", search_name="Access - Excessive Failed Logins - Rule", search_title="Access - Excessive Failed Logins - Rule", annotations.mitre_attack="T1110", annotations.mitre_attack.mitre_tactic="Credential Access", annotations.mitre_attack.mitre_tactic_id="TA0006", annotations.mitre_attack.mitre_technique="Brute Force", annotations.mitre_attack.mitre_technique_id="T1110", notable_type="notable" 
| addinfo 
| sendalert notable param.mapfields=rule_id,rule_name,nes_fields,drilldown_name,drilldown_search,governance,control,default_owner,drilldown_earliest_offset,drilldown_latest_offset,next_steps,investigation_profiles,extract_artifacts,recommended_actions
```

`| eval _raw = mvindex(_raw, 0, 4)`

