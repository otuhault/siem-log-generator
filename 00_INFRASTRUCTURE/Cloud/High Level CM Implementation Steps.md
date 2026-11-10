# 1. Pre-migration fix-up tasks
- Resolution of critical issues identified during the assessment which act as blockers to the migration taking place
# 2. Custom App (whole app) and Splunkbase App local config vetting
- All config objects destined for Splunk Cloud must be vetted and pass
- Objects that do not pass must be excluded or fixed
- Vetted Apps should be changed once vetted, otherwise the vetting process needs to be run on the changed configuration again. Therefore, a change freeze should be agreed with the customer as part of the planning phase
# 3. Private User knowledge object vetting
- All config objects destined for Splunk Cloud must be vetted and pass
- Objects that do not pass must be excluded or fixed
# 4. Setup SplunkCloud with Splunkbase Apps, customer Authentication integration
- Initial configuration of Splunk Cloud with apps from Splunkbase, configuration for customer authentication systems etc.
- This can be performed in parallel as the vetting process continues as vetting can take time
# 5. Index creation / HEC Token transfer into Splunk Cloud
- Preparation for receiving data into Splunk Cloud
# 6. Transfer of App & User config to Splunk Cloud
- Perform manual transfer of configuration
# 7. Customer Testing / Validation
- Test and validation phase as desired by customer
- This may involve dual forwarding data for a time to simulate the post migration state
# 8. Redirect inputs to Splunk Cloud, close on premise inputs
- Start of cutover phase - only perform once Splunk Cloud is fully prepared
- Not feasible to reverse the process at this stage - should continue in a roll forward to the end
# 9. SmartStore Data Migration
- Perform standard SmartStore Migration - data copies to remote storage
# 10. Validate data copy and close
- Validate all expected data buckets are present in Splunk Cloud and are searchable
- Disconnect on premise from remote storage. Customer can then decommission on premise hardware