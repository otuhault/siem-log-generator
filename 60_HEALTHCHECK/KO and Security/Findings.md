### list_storage_passwords capability
Users require access to certain apps and commands they contain (e.g., ipinfo, ldapsearch), but with the needed *list_storage_passwords* capability they can also retrieve clear-text storage passwords via a REST command. 
This creates a direct credential exposure path, increasing the likelihood of secret leakage and unauthorized reuse of third-party tokens/passwords.
```
curl -k -u <username>:<password> https://<splunk_server>:8089/servicesNS/nobody/<app_name>/storage/passwords?output_mode=json`
```     
#### Recommandations
There are multiple ways to address this issue, and they can be combined. 
Mechanisms involved in secret storage management: 

If your app integrates with an external service, that service might require your app’s users to authenticate using a secret. Secrets consist of sensitive data, including passwords, credentials, and API keys, that grant your app’s users access to an external service’s resources and APIs. 

[Manage secret storage | Documentation | Splunk Developer Program](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/secretstorage/) 

**Solution 1 : Role-based access control.** 
[Configure access control for secret storage | Documentation | Splunk Developer Program](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/secretstorage/secretstoragerbac/) 
The idea here is to restrict accesses to passwords, depending on the role the user has. 
Role A has acces to secret A. 
Role B has acces to secret B. 

**Solution 2 : Network allow-list via [storage_passwords_masking] stanza in limits.conf.** 
This approach enables IP-based filtering to allow or deny access to the storage credentials. 
[Secure password storage and access within Splunk | Ideas](https://ideas.splunk.com/ideas/EID-I-297?_gl=1*16o6sw3*_gcl_au*ODQ0NjUwMTEuMTc3MDY1MTExNg..*FPAU*ODQ0NjUwMTEuMTc3MDY1MTExNg..*_ga*NzE2NDQxMDc4LjE3NzA2NTExMTc.*_ga_5EPM2P39FV*czE3NzEzMTgxMDIkbzE0JGcxJHQxNzcxMzE4OTUxJGoyMSRsMCRoMTAzNDE4MTA0NA..*_fplc*bnJGanVNYXcyaER4bnljQVpMYkFvQzJUM011eWxsT1ZSNiUyQm5CekdEVVRXQ0g4a2NhbzdCQkhONGslMkI3MkRjSjVVZlZLdHVwbWdIM2JueUNQVWRZNGl3UjVDSmtvZVdCSkxvR0xCQW9yd3A5WDNvMXY2JTJCalBpTGRiVTlkbmtBJTNEJTNE)

### Some automation jobs run Splunk CLI commands using -auth admin:password
- The command is detected by the EDR and indexed into Splunk 
- The credentials can also be exposed locally through ps aux command and shell history. 
This practice can leak privileged credentials to logs  orlogs or local users with process visibility, creating a high-impact account compromise path.
#### Recommendations 
It will depend on the client’s technical ability to implement them, and on any technical constraints in the current environment. 
- Primary fix: refactor automation to avoid credentials in command-line arguments (use a token / non-interactive auth mechanism and a least-privilege service identity managed in a secrets store). 
- Linux quick wins: ensure the automation context does not persist shell history (e.g. unset HISTFIL, export HISTIGNORE='*splunk *-auth*:*'), and reduce cross-user visibility (e.g. hidepid=2 on /proc mount) of process arguments where feasible (hardening controls). 
- Splunk containment: mask or replace the credential pattern in the EDR data stream before it is indexed in Splunk, using props/transforms mechanisms.

