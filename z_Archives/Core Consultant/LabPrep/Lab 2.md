LDAP
- [!] Splunk native users take precedence over any LDAP users with the same name.
Base Config App: *org_all_search_base* 
```authentication.conf
[authentication]
authType = LDAP
authSettings = org_ldap_auth

[org_ldap_auth]
SSLEnabled = 1
host = ldap.company.com
port = 636 # If SSL Enabled
# port = 389 # If SSL not Enabled

bindDN = cn=splunk_ldap,ou=accounts,ou=groups,dc=company,dc=com
# bindDNpassword = <password> # Optional

# Where in the LDAP tree are users defined?
userBaseDN = ou=People, dc=company,dc=com
userNameAttribute = uid
realNameAttribute = cn

groupBaseDN = ou=Groups,dc=company,dc=com
groupMemberAttribute = member
groupNameAttribute = cn

[roleMap_org_ldap_auth]
# Remember this is contained somewhere under groupBaseDN
admin = Splunk_Admins
user = Splunk_Users
network = Network_Admins
```

Assign your sccStudent user the admin role by creating a new role "Student"

```authorize.conf
[role_org_custom]
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
srchJobsQuota = 3
importRoles = user
srchIndexesAllowed = main;customer
srchIndexesDefault = customer
These users can only see back one week
srchTimeWin = 7days

  
[role_org_network]
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
importRoles = power;user
rtJobsQuota = 1
srchJobsQuota = 5
srchIndexesAllowed = *
srchIndexesDefault = main;network;firewall
srchTimeWin = 30days

[role_org_admin]
cumulativeRTSrchJobsQuota = 0
cumulativeSrchJobsQuota = 0
admin_all_objects = enabled
srchIndexesAllowed = *;_*
srchIndexesDefault = main
srchTimeWin = 0
```