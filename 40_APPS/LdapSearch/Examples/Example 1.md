```splunk-spl
| ldapsearch domain="toennies_rhe" search="(objectClass=computer)"
| eval domain = "toennies_rhe"
| table cn,dNSHostName,operatingSystem,operatingSystemVersion,
description,distinguishedName,whenCreated,whenChanged,domain
| append
[| ldapsearch domain="toennies_wsf" search="(objectClass=computer)"
| eval domain = "toennies_wsf"
| table cn,dNSHostName,operatingSystem,operatingSystemVersion,
description,distinguishedName,whenCreated,whenChanged,domain]
| append
[| ldapsearch domain="toennies_soe" search="(objectClass=computer)"
| eval domain = "toennies_soe"
| table cn,dNSHostName,operatingSystem,operatingSystemVersion,
description,distinguishedName,whenCreated,whenChanged,domain]
| collect index=pfg_ldap_summary source=ldap_assets

```
