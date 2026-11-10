![[Pasted image 20241205161942.png]]
![[Pasted image 20241205162529.png]]
![[Pasted image 20241205155801.png]]
Deployment Server Scaling
```serverclass.conf
[global]
crossServerChecksum = true

[serverClasss:DS_deployment]
whitelist.0 = DS_enfant
[serverClass:DS_Deployment:app:app1]
stateOnClient = noop
```

```deploymentclient.conf
[deployment-client]
repositoryLocation = /opt/splunk/etc/deployment-apps/
serverRepositoryLocationPolicy = rejectAlways

[target-broker:deploymentServer]
targetUri = ds-parent:8089
```


On DS and Client
/opt/splunk/var/run/serverclass.xml
*In memory*
`./splunk show config serverclass`
*In files*
`./splunk btool serverclass list --debug | grep -v system/default`





![[Pasted image 20241205172327.png]]
![[Pasted image 20241205172957.png]]