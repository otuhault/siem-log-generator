# Download & Install SplunkForwarder
```
wget -O splunkforwarder-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/8.2.6.1/linux/splunkforwarder-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz"

sudo tar -xvzf splunk_package_name.tgz -C /opt/

sudo useradd splunk
sudo passwd splunk
sudo chown -R splunk:splunk $SPLUNK_HOME
su - splunk
/opt/splunk/bin/splunk start

alias splunk="/opt/splunkforwarder/bin/splunk"
echo 'alias splunk="/opt/splunkforwarder/bin/splunk"' >> ~/.bashrc

splunk enable boot-start -user splunk
```
# Apps for Clients (pushed manually)
- org_all_deploymentclient
*deploymentclient.conf*
```
[deployment-client]
# Set the phoneHome at the end of the PS engagement
# 10 minutes
# phoneHomeIntervalInSecs = 600

[target-broker:deploymentServer]
targetUri = 10.0.0.4:8089
```
# Apps Deployed
To ensure even data spread we should always have 2x the number of pipelines compared to indexers. As we have 2 indexers and 2 forwarders, our forwarders need to be configured with 2 ingestion pipelines.
- org_APP_TEMPLATE
*server.conf*
``` 
[general]
parallelIngestionPipelines=2
```

*limits.conf* 
```
[thruput]
maxKBps = 0
```

# Best Practices
## SplunkCloud
For intermediate Forwarders:
- use larger forwarders to reduce maintenance issues
	- 24 cores (16 mini), 64GB RAM, 120GB Storage
- allocate enough network bandwidth
	- each UF pipeline can move up to 30 MBps (6 pipelines = 180MBps)
- configure Event Breakers


# Double Routing
```
050_all_forwarder_outputs_on-premise_and_cloud/local/outputs.conf - ON IF

[tcpout]  
defaultGroup = regional_output_group, splunkcloud_<prod stack name>  
autoLBFrequency = 5  
# Implementing blocking, if either on-prem or Splunk Cloud are unavailable,  
# to ensure events are not dropped to either group:  
dropClonedEventsOnQueueFull = -1  
  
# The default target server group can be defined explicitly here  
#[tcpout:regional_output_group]  
#server = server_one:9997, server_two:9997**
--
050_all_forwarder_outputs_on-premise_and_cloud/local/server.conf - ON IF

sslRootCAPath = $SPLUNK_HOME/etc/apps/050_all_forwarder_outputs_route_on-premise_and_cloud/local/base_cacert.pem

```