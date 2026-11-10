# Accreditation Architect Practice Lab 1

## Download & Install Splunk on SearchHead, then others
Create a splunk user and password on your host server 
- sudo adduser splunk
Download & Install Splunk:
```
wget -O splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/8.2.6.1/linux/splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz"

sudo tar -xvzf splunk_package_name.tgz -C /opt/
```
Start Splunk as root
- /opt/splunk/bin/splunk start
- --> enter admin and admin password

It says: "The splunk user and group have already been configured on all hosts." But steps before we had to create the splunk user...

Start Splunk as non-root user
```
useradd splunk
passwd splunk
chown -R splunk:splunk $SPLUNK_HOME
su - splunk
$SPLUNK_HOME/bin/splunk start
alias splunk="/opt/splunk/bin/splunk"
```
Enable booting Splunk as non-root user
- `[sudo] $SPLUNK_HOME/bin/splunk enable boot-start -user bob`
- `[sudo] chown -R bob $SPLUNK_HOME`

Using the same instructions as above install Splunk on the remaining instances: 
1. Access the command line interface on your host. 
2. Create your splunk user. 
3. Download Splunk Enterprise 
4. Install Splunk as root. 
5. For the admin password, use the password found in your Server list. 
6. Run Splunk as splunk user. 
7. Enable Splunk to start on boot as the splunk user.

## Indexers Configuration
- Copy the `org_all_indexer_base` template app to your /opt/splunk/etc/apps folder.  This template has an inputs.conf with a listening port preconfigured. 
	- `scp -r org_app/ user@instance:/tmp`
- Rename the app to `ap1_all_indexer_base`.
>This sort of rename should always be performed on any base template apps implemented.
- Go through each configuration file and validate the settings that are enabled and uncommented.
- Ensure the **permissions** on your copied apps are owned by the **splunk user**.
- **Restart Splunk** to apply the configurations from the template app. 
- Check the receiver status with the following command as the splunk user: `/opt/splunk/bin/splunk display listen`
- Repeat the same steps on your second indexer
## Distributed Search - SH & MC
Differents ways to do it:
### Web
- Settings > Distributed Search > Search Peers > New
Enter information (required http:// or https://)
### CLI
```
./splunk add search-server https://192.168.1.1:8089 -auth admin:password -remoteUsername admin -remotePassword passremote
```
### Distribute the key files
If you add search peers via Splunk Web or the CLI, Splunk Enterprise automatically configures authentication. However, if you add peers by editing `distsearch.conf`, you must distribute the key files manually. After adding the search peers and restarting the search head, as described above:
**1.** Copy the file `$SPLUNK_HOME/etc/auth/distServerKeys/trusted.pem` from the search head to `$SPLUNK_HOME/etc/auth/distServerKeys/<searchhead_name>/trusted.pem` on each search peer.
The `<searchhead_name>` is the search head's `serverName`, specified in [server.conf](http://docs.splunk.com/Documentation/Splunk/9.3.0/admin/Serverconf).
**2.** Restart each search peer.
- restart splunk
## distsearch.conf in etc/system/local/server.conf
```
[distributedSearch]
servers = https://192.168.1.1:8089,https://192.168.1.2:8089
```
>Ensure that you also add the search head as a distributed search peer to the MC.
## Configuring Monitoring Console
https://docs.splunk.com/Documentation/Splunk/latest/DMC/DMCoverview
https://docs.splunk.com/Documentation/Splunk/latest/DMC/Configureindistributedmode
- Monitoring Console > Settings > General Setup


# Accreditation Architect Practice Lab 2
## Configuration - SH, IDXs, MC
ssh sccStudent@

As before - On each host excluding your new uf host: 
1. Create A splunk User 
2. Download Splunk Enterprise Version 8.2.6.1 
3. Install Splunk as Root 
4. Change the default Admin Password (Use the password provided in your Server list) 
5. Run Splunk as a Non-Root User 
6. Enable Splunk to Start on Boot as the Splunk User 
7. Configure Your Indexers
8. Configure Distributed Search
9. Configure the Monitoring Console
>Make sure to rename all of your base configuration templates with the correct prefix ap2_
## Configuration UF
```
wget -O splunkforwarder-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/8.2.6.1/linux/splunkforwarder-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz"
```
Repeat above tasks: 1, 2, 3, 4, 5, 6
## Configure all nodes as Deployment Client
- `scp -r org_all_deployment_client` -> **ap_2_all_deployment_client** on MC, IDX and UFs
**Modify deploymentclient.conf** to match the SH url
> put https:// in front of targetUri
## Configure Forwarding
- `org_all_forwarder_outputs` -> **ap2_all_forwarder_outputs** and modify outputs.conf and add the 2 indexers. Put the app on both etc/apps and etc/deployment-apps of the SH
- restart splunk on all deployment clients
## Configure the serverclass1- All Forwarders
- New serverclass: All_Forwarders
- whitelist: \*-uf1 , \*-mc1
- add: ap2_all_forwarder_outputs to the serverclass with restart splunkd on update
- From your search head run the following search to check your work `index=_internal | stats count by host`
- should see 5 instances
## Configure and Deploy TA for unix and linux
- Put the app on apps/ and deployment-apps/ of the SH
- Enable the needed inputs (create a local/inputs.conf + disabled=false)
- Use `org_all_indexes_base` to create os index -> ap2_all_indexes
> don't forget to uncomment volume in indexes.conf
## Configure the serverclass2- All Linux Host
- New serverclass: All_Linux_Hosts
- Add the Nix_TA to the serverclass
- Add the ap2_all_forwarder_outputs to the serverclass with restart splunkd on update
- Use a machinetypesfilter of "linux-x86_64" and a whitelist of "*"
- Manually copy the add-on to the apps/ folder on your search head
- From your search head run the following search to check your work. index=os | stats count by host. You should see results from your all 5 of your instances.


# Accreditation Architect Practice Lab 3
## Configuration of Distributed Search Infrastructure - sh, idx, mc
1. Create a splunk user. 
2. Download Splunk Enterprise Version 8.2.6.1 
3. Install Splunk as Root. 
4. Change the default admin password. (Use the password provided in your Server list) 
5. Run Splunk as a non-root User. 
6. Enable Splunk to start on boot as the splunk user. 
7. Configure your indexers. 
8. Configure distributed search. 
9. Configure the Monitoring Console.
## Deploy the Universal Forwarders - 4 uf & 2 iuf
1. Create a splunk user. 
2. Download Splunk Universal Forwarder for the version of Splunk 8.2.6.1
3. Install Splunk as Root 
4. Change the default admin password. (Use the password provided in your Server list) 
5. Ensure Splunk will run as the splunk user. 
6. Use the `org_all_deployentclient` template to create and configure an **ap3_deploymentclient** app that calls into the Search Head based deployment server. 
The following servers will also need to be configured as deployment clients: 
	• Monitoring Console 
	• Indexers 
	• Universal Forwarders 
7. Using the Forwarder Management UI on the Search Head confirm that all 9 clients have phoned home to the Deployment Server.
## Serverclass1 - Internal Forwarders
1. Use the base configuration template `org_all_forwarder_outputs` to configure your Intermediate Forwarders to send their logs to your Indexers. The app should be renamed **ap3_internal_forwarder_outputs**. 
2. Update the server list under the [tcpout:primary_indexers] stanza in outputs.conf with your indexers. 
3. Copy the same forwarder outputs app to both the apps/ and deployment-apps/ folders on your search head. This will ensure that the Search Head internal logs are forwarded to the indexing tier in the same manner as the forwarder.
4. Restart Splunk to ensure you configura2on app is applied on the Search Head.

# Distributed Search Migration Lab 4
Current state is All In One server aio1
Goal is to go into distributed architecture, with aio1 becoming an indexer (idx2), + 1 sh, 1mc, 1idx
org = cfrtl4

>**You’ll need to use the bare (public) IP address**
## Deploy and Install Splunk on the New Instances – idx1, sh1, and mc1
```
wget -O splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/8.2.6.1/linux/splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz"

sudo tar -xvzf splunk_package_name.tgz -C /opt/

useradd splunk
passwd splunk
chown -R splunk:splunk $SPLUNK_HOME
su - splunk
alias splunk="/opt/splunk/bin/splunk"
echo 'alias splunk="/opt/splunk/bin/splunk"' >> ~/.bashrc
/opt/splunk/bin/splunk start
splunk enable boot-start -user splunk
```
## Prepare Deployment Server Content
SH will be the DS and License Master.
DeploymentClient Configurations:
- org_all_deploymentclient
Indexers Configuration:
- org_all_indexer_base
- org_all_indexes
- org_full_license_server
- org_indexer_volume_indexes
Search Head Configurations:
- org_all_search_base
- org_all_forwarder_outputs
- org_search_volume_indexes
## Configure the New Indexer and the MC as deployment clients
Deploy cfrtl4 into the idx1 and mc1

## Reclaim Settings from an Existing Node
- Edit the $SPLUNK_HOME/etc/system/local/server.conf selng in [general] for serverName; change this to \_idx2, e.g. “cfrtl4_1234_idx2”.
- Use btool in debug mode to iden2fy where the selngs for the “onboarding” index was written by the GUI.
- Collect these settings and add them to your customized org_all_indexes app on the DS.
- Update the homePath and coldPath as needed to reflect the volume specification from that template app.
- Again, leveraging btool, locate the props.conf and transforms.conf (if any) for the sourcetypes listed here: volume-iops, edifecs, sshd_syslog and iis_onboarding.
		`splunk btool props list --debug | grep volume-iops`
	- for each sourcetype, create a new org_APP_TEMPLATE app:
		- cfrtl4_sourcetype_volume-iops_props, ...
	- Place each props and transforms respectively in the apps
## Make the Single Instance a Deployment Client
- On the AIO, stop splunk
- Rename or Remove the props and transforms file identified above
- Copy the org_all_deploymentclient app to etc/apps
- start splunk
## Use the DS to Ensure Uniform Configuration

# Implementation Practice Lab 5
## Establish Deployment Client Connectivity
`org_all_deployment` with targetUri adjusted
Push it to the forwarder and the DS
Check on the DS we can see the forwarder as a client
## Identify Data Onboarding Parameters
```
[email_log]
TIME_PREFIX=^
TIME_FORMAT=%b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD=15
LINE_BREAKER=([\r\n]+)
SHOULD_LINEMERGE=false
TRUNCATE=10000
```

![[Pasted image 20240829153955.png]]
From the forwarder, check the format of the logs and prepare the magic6
Clone the org_APP_TEMPLATE app for props settings. NOTE: Make sure to call out the sourcetype of the data and props in the name of the configuration app.
ot_sourcetype_email_log_props
Push the app to the standalone and restart splunk

NOTE: Utilize the org_dept_app_inputs within the base configs you downloaded in the beginning of the lab for a sample inputs.conf. 
2. Set the destination index to “maildata”. 
3. Set the sourcetype of this data to “email_log”. 
4. Copy this to the deployment-apps folder on the DS.

5. Clone the base config app “org_all_forwarder_outputs”, and adjust the ‘server’ parameter in the tcpout:primary_indexers group to reflect the (single) IP address of the all-in-one instance. 
6. Copy this app into the deployment-apps folder on the DS as well. 
7. Now, utilizing the Forwarder Management GUI, create a server class to contain the forwarder.
## Create Search-Time Extractions
Observe that each event contains the string ‘sm-mta’ followed by a number enclosed in square brackets ( [ ] ), a colon, and followed in turn by a string of 14 characters and a colon. 
2. Craft a field extraction to extract the digits as a new field called “pid”. 
3. Craft a field extraction to collect the 14-character string as a field called “qid”. 
4. Narrow the search for events by adding the keyword “milter” to the search bar. 
5. Observe the returned events.
>NOTE: Note that some feature the string “Milter: data, discard”. An important metric for the administrators of this email system is the count of dropped or discarded messages. 
6. Extract this “discard” string as a new field “milter_action”. 
7. Narrow these results even further by adding the additional keywords “add header” (your search string should read index=maildata milter add header. 
>NOTE: Some of these events feature a “probability” value indicating the likelihood that the message is, in fact, spam email. 
9. Capture probability value (numeric part only) as a new field called “spam_pct”. 
10. These new sejngs also live in props.conf (and maybe transforms.conf, depending upon how you built the field extraction rules), so be sure to place these new entries in the appropriate app (the same one you created for the data onboarding props).
## Build the Dashboard
1. Open the Apps menu (top le:), then select "Manage Apps". 
2. On the apps page, click “Create app”. 
3. Call the app "email data" (with a folder name of email_data). 
4. Build up search strings to match the following checklist of desired metrics. 
	1a. Number (count only) of messages discarded 
	1b. Number of messages delivered (stat=Sent) by hour. 
	1c. Number of messages successfully delivered (count only). 
	1d. A list of recipients of messages that where stat is not “Sent” showing the msgid, sender (from) and size. 
	1e. The average sending delay, shown broken out by hour. 
	1f. Top ten sending addresses by message count. 
	1g. Top ten recipients by message count. 
	1h. Top ten sending addresses by message
>**NOTE**: It is not required to create saved searches / reports for these items. Instead, it is intended for you to prepare them for inclusion the dashboard. 

>**NOTE**: Note that search 1i requires stitching together two distinct events (the first, containing the size, and the second, containing the recipient address) based upon a common queue ID (‘qid’ field). You will need to employ some means of linking the two together (transac3on is easy, but expensive – stats is more efficient, but trickier) to calculate this result.


DEBUG

```
[props/email_log/EXTRACT-milter_action]
access = read : [ * ], write : [ admin ]
export = system
owner = admin
version = 8.1.0
modtime = 1725009906.183605000

[props/email_log/EXTRACT-pid%2Cqid]
access = read : [ * ], write : [ admin ]
export = system
owner = admin
version = 8.1.0
modtime = 1725008950.169832000

[props/email_log/EXTRACT-spam_pct]
access = read : [ * ], write : [ admin ]
export = system
owner = admin
version = 8.1.0
modtime = 1725008954.865101000

[props/email_log]
version = 8.1.0
modtime = 1725009870.390459000

EXTRACT-milter_action = Milter: data, (?P<milter_action>.+)
EXTRACT-pid,qid = ^[^\[\n]*\[(?P<pid>\d+)\]:\s+(?P<qid>\w{14})
EXTRACT-spam_pct = ^(?:[^=\n]*=){2}(?P<spam_pct>\d+)

```

# Indexer Cluster Lab 6 
## Configure the Management Console
From the UI, configure the search peers (2 indexers and 1 sh)
## Initialize the Cluster Master
- Install 8.2.6.1 version of Splunk Enterprise and deploy appropriate base configs:
- Using the base configs for indexer clustering, configure and install the appropriate apps in $SPLUNK_HOME/etc/apps on the cluster master.
- Add the CM as a search peer of the Monitoring Console




GUID idx1
B7E46E83-F346-4DE0-A27D-A9721013978D

db_1423353933_1348712853_10_B7E46E83-F346-4DE0-A27D-A9721013978D
db_1431292691_1423688984_11_B7E46E83-F346-4DE0-A27D-A9721013978D
db_1438807630_1431541724_12_B7E46E83-F346-4DE0-A27D-A9721013978D