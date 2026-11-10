`CMD + Shift + I` to write into multiple tabs at once
`scp -r folder/ user@host:/tmp/`  
# Download & Install SE
```
wget -O splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/8.2.6.1/linux/splunk-8.2.6.1-5f0da8f6e22c-Linux-x86_64.tgz"

sudo tar -xvzf splunk_package_name.tgz -C /opt/

sudo useradd splunk
sudo passwd splunk
sudo chown -R splunk:splunk $SPLUNK_HOME
su - splunk
/opt/splunk/bin/splunk start

alias splunk="/opt/splunk/bin/splunk"
echo 'alias splunk="/opt/splunk/bin/splunk"' >> ~/.bashrc

sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```
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

New in Splunk 7.1+
- If you start Splunk with ‐‐no‐prompt, the administrator account will NOT be created
- With a text editor, create $SPLUNK_HOME/etc/system/local/user‐seed.conf to contain the admin username / password
- /opt/splunk/bin/splunk start ‐‐accept‐license ‐‐answer‐yes ‐‐no‐prompt ‐‐seed‐passwd $ADMIN_PWD

# Boot-time Documentation
https://docs.splunk.com/Documentation/Splunk/9.3.2/Admin/ConfigureSplunktostartatboottime

# Enterprise Security
https://help.splunk.com/en/splunk-enterprise-security-8/install/8.5/installation/install-splunk-enterprise-security-in-a-search-head-cluster-environment
