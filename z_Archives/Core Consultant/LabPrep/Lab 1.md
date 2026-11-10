pass4SymmKey, splunk.secret, and passwords.conf

1 Cluster Master
1 Monitoring Console

### Install Splunk on the Monitoring Console
Don't start it.

### Get splunk.secret from the Cluster Master
And copy it to *$SPLUNK_HOME/etc/auth/splunk.secret* on the Cluster Master

### Retrieve password
Add the following to *$SPLUNK_HOME/etc/apps/ci1_unhash_app/local/passwords.conf*  for example:
``` passwords.conf
[credential::test:]
password = $pass4symmkeyvalue
```
Use the following command to retrieve your credentials.
```
$SPLUNK_HOME/bin/splunk _internal call /storage/passwords/test

$SPLUNK_HOME/bin/splunk show-decrypted --value '$hashValue'
```

### Join your Monitoring Console to the cluster
You can now use that value to join your new Monitoring console node to your cluster.

The command above may not work in it's current form. Make sure you check your app permissions or adjust the command to match the namespace of your app.

Remember to use base configuration templates to complete the configuration of your MC. You'll find all of the apps you'll need are already deployed to your clustered environment.

Once successfully joined to the cluster with a fully configure monitoring console, make sure that you delete the ci1_unhash_app.