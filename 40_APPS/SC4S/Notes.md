- Read the documentation: https://splunk.github.io/splunk-connect-for-syslog/main/
- Don't check the Indexer Acknowledgement box.
- Create an env_file to put URL Token and override parameters.
You can override default parameter by adding them to the env_file, look for parameters from the add-on

### For SC4S Lite
Needs a config.yaml file.

### Offline configuration
Comment the following line for the unit file:
```
#ExecStartPre=/usr/bin/podman pull $SC4S_IMAGE
```
And load the image:
```
podman load -i ./sc4slite_image.tar
```

