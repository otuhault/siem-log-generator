- **An unexpected error has occured (in the GUI)**

```
sudo vi /etc/systemd/logind.conf
# décommenter / ajouter : 
RemoveIPC=no 

sudo systemctl restart systemd-logind
```

- **This Edge Processor has instances that cannot authenticate package downloads. Fully uninstall and reinstall affected instances or create a local override to keep authentication turned off.**
