# Divers
It will have issues, typos, and errors, on purpose, my job to find it.

Check all basic stuff like version, who is running splunkd, which ports are opened, 

Set up a search head cluster
--> Check versions, do the upgrade
system/local/

look for typos


**setfacl** pour lire fichiers /var/log
`setfacl -m u:user1:r fichier.txt`


recovery du /opt/splunk/etc/auth/splunk.secret

 et initCrcLength

upgrade de cluster à faire en plusieurs fois (checker la matrice de compatibilité pour l'upgrade)

# FishBucket
### Simple Usage
**Forgot a single file from the fishbucket**
```
./splunk cmd btprobe -d $SPLUNK_HOME/var/lib/splunk/fishbucket/splunk_private_db --file $FILE --reset
```
### 2 modes
```
 1: btprobe [-h or --help] -d <btree directory> [-k <hex key OR ALL> | --file <filename>] [--salt <salt>] [--validate] [--reset] [--bytes <bytes>]
 Queries the specified BTree for the given key or file.

    -d           Directory that contains the btree index. (Required)

    -k           Hex crc key or ALL to get all the keys.
    --file       File to compute the crc from.
      (One of -k and --file must be specified.

    --validate   Validate the btree to look for errors.
    --salt       Salt the crc if --file param is specified.
    --reset      Reset the fishbucket for the given key or file in the btree.
    --bytes      Number of bytes to read when calculating CRC (default 256).

 2: btprobe [-h or --help] --compute-crc <filename> [--salt <salt>] [--bytes <bytes>]
 Computes a crc from the specified file (using the given salt if any).

 Examples:
 btprobe -d /opt/splunk/var/lib/splunk/fishbucket/splunk_private_db  -k 0xe8d117ddba85e714 --validate
 btprobe -d /opt/splunk/var/lib/splunk/fishbucket/splunk_private_db --file /var/log/inputfile --salt SOME_SALT
 btprobe --compute-crc /var/log/inputfile --salt SOME_SALT
```

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

ssh sccStudent@EDU-419-cfrtl4-999934-emplo000000000072547-idx1.students.splunk.education
ssh sccStudent@EDU-419-cfrtl4-999934-emplo000000000072547-aio1.students.splunk.education
ssh sccStudent@EDU-419-cfrtl4-999934-emplo000000000072547-sh1.students.splunk.education