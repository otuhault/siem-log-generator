# KV Store – Pilier n°1
Objectif 3 mois : Fixer n’importe quel crash KV (divergence, WiredTiger, perms, upgrade) en moins de 20 min sans Google.

## Checklist Troubleshooting 2025 (les 15 points que tu dois connaître par cœur)
1. `./splunk show kvstore-status` → ready / captain / failed / stale ?
2. `| rest /services/server/info` → kvStoreStatus + version
3. mongod.log → chercher "replica set", "oplog", "WiredTiger"
4. Permissions : `ls -la $SPLUNK_DB/kvstore/mongo/` → tout doit être splunk:splunk + 400/600
5. Resync forcé : `./splunk resync kvstore -source <GUID_captain> --overwrite`
6. Clean local (data loss) : `./splunk clean kvstore --local`
7. Backup avant toute manip : `splunk backup kvstore /tmp/backup_kv_$(date +%F).tar.gz`
8. Upgrade SHC → toujours 1 SH à la fois (disable du cluster → stop → upgrade → start → enable)
9. WiredTiger migration fail → supprimer versionFile40/42 → créer versionFile36 vide → restart
10. Oplog overflow → collections > 25 GB → purge ou split
11. SSL/key perms : `chmod 600 $SPLUNK_HOME/var/lib/splunk/kvstore/mongo/splunk.key`
12. Captain overload → `server.conf [shclustering] max_peer_rep_load = 140`
13. Odd number of SH members (3-5-7 impératif)
14. Health check MC → Monitoring Console → Search Head Clustering → KV Store
15. Post-incident : toujours un `splunk diag` avant/après

## 15 Tickets Réels 2025 (anonymisés – à apprendre par cœur)
1. Upgrade 9.3→9.4 → KV stuck "old version" → Fix : rolling upgrade SHC
2. IP change cluster → "Did not find local replica set config" → resync --overwrite
3. 3/5 members stale → oplog overflow → clean --local + resync
4. ES/ITSI lent → collections 40 GB → purge savedsearches inutiles
5. "Failed to start KV process" → perms root → chown splunk:splunk
6. Storage full après fsck → clean kvstore (data loss)
7. splunk.key 644 → chmod 600 → restart
8. "No suitable servers" error 13053 → clean --local sur les 2 stale
9. Process terminated code 14 → server.pem expiré → renew + clean
10. Captain 100 % CPU → max_peer_rep_load trop bas
11. Post-9.4 WiredTiger mig fail → delete versionFile42 → create versionFile36
12. Cisco App crash → raise cache memory dans app.conf
13. Bulletin board errors → restart tous les SH en séquence
14. SHC 4 members → quorum impossible → ajouter 5e ou descendre à 3
15. Login LDAP KO après restart KV → login admin native d’abord

[[Lab KV Store – Dimanche 7 décembre]]