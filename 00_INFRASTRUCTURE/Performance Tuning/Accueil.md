# Performance Tuning – Pilier n°4
Objectif : 0 skipped searches + 90 % slots utilisés en permanence.

## Les 15 paramètres que tu changes en 5 minutes et qui sauvent 90 % des clusters
1. limits.conf → max_searches_perc = 70 (au lieu de 50)
2. limits.conf → base_max_searches = 10
3. limits.conf → max_searches_per_cpu = 8 (16 cores = 138 slots totaux)
4. allow_skew = 300 (5 min) pour éviter pile-ups
5. auto_summary_perc = 75 pour ES/ITSI acceleration
6. shclustering → max_peer_rep_load = 140
7. shclustering → remote_job_retry_attempts = 5
8. workload_management → activer si > 500 users concurrents
9. Monitoring Console → Scheduler Activity dashboard (ton meilleur ami)
10. Skip ratio > 5 % → tuer les real-time searches > 7 jours
11. Ad-hoc searches → quota 20 % max (shc_adhoc_quota_enforcement = on)
12. SmartStore downloads → limiter à 10 simultanés
13. Cache manager → augmenter bucket sizes si RAM > 64 GB
14. NUMA disable si VM → bios numa=off
15. Correlation searches ES → max 16 concurrent (ITSI 8)

## 12 tickets classiques 2025
1. 300 skipped searches/j → max_searches_perc encore à 50
2. Captain SH à 100 % CPU → max_peer_rep_load trop bas
3. Real-time search 30 jours → bouffe 50 slots permanents
4. 400 dashboards Studio → timeout 503 → collapse panels
5. Indexer discovery lent → increase indexer_discovery_timeout
6. SmartStore S3 lent → région différente du cluster
7. Correlation searches ES > 24 h → auto_summary_perc = 0
8. Workload rules mal définies → tout le monde dans default_pool
9. SHC delegation fail → captain overload
10. Ad-hoc users 200 simultanés → quota dépassé
11. KV Store collections 40 GB → ralentit tout le scheduler
12. scheduled views ITSI > 100 → disable les inutiles

[[Lab Perf Tuning – Week-end 21 décembre]]