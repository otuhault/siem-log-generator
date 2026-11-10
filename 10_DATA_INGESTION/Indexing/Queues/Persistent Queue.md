| Paramètre             | Valeur par défaut         | Fichier de config |
| --------------------- | ------------------------- | ----------------- |
| `maxQueueSize`        | **500 KB** (en mémoire)   | `outputs.conf`    |
| `persistentQueueSize` | **Non activé par défaut** | `outputs.conf`    |
| Disk-based spooling   | Dépend de la config       | `outputs.conf`    |
```none
[tcpout]
persistentQueueSize = 100GB
maxQueueSize = 15MB
```

