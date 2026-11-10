|Préfixe|État|
|---|---|
|`hot_v1_<id>`|**hot**|
|`db_<newest_epoch>_<oldest_epoch>_<id>`|**warm**|
|`db_<newest>_<oldest>_<id>_<GUID>`|warm, copie primaire en cluster|
|`rb_<newest>_<oldest>_<id>_<GUID>`|copie **répliquée** (cluster)|
Script Check migration:
```
cat > /tmp/check-migration.sh <<'EOF'
#!/bin/bash
SRC=/opt/splunk
HOTWARM=/opt/hotwarm
COLD=/opt/cold

printf '%-42s %-9s %-9s %s\n' SOURCE TYPE TAILLE DESTINATION
echo "--------------------------------------------------------------------------------------------"

for d in "$SRC"/*/; do
  name=$(basename "$d")

  case "$name" in
    bin|cmake|etc|include|lib|openssl|opt|quarantined_files|share|swidtag|var)
      continue ;;
  esac

  if [ ! -d "$d/db" ] && [ ! -d "$d/colddb" ]; then
    echo "IGNORE (ni db ni colddb) : $name"
    continue
  fi

  for sub in db summary datamodel_summary; do
    if [ -d "$d/$sub" ]; then
      sz=$(du -sh "$d/$sub" 2>/dev/null | cut -f1)
      printf '%-42s %-9s %-9s %s\n' "$name/$sub" hotwarm "$sz" "$HOTWARM/$name/$sub"
    fi
  done

  if [ -d "$d/colddb" ]; then
    sz=$(du -sh "$d/colddb" 2>/dev/null | cut -f1)
    printf '%-42s %-9s %-9s %s\n' "$name/colddb" cold "$sz" "$COLD/$name/colddb"
  fi

  for extra in "$d"*/; do
    e=$(basename "$extra")
    case "$e" in
      db|colddb|summary|datamodel_summary|thaweddb|'*') ;;
      *) echo "    /!\ NON GERE : $name/$e" ;;
    esac
  done
done

echo
echo "=== TOTAUX ==="
printf 'hotwarm : '; du -sc "$SRC"/*/db "$SRC"/*/summary "$SRC"/*/datamodel_summary 2>/dev/null | tail -1
printf 'cold    : '; du -sc "$SRC"/*/colddb 2>/dev/null | tail -1
EOF

bash -n /tmp/check-migration.sh && bash /tmp/check-migration.sh
```

Script effectue la migration:
```
cat > /tmp/migrate.sh <<'EOF'
#!/bin/bash
set -u
SRC=/opt/splunk; HOTWARM=/opt/hotwarm; COLD=/opt/cold

pgrep -x splunkd >/dev/null && { echo "ABORT: splunkd tourne"; exit 1; }

mkdir -p "$HOTWARM" "$COLD"; chown splunk:splunk "$HOTWARM" "$COLD"

for d in "$SRC"/*/; do
  name=$(basename "$d")
  case "$name" in
    bin|cmake|etc|include|lib|openssl|opt|quarantined_files|share|swidtag|var) continue ;;
  esac
  [ -d "$d/db" ] || [ -d "$d/colddb" ] || continue

  for sub in db summary datamodel_summary; do
    if [ -d "$d/$sub" ]; then
      mkdir -p "$HOTWARM/$name"
      mv -v "$d/$sub" "$HOTWARM/$name/$sub" || exit 1
    fi
  done

  if [ -d "$d/colddb" ]; then
    mkdir -p "$COLD/$name"
    mv -v "$d/colddb" "$COLD/$name/colddb" || exit 1
  fi
done

chown -R splunk:splunk "$HOTWARM" "$COLD"
echo "--- reste sous /opt/splunk (doit être vide) ---"
ls -d "$SRC"/*/db "$SRC"/*/colddb 2>/dev/null
EOF
```

