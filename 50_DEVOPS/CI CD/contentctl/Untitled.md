``` python
import yaml
import requests
import urllib3
urllib3.disable_warnings()

def deploy_detection(yaml_file, splunk_host, username, password):
    
    # Charger le YAML
    with open(yaml_file, 'r') as f:
        detection = yaml.safe_load(f)
    
    # Mapper les champs YAML vers Splunk
    payload = {
        'name': detection['name'],
        'search': detection['search'],
        'description': detection.get('description', ''),
        'cron_schedule': '*/5 * * * *',
        'is_scheduled': '1',
        'dispatch.earliest_time': '-15m',
        'dispatch.latest_time': 'now',
        'alert_type': 'number of events',
        'alert_comparator': 'greater than',
        'alert_threshold': '0',
        'alert.severity': str(detection['tags'].get('risk_score', 50)),
        'disabled': '0'
    }
    
    # Pousser via REST
    url = f"https://{splunk_host}:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
    
    response = requests.post(
        url,
        data=payload,
        auth=(username, password),
        verify=False
    )
    
    if response.status_code in [200, 201]:
        print(f"✅ Detection '{detection['name']}' déployée avec succès")
    else:
        print(f"❌ Erreur : {response.status_code} - {response.text}")

# Exécution
deploy_detection(
    yaml_file='ma_detection.yml',
    splunk_host='<es_host>',
    username='admin',
    password='password'
)
```


``` python
# Créer une saved search (detection rule) via REST
curl -k -u admin:password \
  -X POST \
  "https://<es_host>:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches" \
  -d "name=<nom_detection>" \
  -d "search=<votre_spl_query>" \
  -d "cron_schedule=*/5 * * * *" \
  -d "dispatch.earliest_time=-15m" \
  -d "dispatch.latest_time=now" \
  -d "alert_type=number of events" \
  -d "alert_comparator=greater than" \
  -d "alert_threshold=0" \
  -d "is_scheduled=1" \
  -d "alert.severity=high"
```

enabled_by_default: true
