**security_content:** the WHAT, a knowledge library. Lot of YAML files for detections, analytic stories and playbooks.

**contentctl:** the HOW, a dev and automation tool (CLI). Python program. Manage cycle life in security_content, verify YAML files are correct. It can test detection to validate they work. It converts YAML objects in Splunk objects, and can deploy it to splunk.

**En résumé :** `contentctl` est l'outil utilisé par Splunk (et par vous) pour construire, tester et déployer ce qui se trouve dans `security_content`. L'un ne va pas sans l'autre si vous souhaitez suivre une approche de "Detection as Code".

