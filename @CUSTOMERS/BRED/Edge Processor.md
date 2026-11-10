22/09/2026

Bertrand Ring en charge plateforme data
Paul Alain : 27 bred + 8 ans de splunk
Egid : admin Splunk + Elastic Search

Optimisation de l'ingestion
Masking des données

Problèmes lors de l'installation.

Répartir la charge entre build (add features) et run
Versions compatible issue, installer bonne archi pour faire tourner.
Méthodes supportées par Splunk.

Faire fonctionner sur env de dev/test - OK.
Regarde externe + recommendations
Pipelines non mis en place - Faire fonctionner.
Accompagnement sur l'env de prod.

Totalement On-premise.
Control pane difficultés.
ça marche en dev = prod pour ceux qui font des applis.
tout le flux des HFs de dev traverse 3 edge nodes - pas de pipeline encore.

3 noeuds minimum dans les reco - pour redémarrage + sizing OK ?
3 en dev et 3 en recette - on verra en prod.
Dès qu'il y a un souci il explose (lorsqu'il peut pas envoyer aux indexers) - probleme de queue?
Stopper EP et repasser sur indexation classique, est-ce possible?

Procédures de mise à jour + procédure de redémarrage - À documenter.

Monter de version ? Procédure officielle.
RHEL9 - sauf les Heavy Forwarders.

Best practices pour le run/upgrade/suivi.
Optimisation de l'indexation quotidienne, soit masquage/reduction logs
Openshift.

Passation des connaissances.

Récupérer les informations de l'existant.


Ordre et Architecture très importante.
Probleme telemtrie qui remonte pas.

Validation des certificats aux bons formats.

Monitoring d'Edge Processor - ?

Sizing pour prod

Monter de version sans souci.

Si possible avant la fin de l'année : 1 ou 2 pipelines.
vérification bcp de redémarrage.

---
HealthCheck de ce qui existe.

