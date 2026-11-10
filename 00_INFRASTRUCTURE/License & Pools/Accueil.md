# Licences & Pools – Pilier n°3
Objectif : 0 violation sur 60 jours rolling + optimisation coût –20 % minimum.

## Règles 2025 que personne ne connaît par cœur (mais toi oui)
1. 5 warnings ou plus sur 60 jours rolling → violation permanente du pool → search off 30 jours
2. 45 warnings sur 60 jours → search off pour le pool entier (même si quota < 100 %)
3. No-enforcement license uniquement si version < 6.5
4. Metrics logs = 150 bytes/event fixe (pas 115 comme avant)
5. Pool quota est en bytes, stack quota aussi → le plus restrictif gagne
6. Indexer orphelin ou sourcetype inconnu → compte dans _audit ou _internal → explose les licences
7. Query monitoring : 
   | rest /services/licenser/pools | eval %used=round(used_bytes/quota*100,2) | where %used>80
8. Purge rapide : delete by sourcetype dans _internal / _audit sur les 90 derniers jours
9. Sub-pools (ES/ITSI) → dépassement n’impacte pas les autres pools
10. Free license → 3 warnings max, puis blocage total

## 12 tickets classiques 2025
1. Violation permanente après 6 warnings → clean _audit + _internal 90 jours
2. Pool à 98 % alors que volume réel 70 % → indexers orphelins dans license manager
3. Search blocked mais stack < 100 % → c’est le pool qui a pris 45 warnings
4. Client pense avoir 50 GB/j mais licence 100 GB → _internal = 35 GB/j seul
5. Migration Cloud → licence on-prem à rendre le jour du cutover
6. Stack désactivé après 30 jours sans contact License Master
7. Achat urgence licence → +30 % prix si violation en cours
8. Avalanche forwarders après reboot → burst 500 % → 5 warnings instant
9. Licence ES ajoutée mais quota non augmenté → notable index compte double
10. Pool quota mal réparti → un BU bloque tout le monde
11. Alert violation → créer avec action « email + slack » obligatoire
12. QAS (Query Audit Search) carve-out → ne compte plus dans licence depuis 9.2

[[Lab Licences – Week-end 14 décembre]]