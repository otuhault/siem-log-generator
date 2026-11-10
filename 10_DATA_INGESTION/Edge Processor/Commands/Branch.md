### [BRANCH](https://help.splunk.com/en/splunk-cloud-platform/search/spl2-search-reference/branch-command/branch-command-overview-syntax-and-usage)
```
| from main | branch 
[stats count() BY host | where count > 50 select host | into p_hosts], 
[stats count() BY source | where count > 100 select source | into p_sources]
```

Prend un flux de données unique, en fait des copies pour chaque branch, puis chaque branch traite la donnée.
#### **Use Cases**
1. **Traitement différencié des données** : Imagine que tu collectes des logs de sécurité. Tu pourrais vouloir :
    - Envoyer une copie brute et complète de ces logs vers un index de conformité pour archivage.
    - Envoyer une autre copie vers un index d'analyse de sécurité, mais en masquant les adresses IP sensibles pour respecter la confidentialité.
    - Envoyer une troisième copie, très filtrée, vers un tableau de bord opérationnel qui ne s'intéresse qu'aux alertes critiques.
2. **Optimisation des performances** : Au lieu de lancer plusieurs recherches ou pipelines distincts sur les mêmes données sources, la commande `branch` traite les données une seule fois au début, puis les distribue. Cela peut rendre tes traitements plus efficaces car tu évites de charger et de traiter les mêmes données encore et encore.
3. **Tests et expérimentation** : Tu peux utiliser `branch` pour tester différentes transformations ou agrégations sur tes données sans affecter ton pipeline principal. Une branche pour la version A, une autre pour la version B !