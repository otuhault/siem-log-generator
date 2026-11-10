**Problème :** 
Lors de l'exécution de : yum update

YUM ne disposait pas des repositories RHEL nécessaires pour effectuer les mises à jour.

1. **Vérification de l'enregistrement des serveurs Red Hat**

Dans un premier temps, j'ai vérifié depuis la console Red Hat que les deux serveurs SOAR DEV et PROD étaient bien enregistrés et présents dans l'inventaire Red Hat.

J'ai également confirmé l'enregistrement directement en CLI sur les deux serveurs avec les commandes suivantes :

subscription-manager identity

subscription-manager status

La commande suivante permet également de vérifier l'état de la connexion aux différents services Red Hat :

rhc status

Exemple de résultat constaté sur le serveur DEV :

Connection status for fr-s-soar-dev:

● Connected to Red Hat Subscription Management

● Not connected to Red Hat Insights

● The Remote Host Configuration daemon is inactive

Le serveur était donc bien enregistré auprès de Red Hat Subscription Management, mais n'était pas connecté à Red Hat Insights et le daemon Remote Host Configuration était inactif.

La connexion aux services Red Hat a été finalisée avec :

rhc connect

Exemple de résultat :

● This system is already connected to Red Hat Subscription Management

● Connected to Red Hat Insights

● Activated the Remote Host Configuration daemon

Successfully connected to Red Hat!

Une dernière vérification a été effectuée avec :

rhc status

subscription-manager status

À ce stade, les serveurs étaient correctement enregistrés et connectés aux services Red Hat. Le problème restant concernait donc la disponibilité/activation des repositories nécessaires à RHEL 8.

2. **Vérification des repositories RHEL**

Les repositories disponibles ont ensuite été vérifiés avec :

subscription-manager repos –list  (qui cette fois affichait bien des repositories, car la connexion à Red Hat Insights et RHC était effective)

Pour RHEL 8, les deux repositories principaux nécessaires sont :

rhel-8-for-x86_64-baseos-rpms

rhel-8-for-x86_64-appstream-rpms

Dans notre cas, ils sont associés aux repositories RHEL 8.10 BaseOS et AppStream.

**3. Activation de BaseOS et AppStream**

Les deux repositories ont été activés avec :

subscription-manager repos \

  --enable=rhel-8-for-x86_64-baseos-rpms \

  --enable=rhel-8-for-x86_64-appstream-rpms

Résultat :

Repository 'rhel-8-for-x86_64-baseos-rpms' is enabled for this system.

Repository 'rhel-8-for-x86_64-appstream-rpms' is enabled for this system.

**4. Validation avec yum update**

Une fois les repositories activés :

yum update

Les métadonnées BaseOS et AppStream ont été récupérées correctement :

Updating Subscription Management repositories.

Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)    39 MB/s |  87 MB

Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)       56 MB/s | 151 MB

Last metadata expiration check: 0:00:01 ago on Wed 19 Aug 2026 08:01:14 AM CEST.

Dependencies resolved.

La même correction a été appliquée sur les environnements **SOAR DEV et PROD**, et les mises à jour YUM fonctionnent maintenant correctement sur les deux serveurs.