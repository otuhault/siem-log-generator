**ca-cert.pem**: Root CA certificat (and intermediates concatenated)
**server.pem**: Splunk certificat + Private Key + Intermediates concatenated + Root if required.

*server.conf*
```
[sslConfig]
sslRootCAPath = /opt/splunk/etc/auth/mycerts/ca-cert.pem
serverCert = /opt/splunk/etc/auth/mycerts/server.pem
sslPassword = PrivateKey Password
requireClientCert = false          ; ou true si auth mutuelle
sslVerifyServerCert = false        ; souvent mis à false en interne
sslVersions = tls1.2
cipherSuite = HIGH
ecdhCurves = prime256v1
cliVerifyServerName = true
sslCommonNameToCheck = ds.test.com,idx.test.com,sh.test.com.com,etc. - All hostnames/FQDN
```

```
[sslConfig]
sslRootCAPath = /opt/splunk/etc/auth/mycerts/ca-cert.pem
serverCert = /opt/splunk/etc/auth/mycerts/server.pem
# sslKeysfilePassword = 
sslVersions = tls1.2
cipherSuite = HIGH
#sslVersionsForClient = tls1.2
#sslVerifyServerCert = true
sslVerifyServerCert = false
# here list of allowed names
sslCommonNameToCheck = ds.cloud.plouic.com,idx.cloud.plouic.com,sh.cloud.plouic.com,cm.cloud.plouic.com,mc.cloud.plouic.com hf.cloud.plouic.com ds3.cloud.plouic.com,hf3.cloud.plouic.com,sh3.cloud.plouic.com,cm3.cloud.plouic.com,mc3.cloud.plouic.com
#sslAltNameToCheck = ds.myorg.com
#sslCommonNameList = ds.myorg.com
# (enabled in deployment client and for indexer in indexer ssl)
#requireClientCert = true
requireClientCert = false
ecdhCurves = prime256v1
cliVerifyServerName = true

[diag]
# don't capture local certs information in troubleshooting files
# this is already by default, EXCLUDE-auth = */etc/auth/* (dont reuse the same name, it is used by product and we really want to exclude this dir)
# just in case, certs are outside /etc/auth in a certs dir, adapt otherwise
#EXCLUDE-orgcerts = */certs/*
```

# Explanations
### x509
La norme X.509 est définie par l'Union Internationale des Télécommunications (UIT).
Un certificat X.509 est un document numérique qui lie une identité (comme un site web, une organisation ou un individu) à une clé publique à l'aide d'une signature numérique.
Son objectif principal est de :
- **Authentifier** l'identité d'un serveur, d'une application ou d'un utilisateur.
- **Établir la confiance** en vérifiant que le certificat a été émis par une autorité de certification (CA) de confiance.
- **Permettre le chiffrement** des données échangées en fournissant la clé publique de l'entité.
### Composants Clés d'un Certificat X.509
Un certificat X.509 contient plusieurs champs qui décrivent l'entité qu'il représente et l'autorité qui l'a émis.
- **Version** : Indique la version de la norme X.509 à laquelle le certificat est conforme (par exemple, v3).
- **Numéro de série** : Un identifiant unique attribué au certificat par l'autorité de certification émettrice.
- **Algorithme de signature** : Spécifie l'algorithme cryptographique utilisé par la CA pour signer le certificat (par exemple, SHA256 avec RSA).
- **Émetteur (Issuer)** : Le nom distinctif (DN - Distinguished Name) de l'autorité de certification qui a émis et signé le certificat.
- **Période de validité (Validity Period)** : Les dates de début et de fin pendant lesquelles le certificat est considéré comme valide.
- **Sujet (Subject)** : Le nom distinctif (DN) de l'entité (serveur, personne, organisation) à laquelle le certificat est délivré. C'est ici que l'on retrouve les attributs que vous avez mentionnés :
    - **CN (Common Name)** : Le nom commun. Pour les serveurs web, il s'agit généralement du nom de domaine pleinement qualifié (FQDN) du serveur (par exemple, `www.example.com`). Pour une personne, ce serait son nom.
    - **O (Organization)** : Le nom de l'organisation ou de l'entreprise (par exemple, `Mon Entreprise SARL`).
    - **OU (Organizational Unit)** : Le nom du département ou de l'unité au sein de l'organisation (par exemple, `IT Department`).
    - **L (Locality)** : La ville ou la localité (par exemple, `Paris`).
    - **ST (State or Province)** : L'État ou la province (par exemple, `Ile-de-France`).
    - **C (Country)** : Le code du pays à deux lettres (par exemple, `FR`).
- **Informations sur la clé publique du sujet (Subject Public Key Info)** : Contient la clé publique de l'entité à laquelle le certificat est délivré, ainsi que l'algorithme utilisé pour cette clé (par exemple, RSA 2048 bits).
- **Extensions** : Des champs supplémentaires qui fournissent des informations additionnelles ou des contraintes sur l'utilisation du certificat. L'une des extensions les plus importantes est le **Subject Alternative Name (SAN)**, qui permet à un certificat de sécuriser plusieurs noms de domaine (par exemple, `example.com` et `www.example.com`).

### Qu'est-ce qu'une Autorité de Certification (CA) ?
Une **Autorité de Certification (CA)**, ou _Certificate Authority_, est une entité de confiance tierce qui émet des certificats numériques. Son rôle principal est de vérifier l'identité des demandeurs de certificats et de lier cette identité à une clé publique. En d'autres termes, une CA agit comme un notaire numérique.
Le fonctionnement repose sur un **modèle de confiance** :
1. Les utilisateurs (clients) font confiance à un ensemble de CA pré-installées dans leurs systèmes d'exploitation ou navigateurs.
2. Lorsqu'un client reçoit un certificat, il vérifie que ce certificat a été signé par une CA qu'il considère comme fiable.
3. Si la signature est valide et que la CA est de confiance, le client peut alors faire confiance à l'identité déclarée dans le certificat.

Il existe deux types principaux de CA :
- **CA Racine (Root CA)** : C'est le point d'ancrage de la confiance. Le certificat d'une CA racine est auto-signé, ce qui signifie qu'il est signé par sa propre clé privée. Ces certificats racines sont distribués largement et pré-installés dans les magasins de confiance des systèmes.
- **CA Intermédiaire (Intermediate CA)** : Pour des raisons de sécurité et de gestion, les CA racines ne signent généralement pas directement les certificats d'entité finale. Elles signent plutôt des certificats de CA intermédiaires. Ces CA intermédiaires sont ensuite utilisées pour émettre les certificats d'entité finale. Cela crée une chaîne de confiance.

### La Chaîne de Certificats (ou Chaîne de Confiance)
Une chaîne de certificats est une séquence de certificats numériques qui commence par le certificat d'entité finale (celui du serveur, par exemple) et se termine par un certificat de CA racine de confiance.

Lorsque votre navigateur ou une application (comme Splunk) reçoit un certificat, il ne fait pas confiance au certificat directement. Il doit vérifier la chaîne de confiance :
1. Il prend le certificat de l'entité finale et vérifie qu'il est signé par le certificat de la CA intermédiaire.
2. Il prend ensuite le certificat de la CA intermédiaire et vérifie qu'il est signé par le certificat de la CA racine.
3. Si le certificat de la CA racine est présent dans son magasin de confiance (trust store) et que toutes les signatures de la chaîne sont valides, alors le certificat de l'entité finale est considéré comme fiable.

### Le Fichier `cacert` (Bundle de Certificats CA)
Le terme `cacert` (ou `ca.pem`, `ca-bundle.crt` selon les systèmes et applications) fait référence à un fichier qui contient un ensemble de certificats de CA racine et/ou intermédiaires de confiance.
- **Rôle** : Ce fichier est le "magasin de confiance" (trust store) qu'une application utilise pour vérifier la validité des certificats qui lui sont présentés. Si le certificat d'une CA émettrice n'est pas dans ce bundle, l'application ne pourra pas valider la chaîne de confiance et considérera le certificat comme non fiable, entraînant souvent des erreurs de connexion SSL/TLS.
- **Exemples** :
    - Les environnements Java utilisent un fichier `cacerts` (souvent situé dans `JAVA_HOME/lib/security/cacerts`) qui est un keystore au format JKS. Il contient des certificats de CA bien connues comme VeriSign.
    - Les systèmes Linux utilisent souvent des fichiers `.pem` ou `.crt` pour stocker les certificats de CA de confiance.

### Detail Splunk Certificates
**ca.pem**: stock le certificat de l'autorité de certification racine (Root CA) = point d'ancrage de la confiance dans une infrastructure à clé publique (PKI).
**cacert.pem**: CA Certification Bundle, ensemble de certificats de CA de confiance, pouvant inclure le certificat racine ainsi que des certificats de CA intermédiaires. C'est le magasin de confiance (trust store) qu'une application utilise pour valider la chaîne de confiance des certificats qui lui sont présentés.

### Explications
**CA** (Certificate Authority) = organisation, service ou même logiciel qui vérifie l'identité des personnes ou entités et d'émettre des certificats numériques pour elles.
Elle garantie que la clé publique contenue dans un certificat appartient bien à l'identité déclarée dans ce certificat.
C'est comme la préfecture qui vérifie votre identité et émet votre passport.
C'est comme DigiCert, Let's Encrypt ou votre propre CA interne.

La CA possède sa propre paire de clés:
- privée utilisée pour signer tous les certificats qu'elle émet. Si cette clé est compromise, toutes la confiance dans les certificats émis par cette CA est brisée.
- publique utilisée par le clients (navigateurs, applications, etc.) pour vérifier les signatures apposées par la CA sur les certificats.
La CA a son propre certificat:
- c'est le certificat public de la CA. Il contient la clé publique de la CA, son identité (CN, O, etc.) et d'autres informations.
- si c'est une CA Root, son certificat est auto-signé (signé par sa propre clé privée). C'est le point d'ancrage de la confiance.
- si c'est une CA intermédiaire, son certificat est signé par une CA supérieure (généralement la CA racine).

**CA intermédiaires**
1. Sécurité renforcée - ce sont les CA intermédiaires qui signent les certificats des entités finales. Si la clé privée d'une CA intermédiaire est compromise, seul un sous ensemble de certificats (ceux émis par cette CA spécifique) est affecté, et non l'ensemble de l'infrastructure.


**Certificat x509** = document numérique standardisé qui lie un clé publique à une identité spécifique (server, personne, organisation).
Il contient:
- *clé publique* de l'entité
- *l'identité de l'entité* (le "Sujet": Common Name, Organisation, etc.)
- *l'identité de la CA* qui l'a émis et signé (l'émetteur)
- une *période de validité*
- d'autres informations (numéro de série, algo de signature, extensions comme SAN)
- ***la signature numérique de la CA***
Son but: permettre à d'autres entités de vérifier l'identité du propriétaire de clé publique et d'établir une communication sécurisée.
C'est votre passeport ou votre carte d'identité. Il contient votre photo (votre identité), votre numéro de document, vos dates de validité, et il est signé par l'autorité qui l'a émis.

**Signature du certificat - Le Sceau d'authentification de la CA**
C'est le mécanisme cryptographique par lequel une CA atteste de l'authenticité et de l'intégrité d'un certificat qu'elle a émis.
1. Le CA prend toutes les informations du certificat (clé publique du sujet, identité du sujet, période de validité, etc.)
2. Elle calcule un hash de toutes ces informations
3. Elle chiffre ce hash avec sa propre clé privée -> **Signature Numérique**
4. Cette signature est ensuite ajoutée au certificat
Son but: prouver que le certificat n'a pas été altéré depuis son émission par la CA et qu'il a bien été émis par cette CA spécifique. N'importe qui peut vérifier cette signature en utilisant la clé publique de la CA.
C'est le sceau officiel ou la signature de l'agent de la préfecture sur votre passeport. Il prouve que le document est authentique et a été délivré par l'autorité compétente.

**CSR - Certificate Signing Request** = La demande et son approbation
CSR est une demande de certificat. Lorsqu'une entité veut obtenir un certificat, elle génère d'abord une paire de clés pub/priv. Ensuite, elle crée un CSR qui contient:
- sa *clé publique*
- les *informations d'identité* qu'elle souhaite voir apparaitre dans le certificat (CN, O, OU, etc.)
- une signature du CSR par la clé privée de l'entité demanderesse (pour prouver qu'elle possède bien la clé privée correspondant à la clé publique fournie). Le CSR est ensuite envoyé à une CA.
Signer le CSR = action de la CA qui examine le CSR, vérifie l'identité du demandeur (si nécessaire), et si tout est en ordre, crée un nouveau certificat x.509 en y intégrant les informations du CSR et en y ajoutant sa propre signature numérique. 
- La CA ne signe pas littéralement le fichier CSR lui-même pour le renvoyer. Elle utilise les informations du CSR pour construire et signer un nouveau document: **le certificat final.**
Son but: la CA transforme une CSR en un certificat validé et signé, prêt à être utilisé.