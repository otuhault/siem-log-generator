# Windows — métadonnées source/sourcetype et exigences du TA

> Collecté le 2026-09-11.
> TA de référence disponible localement : `TAs/Splunk_TA_windows`, **version 11.0.2**
> (`default/app.conf`). Toutes les citations `.conf` ci-dessous en proviennent et
> sont vérifiables dans le dépôt.
>
> Convention de lecture : **SOURCÉ** = lu dans le TA local ou dans une page
> éditeur citée en fin de document. **DÉDUIT** = raisonnement à partir de ces
> éléments, non affirmé par une source.

---

## Hypothèse testée : `source` vient de inputs.conf

**Verdict : PARTIELLEMENT CONFIRMÉE.** L'input pose bien les valeurs initiales,
mais le TA les **réécrit à l'indexation en les dérivant du contenu du log**. La
seconde moitié de l'hypothèse — « les métadonnées ne sont pas déduites du
contenu » — est donc **infirmée**.

**Ce qui confirme la première moitié** (SOURCÉ) : aucune des stanzas
`[WinEventLog://...]` de `default/inputs.conf` ne déclare de clé `sourcetype =`.
Exemple littéral :

```ini
[WinEventLog://Security]
disabled = 1
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
checkpointInterval = 5
blacklist1 = EventCode="4662" Message="Object Type:(?!\s*groupPolicyContainer)"
blacklist2 = EventCode="566" Message="Object Type:(?!\s*groupPolicyContainer)"
renderXml=true
```

Le sourcetype et le source sont donc produits par l'input modulaire à partir du
nom de la stanza, pas déclarés.

**Ce qui infirme la seconde moitié** (SOURCÉ) — `default/transforms.conf` :

```ini
## Setting generic sourcetype and unique source
[ta-windows-fix-classic-source]
DEST_KEY = MetaData:Source
REGEX = (?m)^LogName=(.+?)\s*$
FORMAT = source::WinEventLog:$1

[ta-windows-fix-xml-source]
DEST_KEY = MetaData:Source
REGEX = <Channel>(.+?)<\/Channel>.*
FORMAT = source::XmlWinEventLog:$1

[ta-windows-fix-sourcetype]
SOURCE_KEY = MetaData:Sourcetype
DEST_KEY = MetaData:Sourcetype
REGEX = sourcetype::([^:]*)
FORMAT = sourcetype::$1
```

appliqués par `default/props.conf` (lignes 57-61), avec le commentaire d'intention
du TA :

```ini
## consistent sourcetypes for common extractions XmlWinEventLog or WinEventLog
## format source using sourcetype value, so we know whether its XML or not
## this stanza will ensure the new extractions are backwards compatible; we will know what to do regardless of what source/sourcetype
## the mod input sets and new sources will be accommodated as well
[(::){0}WinEventLog:*\S+]
TRANSFORMS-Fixup = ta-windows-fix-classic-source,ta-windows-fix-sourcetype

[(::){0}XmlWinEventLog:*\S+]
TRANSFORMS-XmlFixup = ta-windows-fix-xml-source,ta-windows-fix-sourcetype
```

Le TA dit explicitement qu'il veut fonctionner « regardless of what source/sourcetype
the mod input sets » : il ne fait pas confiance à l'input et recalcule `source`
depuis le contenu (`LogName=` en classic, `<Channel>` en XML), puis tronque le
sourcetype à son préfixe générique.

---

## Mode d'attribution du sourcetype (1 renommage / 2 input / 3 direct)

**Verdict : mode 1 — renommage index-time.** Sans ambiguïté.

Preuve décisive (SOURCÉ) : le TA contient bien des `TRANSFORMS-*` agissant sur
`MetaData:Sourcetype` **et** `MetaData:Source`, cités ci-dessus. Windows est donc
dans le même mode que Palo Alto, avec deux différences de mécanique :

| | Palo Alto | Windows |
|---|---|---|
| Sourcetype envoyé | générique `pan:log` | suffixé `WinEventLog:<Canal>` |
| Sens du renommage | générique → spécifique (`pan:traffic`…) | spécifique → **générique** (`WinEventLog`) |
| Clé portant la spécificité après indexation | `sourcetype` | **`source`** |
| Dérivé de | 4ᵉ champ CSV | `LogName=` / `<Channel>` |

Confirmation éditeur (SOURCÉ), page Upgrade du TA :

> « All WinEventLogs are now assigned to either the WinEventLog or the
> XmlWinEventLog sourcetype and are distinguished by their source. »

C'est l'inverse de l'intuition : chez Windows le sourcetype **perd** l'information
de canal, qui migre dans `source`.

---

## Correspondance inputs.conf → source → sourcetype

Table de migration officielle (SOURCÉ, page Upgrade du TA, colonnes « Windows 6.0.0 ») :

| stanza inputs.conf | renderXml | `source` produit | `sourcetype` produit | doc |
|---|---|---|---|---|
| `[WinEventLog://Security]` | `true` | `XmlWinEventLog:Security` | `XmlWinEventLog` | Upgrade + transforms |
| `[WinEventLog://Security]` | `false` | `WinEventLog:Security` | `WinEventLog` | Upgrade + transforms |
| `[WinEventLog://System]` | `true` | `XmlWinEventLog:System` | `XmlWinEventLog` | idem |
| `[WinEventLog://Application]` | `true` | `XmlWinEventLog:Application` | `XmlWinEventLog` | idem |
| `[WinEventLog://Directory Service]` | `true` | `XmlWinEventLog:Directory Service` | `XmlWinEventLog` | inputs.conf + eventtype `wineventlog-ds` |
| `[WinEventLog://DNS Server]` | `true` | `XmlWinEventLog:DNS Server` | `XmlWinEventLog` | eventtype `wineventlog-dns` |
| `[WinEventLog://DFS Replication]` | `true` | `XmlWinEventLog:DFS Replication` | `XmlWinEventLog` | eventtype `wineventlog-dfs` |
| `[WinEventLog://ForwardedEvents]` | `true` (imposé) | `XmlWinEventLog:ForwardedEvents` | `XmlWinEventLog` | inputs.conf |

Note (SOURCÉ) : la table de migration officielle est **incohérente sur un point** —
pour DFS Replication en XML elle donne `Sourcetype in Windows 6.0.0 =
XmlWinEventLog:DFS`, alors que la ligne DNS donne `XmlWinEventLog` et que la
phrase de synthèse annonce un sourcetype générique. Le transform local
`ta-windows-fix-sourcetype` produit sans ambiguïté la forme **générique** ; je
retiens celle-ci, la table semblant comporter une coquille.

Toutes les stanzas `WinEventLog://` du TA 11.0.2 sont livrées avec
`renderXml=true` (SOURCÉ), sauf `Microsoft-Windows-PrintService/Operational`.

---

## Sourcetypes officiels du TA

Table officielle (SOURCÉ, page « Source Types and CIM » du TA) :

| Sourcetype | Input | Data models CIM |
|---|---|---|
| `WinEventLog` & `XmlWinEventLog` | WinEventLog | Application State, Authentication, Change Analysis, Performance, Updates, Vulnerabilities, Endpoint, Event Signatures, Change |
| `WMI:WinEventLog:*` | WMI | idem |

Autres sourcetypes déclarés dans `inputs.conf` (SOURCÉ), hors périmètre event log :
`DhcpSrvLog`, `WindowsUpdateLog`, `MSAD:NT6:Netlogon`, `WindowsFirewallLog`,
`MSAD:NT6:DNS`, `msdns:analytical`, `Script:ListeningPorts`,
`Script:InstalledApps`, `WinHostMon`, `Perfmon:*`, `WinRegistry`.

Les stanzas `props.conf` portant les FIELDALIAS/LOOKUP CIM sont
**`[WinEventLog]` (ligne 101)** et **`[XmlWinEventLog]` (ligne 147)** — donc les
formes génériques, ce qui corrobore la normalisation.

---

## WinEventLog vs XmlWinEventLog

| | `WinEventLog` | `XmlWinEventLog` |
|---|---|---|
| S'applique quand | `renderXml=false` | `renderXml=true` |
| Format attendu | texte multi-lignes `clé=valeur`, débutant par `LogName=` | XML `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` |
| Extraction | REPORT/EXTRACT search-time | `INDEXED_EXTRACTIONS = XMLKV-WINEVT` (index-time), `LINE_BREAKER=([\r\n]+)<Event\sxmlns` |
| Dérivation de `source` | `(?m)^LogName=(.+?)\s*$` | `<Channel>(.+?)</Channel>` |

(SOURCÉ : `props.conf` stanzas `[WinEventLog]`, `[XmlWinEventLog]`, et transforms.)

Défaut du TA 11.0.2 : XML partout (SOURCÉ, `renderXml=true` sur quasiment toutes
les stanzas). La doc éditeur indique que depuis la 6.0.0 la collecte WinEventLog
est en XML par défaut.

---

## Le TA utilise-t-il `source` pour classifier ?

**Verdict : OUI, massivement. C'est la clé de voûte de la classification.**
Une valeur de `source` fausse rend l'événement invisible aux eventtypes — et donc
aux datamodels — même si l'extraction de champs est parfaite.

**`eventtypes.conf` — 26 occurrences de `source=`** (SOURCÉ). Extraits littéraux :

```ini
[wineventlog_security]
search = source=WinEventLog:Security OR source=WMI:WinEventLog:Security OR source=XmlWinEventLog:Security

[wineventlog_application]
search = source=WinEventLog:Application OR source=WMI:WinEventLog:Application OR source=XmlWinEventLog:Application

[wineventlog_system]
search = source=WinEventLog:System OR source=WMI:WinEventLog:System OR source=XmlWinEventLog:System

[wineventlog-ds]
search = source="WinEventLog:Directory Service" OR source="XmlWinEventLog:Directory Service"
```

et les eventtypes CIM porteurs, tous filtrés sur `source` :

```ini
search = (source=WinEventLog:Security OR source=XmlWinEventLog:Security) (EventCode=4624 OR EventCode=4625 OR EventCode=4672)
search = (source="WinEventLog:Security" OR source="XmlWinEventLog:Security") (EventCode=4688 OR EventCode=4689 OR ...)
search = (source=WinEventLog:Security OR source=XmlWinEventLog:Security) AND EventCode IN (4634,4703,...,4720,4722,...)
```

**`props.conf` — 16 stanzas `[source::...]`** (SOURCÉ) :
`[source::WinEventLog:Security]` (l.594), `[source::XmlWinEventLog:Security]`
(l.349), `[source::WinEventLog:System]` (l.225), `[source::XmlWinEventLog:System]`
(l.299), `[source::XmlWinEventLog:Application]` (l.526),
`[source::WinEventLog:Application]` (l.582),
`[source::XmlWinEventLog:Microsoft-Windows-PowerShell/Operational]` (l.534),
`[source::XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational]` (l.538),
`[source::WinEventLog:ForwardedEvents]` (l.819), etc.

**`tags.conf` — NON** (SOURCÉ). Les 3 occurrences du mot « source » y sont des
faux positifs (`resource = enabled`). Les tags portent sur `eventtype=`, qui
lui-même dépend de `source` : la dépendance est indirecte mais réelle.

**`transforms.conf` — oui, en écriture** : c'est lui qui pose `source` (voir plus haut).

---

## Mode de collecte : HEC/syslog vs input natif

Notre application n'utilise jamais d'input Windows natif. Constat sur le code
(SOURCÉ) : `hec_sender.py:45` cible `/services/collector/event`, et le payload
porte `source` uniquement si l'utilisateur l'a saisi (`hec_sender.py:96-97`) ;
le formulaire laisse le champ vide par défaut.

**Champs à poser dans le payload HEC pour imiter un UF** (DÉDUIT des tables de
migration officielles) : `source`, `sourcetype`, `host`, `index`. Les quatre sont
acceptés par le endpoint `/event` (SOURCÉ, doc HEC : clés `time`, `host`,
`source`, `sourcetype`, `index`, `fields`).

**Le TA fonctionne-t-il à l'identique par HEC ?** Réponse honnête : **incertain
sur un point précis**, et c'est l'incertitude principale de ce document. La
question est de savoir si les `TRANSFORMS-*` index-time du TA s'exécutent sur les
événements envoyés à `/services/collector/event`. La doc éditeur consultée
n'énonce pas la règle ; les réponses communautaires se contredisent ouvertement
(voir Sources). Deux scénarios :

- **s'ils s'exécutent** : envoyer `sourcetype=XmlWinEventLog:Security` suffit,
  le TA dérivera `source` du `<Channel>` et normalisera le sourcetype ;
- **s'ils ne s'exécutent pas** : `source` resterait vide et le sourcetype
  resterait suffixé — la stanza `[XmlWinEventLog]` ne matcherait pas, aucun
  FIELDALIAS CIM ne s'appliquerait, et tous les eventtypes échoueraient.

**Contournement robuste dans les deux cas** (DÉDUIT) : émettre directement les
valeurs **finales**, `source = XmlWinEventLog:<Canal>` et
`sourcetype = XmlWinEventLog`. Si les transforms tournent, ils recalculent la
même valeur de `source` depuis le `<Channel>` et `ta-windows-fix-sourcetype`
laisse `XmlWinEventLog` inchangé (la regex `sourcetype::([^:]*)` sur une valeur
sans deux-points est un no-op). Si les transforms ne tournent pas, les valeurs
sont déjà bonnes. Ce choix est neutre vis-à-vis de l'incertitude.

**Syslog est-il viable pour du Windows Event Log ?** (DÉDUIT) Non pour la
chaîne TA telle quelle. Le transport syslog ne véhicule ni `source` ni
`sourcetype` : ces métadonnées seraient posées par la stanza de l'input syslog
côté récepteur (SC4S ou `[udp://514]`), identiques pour tout le flux. Il n'existe
dans le TA aucune stanza ni transform prévoyant une entrée syslog. En XML, le
`<Channel>` reste dans le contenu et un transform maison pourrait reconstituer
`source`, mais rien de tel n'est fourni par le TA. Aucune page éditeur trouvée
ne documente une ingestion WinEventLog par syslog.

---

## Contenu du log

Le TA s'appuie **aussi** sur des littéraux du contenu, en plus des métadonnées
(SOURCÉ) : `LogName=` en classic et `<Channel>` en XML sont les ancres des deux
transforms de dérivation de `source`. Le contenu n'est donc pas neutre.

**Vérification exécutée sur notre générateur** — les regex littérales du TA ont
été appliquées à la sortie réelle de `windows.py` :

| render_format | 1re ligne émise | regex TA | match | `source` dérivé |
|---|---|---|---|---|
| `classic` | `Log Name:      Security` | `(?m)^LogName=(.+?)\s*$` | **NON** | néant |
| `xml` | `<Event xmlns=…><Channel>Security</Channel>` | `<Channel>(.+?)</Channel>.*` | **OUI** | `XmlWinEventLog:Security` |

Notre `render_format='classic'` produit le format d'affichage de l'**Observateur
d'événements Windows** (`Log Name:` avec espace et deux-points), et non le format
Splunk classic `LogName=Security`. Il ne correspond donc à **aucun** sourcetype
officiel du TA. Le format `xml` correspond bien à `XmlWinEventLog`.

---

## Active Directory

**Constat sur notre code** (SOURCÉ, exécution de `active_directory.py`) : les
cinq catégories émettent toutes `<Channel>Security</Channel>`, en XML.

| catégorie | EventID émis | canal émis |
|---|---|---|
| `account_management` | 4720, 4722, 4725, 4726, 4738, 4740, 4767, 4781 | Security |
| `group_management` | 4728, 4729, 4732, 4733, 4756, 4757 | Security |
| `directory_service` | 4662, 5136, 5137 | Security |
| `authentication` | 4768, 4769, 4771, 4776 | Security |
| `computer_management` | 4741, 4742, 4743 | Security |

**Verdict : le canal Security est correct pour les cinq catégories** (DÉDUIT,
corroboré par le TA). Ces EventID sont bien journalisés dans le canal Security
d'un contrôleur de domaine : le TA les cible explicitement via des eventtypes
filtrés sur `source=…Security`, par exemple `EventCode IN (…,4720,4722,4723,4724,4725,4726,4732,4738,4740,4767,4781,…)`
et `EventCode=4688…`. Le TA blackliste d'ailleurs `EventCode="4662"` dans la
stanza `[WinEventLog://Security]`, ce qui confirme que 4662 arrive par Security.

**À ne pas confondre avec le canal « Directory Service »** (SOURCÉ) : c'est un
canal distinct, alimenté par la stanza `[WinEventLog://Directory Service]` et
ciblé par l'eventtype `wineventlog-ds`
(`source="WinEventLog:Directory Service" OR source="XmlWinEventLog:Directory Service"`).
Il porte les événements NTDS internes (réplication, LDAP interne), pas les 4662 /
5136 / 5137. **Notre générateur ne produit rien pour ce canal**, et le nom de
notre catégorie `directory_service` est donc trompeur : elle produit des
événements Security.

Le registre déclare `active_directory` sous `WinEventLog:Security` : **doublement
inexact** — c'est la valeur d'un `source`, pas d'un `sourcetype`, et la forme
classic alors que le générateur émet du XML.

---

## Exemples sourcés

**Table de migration officielle** (page Upgrade du TA, citée verbatim) :

| WinEventLog format | Source in AD 1.0.0 | Sourcetype in AD 1.0.0 | Source in Windows 6.0.0 | Sourcetype in Windows 6.0.0 |
|---|---|---|---|---|
| Classic | WinEventLog:DFS Replication | WinEventLog:DFS-Replication | WinEventLog:DFS-Replication | WinEventLog |
| XML | WinEventLog:DFS Replication | WinEventLog:DFS-Replication | WinEventLog:DFS-Replication | XmlWinEventLog:DFS |

| WinEventLog format | Source in DNS 1.0.1 | Sourcetype in DNS 1.0.1 | Source in Windows 6.0.0 | Sourcetype in Windows 6.0.0 |
|---|---|---|---|---|
| Classic | WinEventLog:DNS Server | WinEventLog:DNS-Server | WinEventLog:DNS Server | WinEventLog |
| XML | WinEventLog:DNS Server | WinEventLog:DNS-Server | XmlWinEventLog:DNS Server | XmlWinEventLog |

**Phrase de synthèse éditeur**, verbatim :

> « All WinEventLogs are now assigned to either the WinEventLog or the
> XmlWinEventLog sourcetype and are distinguished by their source. »

**Exemple de ligne de log réelle issue d'un forwarder** :
**AUCUN EXEMPLE SOURCÉ TROUVÉ.** Aucune page éditeur consultée ne publie un
événement WinEventLog complet accompagné de ses métadonnées `source`/`sourcetype`
telles qu'indexées. Les seules valeurs littérales dont je dispose sont celles des
tables ci-dessus et des `.conf` du TA.

---

## Écart avec notre code

| ce que le code produit | ce que le TA attend | verdict | fichier:ligne |
|---|---|---|---|
| `sourcetype` = `WinEventLog:Security` (registre) | `sourcetype` = `XmlWinEventLog` (générique), canal porté par `source` | **inexact** : confond source et sourcetype | `ta_registry.py` section `windows` |
| aucun champ `source` émis par défaut | `source` = `XmlWinEventLog:Security` — clé de toute la classification | **bloquant** : tous les eventtypes échouent | `hec_sender.py:96-97`, champ UI vide |
| `render_format='classic'` → `Log Name:      Security` | `LogName=Security` en début de ligne | **inexact** : format Observateur d'événements, non reconnu | `windows.py` (branche classic) |
| `render_format='xml'` → `<Channel>Security</Channel>` | idem | **conforme** | `windows.py` (branche xml) |
| `active_directory` déclaré `WinEventLog:Security` | XML → `source` = `XmlWinEventLog:Security`, `sourcetype` = `XmlWinEventLog` | **inexact** : mauvais format et confusion source/sourcetype | `ta_registry.py` section `active_directory` |
| catégorie AD nommée `directory_service` émettant du canal Security | canal `Directory Service` = eventtype `wineventlog-ds`, EventID NTDS | **nom trompeur**, contenu lui-même correct | `active_directory.py` |
| envoi HEC `/services/collector/event` | comportement des transforms index-time non documenté sur ce endpoint | **incertain** — voir Zones d'incertitude | `hec_sender.py:45` |

---

## Verdict par source

| source de log | `source` à émettre | `sourcetype` à émettre | render_format | bloquant ? |
|---|---|---|---|---|
| windows / Security | `XmlWinEventLog:Security` | `XmlWinEventLog` | `xml` | **oui** — `source` absent aujourd'hui |
| windows / System | `XmlWinEventLog:System` | `XmlWinEventLog` | `xml` | **oui** — idem |
| windows / Application | `XmlWinEventLog:Application` | `XmlWinEventLog` | `xml` | **oui** — idem |
| active_directory (5 catégories) | `XmlWinEventLog:Security` | `XmlWinEventLog` | `xml` (seul produit) | **oui** — idem |

Variante classic, si un jour le générateur produit le vrai format `LogName=` :
`source = WinEventLog:<Canal>`, `sourcetype = WinEventLog`. En l'état la branche
`classic` ne correspond à aucun sourcetype du TA et ne devrait pas être présentée
comme compatible.

---

## Valeurs de `source` à proposer dans l'app

Canaux tirés de `inputs.conf` et `eventtypes.conf` du TA 11.0.2 (SOURCÉ), à
préfixer par `XmlWinEventLog:` en XML ou `WinEventLog:` en classic :

| Canal | Origine dans le TA | Couvert par notre générateur ? |
|---|---|---|
| `Security` | `[WinEventLog://Security]`, eventtype `wineventlog_security` | oui |
| `System` | `[WinEventLog://System]`, eventtype `wineventlog_system` | oui |
| `Application` | `[WinEventLog://Application]`, eventtype `wineventlog_application` | oui |
| `Directory Service` | `[WinEventLog://Directory Service]`, eventtype `wineventlog-ds` | non |
| `DNS Server` | `[WinEventLog://DNS Server]`, eventtype `wineventlog-dns` | non |
| `DFS Replication` | `[WinEventLog://DFS Replication]`, eventtype `wineventlog-dfs` | non |
| `File Replication Service` | eventtype `wineventlog-filereplication` | non |
| `Key Management Service` | eventtype `wineventlog-keymanagement` | non |
| `ForwardedEvents` | `[WinEventLog://ForwardedEvents]` (WEF, XML imposé) | non |
| `Microsoft-Windows-PrintService/Operational` | `[WinEventLog://…PrintService/Operational]` | non |
| `Microsoft-Windows-PowerShell/Operational` | `[source::…PowerShell/Operational]`, eventtype `powershell` | non |
| `Microsoft-Windows-Windows Defender/Operational` | eventtypes `wineventlog_defender_operational_*` | non |

Canal supplémentaire hors TA Windows (SOURCÉ, fil communautaire Splunk ;
relève du TA Sysmon, pas de celui-ci) :
`Microsoft-Windows-Sysmon/Operational`, cité sous la forme
`source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` avec `renderXml = 1`.

Attention (SOURCÉ) : les canaux comportant une espace apparaissent **entre
guillemets** dans les eventtypes (`source="XmlWinEventLog:Directory Service"`), et
la valeur elle-même conserve l'espace — la table de migration DFS montre une
variante à tiret (`DFS-Replication`) qui semble propre à l'ancien TA AD. Retenir
la forme avec espace, conforme au nom de canal Windows.

---

## Zones d'incertitude

1. **Transforms index-time et HEC `/services/collector/event`** — incertitude
   principale. Impossible de trancher sur doc éditeur : la page « Format events
   for HTTP Event Collector » énumère les clés acceptées mais n'aborde pas le
   comportement des `TRANSFORMS-*` selon le endpoint, et les réponses
   communautaires se contredisent frontalement (l'une affirme que seul `/event`
   est affecté par props/transforms, l'autre qu'il faut `/raw` pour les
   déclencher). Non levée. Seul un test contre un Splunk réel trancherait.
2. **Coquille apparente de la table de migration officielle** — la ligne DFS/XML
   annonce `XmlWinEventLog:DFS` comme sourcetype là où tout le reste (phrase de
   synthèse, transform local, stanzas `props.conf`) impose la forme générique.
   J'ai retenu la forme générique sans pouvoir le confirmer par une seconde source.
3. **Valeur littérale de `source` posée par l'input modulaire avant transform** —
   je n'ai trouvé aucune page éditeur l'énonçant directement. Elle est déduite
   des tables de migration et du fait que le TA la recalcule de toute façon.
   Sans importance pratique si les valeurs finales sont émises directement.
4. **Format classic exact** — le TA ancre sur `^LogName=`. Je n'ai pas trouvé de
   spécification éditeur complète du format classic (ordre et liste des clés),
   seulement cette ancre. Reconstituer un classic fidèle demanderait une source
   supplémentaire.
5. **Couverture des EventID par les eventtypes** — non auditée ici, hors
   périmètre des questions posées. Un `source` correct est nécessaire mais peut
   ne pas suffire si un EventID n'est listé dans aucun eventtype.
6. **`docs.splunk.com` inaccessible** (HTTP 403 sur les deux URL tentées). Le
   contenu éditeur a été obtenu via le miroir officiel `splunk.github.io`, publié
   par Splunk pour ce même add-on. Je le considère comme éditeur, mais ce n'est
   pas le canal primaire.

---

## Sources

| URL | éditeur/tiers | date de consultation | apport |
|---|---|---|---|
| `TAs/Splunk_TA_windows` v11.0.2 — `inputs.conf`, `props.conf`, `transforms.conf`, `eventtypes.conf`, `tags.conf` | éditeur (artefact livré) | 2026-09-11 | Preuve principale : absence de `sourcetype=` dans les stanzas, transforms de réécriture, 26 filtres `source=`, 16 stanzas `[source::]` |
| https://splunk.github.io/splunk-add-on-for-microsoft-windows/Upgrade/ | éditeur (miroir officiel) | 2026-09-11 | Tables de migration source/sourcetype ; phrase « distinguished by their source » |
| https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/ | éditeur (miroir officiel) | 2026-09-11 | Table officielle des sourcetypes : `WinEventLog` & `XmlWinEventLog` génériques |
| https://splunk.github.io/splunk-add-on-for-microsoft-windows/Troubleshoot/ | éditeur (miroir officiel) | 2026-09-11 | Renvoi explicite vers « source and sourcetype changes » |
| https://splunk.github.io/splunk-add-on-for-microsoft-windows/ReleaseNotes/ | éditeur (miroir officiel) | 2026-09-11 | Version 11.0.2 confirmée |
| https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector | éditeur | 2026-09-11 | Clés acceptées par `/event` : time, host, source, sourcetype, index, fields |
| https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo | éditeur | 2026-09-11 | **HTTP 403** — inaccessible, non exploitée |
| https://community.splunk.com/t5/Splunk-Enterprise-Security/Seeing-both-WinEventLogs-and-XmlWinEventlogs/m-p/513778 | tiers (forum) | 2026-09-11 | Subdivision WinEventLog / XmlWinEventLog depuis la 5.0.0 |
| https://community.splunk.com/t5/Getting-Data-In/Ingesting-XML-and-Classic-WinEventLogs-issue-renderXml-false/m-p/566524 | tiers (forum) | 2026-09-11 | Effet de `renderXml=false` sur le sourcetype |
| https://community.splunk.com/t5/Splunk-Enterprise/Sysmon-events-not-being-parsed-stuck-as-xmlwineventlog-even-with/m-p/754476 | tiers (forum) | 2026-09-11 | Forme `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| https://community.splunk.com/t5/Getting-Data-In/HEC-HTTP-Event-Collector-host-rename-using-props-transforms/m-p/462264 | tiers (forum) | 2026-09-11 | Avis contradictoires sur transforms et endpoint HEC — incertitude n°1 |
