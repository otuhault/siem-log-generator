# Fortinet FortiGate — Phase 0, before writing any code

Documentary pass on `Splunk_TA_fortinet_fortigate` as shipped in
`TAs/Splunk_TA_fortinet_fortigate/` (version 1.6.10, `default/app.conf:22`),
following `references/adding-a-source.md`. **Sourced** facts cite the file and
line; anything else is marked as deduced.

The headline: the sourcetype names everyone quotes — `fgt_traffic`, `fgt_utm`,
`fgt_event` — are aliases. In 1.6 the canonical stanzas are `fortigate_*` and the
`fgt_*` ones only `rename` into them. Emitting the alias still works; emitting
the canonical name is what a 1.6 deployment is configured for.

---

## 1. Which sourcetype to emit

There is **no `inputs.conf`** in this add-on. Nothing collects on its own: the
sourcetype is set by whoever ingests — SC4S, a HEC caller, or a TCP input. So
the question is not "what does the input set" but "what does the add-on parse".

`props.conf` answers it, and the direction of the `rename` is the whole answer:

```
props.conf:11  [fortigate_traffic]   ← 53 lines of extractions and aliases
props.conf:65  [fgt_traffic]
props.conf:66  rename = fortigate_traffic
```

Same for `utm` (68/122), `anomaly` (125/169) and `event` (172/230). The
configuration lives on `fortigate_*`; `fgt_*` is an empty stanza that points at
it. **The FINAL sourcetype is `fortigate_*`, whichever of the two is emitted.**

That matches the SC4S option, which the product documentation words the other
way round:

> `SC4S_OPTION_FORTINET_SOURCETYPE_PREFIX` — default `fgt`. Starting with
> version 1.6 of the add-on the sourcetype changed from `fgt_*`; to use the new
> sourcetype set this variable to `fortigate`.

The add-on's own `README.txt:40-73` still lists the `fgt_*` names, and so does
the SC4S sourcetype table. Both predate 1.6. `eventtypes.conf` covers the two
spellings on every single stanza (`sourcetype=fgt_utm OR sourcetype=fortigate_utm`,
lines 2-110), so nothing breaks either way — but there is no reason to emit the
legacy spelling against a 1.6 add-on.

**Decision: emit `fortigate_traffic`, `fortigate_utm`, `fortigate_event`,
`fortigate_anomaly`.**

### The umbrella that exists and that we do not use

`[fortigate_log]` and `[fgt_log]` (props.conf:1-9) carry an index-time fan-out,
exactly the shape Palo Alto uses:

```
transforms.conf:2  [force_sourcetype_fortigate]
                   DEST_KEY = MetaData:Sourcetype
                   REGEX  = ^(?=.*\bdevid="?F(?:G|W|\dK)[^"\s]*"?).*?\btype="?(traffic|utm|event|anomaly)\b
                   FORMAT = sourcetype::fortigate_$1
```

So a caller who does not know the category can send everything as
`fortigate_log` and let the add-on sort it. We do know the category — the sender
picks it — so we emit the specific sourcetype and leave `hec_default_sourcetype`
unset.

Two things the regex tells us anyway, and they constrain the generator:

- `devid` must start with `FG`, `FW` or `F<digit>K`. A device id outside that set
  strands an umbrella feed in `fortigate_log` with no extractions at all.
- `type=` must be one of `traffic|utm|event|anomaly` — the four sourcetypes, and
  the reason `anomaly` is in the catalogue even though the SC4S table omits it.

## 2. `source` plays no part

```
grep -c "source=" default/eventtypes.conf   → 0
grep -n "^\[source::" default/props.conf    → none
```

Nothing classifies on `source`. **No `hec_source`** — the opposite of Windows,
and of auditd where `[auditd_modify]` keys on `source=auditd`.

## 3. HEC compatibility

No `INDEXED_EXTRACTIONS`, no `LINE_BREAKER`, no `CHARSET` anywhere in
`props.conf`. `SHOULD_LINEMERGE = false` and `EVENT_BREAKER_ENABLE = true` are
the file/TCP parser's business and are simply not consulted by
`/services/collector/event`.

Field extraction is search-time and delimiter-based:

```
props.conf:15   KV_MODE = none
props.conf:16   REPORT-field_extract = field_extract
transforms.conf:24  [field_extract]
                    DELIMS = "\ ,", "="
```

Space or comma separates the pairs, `=` separates key from value, quotes are
stripped. Nothing here depends on how the event arrived, so HEC and syslog are
equivalent for parsing.

No `nullQueue` anywhere in `transforms.conf`.

## 4. The timestamp, and why there must be no BSD header

Every stanza sets `TIME_PREFIX = ^` (props.conf:12, 70, 126, 173) with no
`MAX_TIMESTAMP_LOOKAHEAD`. The timestamp is expected **at offset zero**, and the
event begins with its own:

```
date=2015-08-11 time=19:19:43 devname=Nosey devid=FG800C3912801080 ...
```

FortiOS over syslog sends the priority and then that same payload, with no
RFC 3164 header of its own:

```
<189>date=2019-05-13 time=11:29:55 devname="FGT" devid="FG..." type="traffic" ...
```

This is why the SC4S entry says *"MSG format based filter"*: there is no program
name and no hostname in the header to route on, so SC4S matches on the message
body instead.

> **Consequence for us.** The generic framer in `syslog_framing.py` prepends
> `<PRI>Mmm dd HH:MM:SS host tag:` when a line has no BSD header. Doing that here
> would be wrong twice over: it is not what a FortiGate sends, and with
> `TIME_PREFIX = ^` Splunk would read the *header's* timestamp — no year, no
> sub-second — instead of the event's own `date=`/`time=`. FortiGate needs
> priority-only framing.

The PRI's severity is not fixed either: FortiOS derives it from the event's own
`level=`, whose vocabulary the add-on spells out in
`lookups/ftnt_severity_info.csv` — `emergency, alert, critical, error, warning,
notice, information, debug`. Those are the syslog severity names, give or take
the spelling of three of them.

## 5. The lookups drive the repertoire

Like auditd's action lookup, these decide what CIM sees. Generating a value
outside them yields no `action`, and an event with no `action` is worth little
in Network_Traffic or Change.

`lookups/ftnt_action_info.csv` — `ftnt_action` → `action`, applied to traffic,
utm and anomaly (props.conf:29, 91, 144). 21 rows, among them
`accept/allow/pass/passthrough/detected/start → allowed`,
`deny/block/blocked/dropped/clear_session → blocked`, `timeout → teardown`,
`analytics/monitored → deferred`.

`lookups/ftnt_event_action_info.csv` — `(subtype, vendor_action, vendor_status)`
→ `(action, change_type)`, applied to `fortigate_event` (props.conf:192). 53
rows. The ones this generator has to hit exactly:

| subtype | action= | status= | → action | change_type |
|---|---|---|---|---|
| user | authentication | success / failure | success / failure | auth |
| system | login | success / **failed** | success / failure | auth |
| system | logout | success | logoff | AAA |
| system | Edit / Add / delete | unknown | modified / created / deleted | network_config |
| vpn | negotiate | success / failure | success / failure | auth |
| vpn | tunnel-up / install_sa / ssl-new-con | unknown | added | network_config |
| vpn | tunnel-down / delete_ipsec_sa | unknown | blocked | network_config |

Note `status=failed` for a failed admin login and `status=failure` for a failed
user authentication. The lookup is the spec; the spelling is not ours to choose.

`lookups/ftnt_severity_info.csv` maps `level` → `severity`/`severity_id`.

## 6. What each subtype reaches, and how

`eventtypes.conf` matches on `sourcetype` plus `subtype` (and sometimes
`vendor_action`, `vendor_status` or `logid`); `tags.conf` grants the tags.

| sourcetype | subtype | eventtype | tags | datamodel |
|---|---|---|---|---|
| fortigate_traffic | forward | `ftnt_fortigate_traffic` | network, communicate | Network_Traffic |
| fortigate_utm | app-ctrl | `ftnt_fortigate_appctrl` | network, communicate | Network_Traffic |
| fortigate_utm | webfilter | `ftnt_fortigate_webfilter` | web | Web |
| fortigate_utm | ips | `ftnt_fortigate_ips` | ids, attack | Intrusion_Detection |
| fortigate_utm | virus (`action!=analytics`) | `ftnt_fortigate_virus` | malware, attack, operations | Malware |
| fortigate_anomaly | anomaly | `ftnt_fortigate_anomaly` | ids, attack | Intrusion_Detection |
| fortigate_event | user + `action=authentication` + `status IN(success,failure)` | `ftnt_fortigate_auth` | authentication, default | Authentication |
| fortigate_event | system + `action=login` | `ftnt_fortigate_auth_privileged_login` | authentication, privileged | Authentication (privileged) |
| fortigate_event | system + `action=logout` | `ftnt_fortigate_auth_privileged_logout` | change, account | Change.Account_Management |
| fortigate_event | vpn + `action IN(negotiate, ssl-login-fail)` | `ftnt_fortigate_vpn_auth` | authentication, default | Authentication |
| fortigate_event | vpn + `action IN(tunnel-up, install_sa, ssl-new-con, ssl-web-pass)` | `ftnt_fortigate_vpn_start` | network, session, vpn, start | Network_Sessions |
| fortigate_event | vpn + `action IN(tunnel-down, delete_ipsec_sa, ssl-web-close)` | `ftnt_fortigate_vpn_end` | network, session, vpn, end | Network_Sessions |
| fortigate_event | system + `action IN(Add, Edit, delete, …)` | `ftnt_fortigate_config_change` | change, network | Change.Network_Changes |
| fortigate_event | system + `action=perf-stats` | `ftnt_fortigate_perf_stats` | os, performance, cpu, memory | Performance |

Three traps in that table, all of them from reading the searches rather than the
subtype names:

- `[ftnt_fortigate_auth]` (eventtypes.conf:77) requires
  `vendor_status=success OR vendor_status=failure`. The add-on's own sample
  (`samples/sample.ftnt_fortigate_auth`) carries `status=logout` and therefore
  **matches nothing**. A generator copying the sample verbatim would produce a
  perfectly parsed event in no datamodel at all.
- `[ftnt_fortigate_virus]` (line 23) excludes `vendor_action=analytics`, which is
  precisely what both shipped virus samples carry — those are sandbox
  submissions, not detections.
- `[ftnt_fortigate_auth_privileged_login]` (line 83) excludes
  `logid IN(0100022952, 0100022949)`; those two are FortiCloud/FortiGuard
  logins, not administrator logins.

`EVAL-user_type` (props.conf:207) keys on `logdesc` matching `^Admin log(?:out|in)`,
so an admin event needs that `logdesc` to be typed as an Admin.

## 7. Subtypes deliberately left out

`spam`, `netscan`, `dlp` and `wireless` all have eventtypes and, for the first
three, tags. They are excluded from the first pass because the add-on ships no
sample for any of them and the field layout would be guesswork — and a guessed
layout that parses is worse than an absent one, because it looks right.
`wireless` additionally needs an AP roster that A&I has no concept of.

## 8. Wire summary

| | value | source |
|---|---|---|
| emitted sourcetype | `fortigate_traffic` / `_utm` / `_event` / `_anomaly` | props.conf canonical stanzas |
| final sourcetype | identical | no rename on the canonical names |
| emitted source | none | nothing classifies on `source` |
| syslog | priority only, no BSD header | `TIME_PREFIX = ^` + FortiOS wire format |
| facility | `local7` | FortiOS default (`config log syslogd setting`) — deduced, not in the add-on |
| severity | follows `level=` | `lookups/ftnt_severity_info.csv` vocabulary |
| index (SC4S) | `netfw` for traffic/utm, `netops` for event/log | SC4S product documentation |
