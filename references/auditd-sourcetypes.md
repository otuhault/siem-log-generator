# auditd — Phase 0, before writing any code

Documentary pass on `Splunk_TA_nix` as shipped in `TAs/Splunk_TA_nix/`, following
`references/adding-a-source.md`. **Sourced** facts cite the file and line;
anything else is marked as deduced or undetermined.

The headline: unlike SSH, there is no sourcetype that gives a clean CIM
datamodel out of the box. That is a decision to take, not a detail to discover
halfway through the implementation.

---

## 1. Two sourcetypes, two different collection methods

The add-on knows two, and they are **not** two names for the same bytes.

| | `auditd` | `linux_audit` |
|---|---|---|
| Status in TA 10.3.4 | **current** (`props.conf:801`, its own section) | **legacy** (`props.conf:573`, inside the retired block) |
| Produced by | `[script://./bin/rlog.sh]`, `inputs.conf:155` | scripts from TA-deploymentapps, retired |
| Command | `/sbin/ausearch -i` (`bin/rlog.sh`) | — |
| Format | ausearch **interpreted** | raw `/var/log/audit/audit.log` |
| Eventtype | `[auditd]`, `[auditd_modify]` | **none** |
| Tags | `os unix resource file`, `modify` | **none** |
| Auto-KV (`KV_MODE` unset) | yes | yes |
| CIM aliases | **none** | 20 |

**`linux_audit` is explicitly retired.** `props.conf:559-660` is delimited
`BEGIN`/`END SCRIPTED INPUT CONTENT IMPORTED FROM TA-deployment-apps` and says so:

> Stanzas in this section are legacy configuration stanzas intended to support
> parsing of data created by scripts in TA-deploymentapps, **which has since been
> retired**.

`[linux_audit]` sits at line 573, inside that block. Its richer mapping exists
because it was written for those old scripts and is kept so historical data still
parses — not because it is the recommended path. (`[linux_secure]` at 731 and
`[auditd]` at 802 are both outside the block, so the SSH work targeted correctly.)

**The `-i` flag is the whole distinction.** `ausearch -i` resolves numeric ids to
names (`uid=0` → `uid=root`), rewrites the timestamp to a human-readable form,
and **strips the quotes** around values.

Two details in the add-on confirm which stanza expects which:

- `props.conf` `[auditd]` and `[linux_audit]` both set `TIME_PREFIX = audit\(`
  with `MAX_TIMESTAMP_LOOKAHEAD = 23`. Twenty-three characters is the width of
  `11/09/2026 18:00:00.123`, the interpreted form — not of a raw epoch
  (`1699999999.123:4242`, ~19).
- `transforms.conf:286` `[command_for_linux_audit]` is
  `REGEX = exe=.*\/(\S+)\"` — it requires a **closing double quote** after the
  path. `ausearch -i` removes quotes, raw `audit.log` keeps them.

> **Deduced, not sourced:** `[monitor:///var/log]` (`inputs.conf:177`) whitelists
> `\.log`, so it does pick up `/var/log/audit/audit.log`, and it sets no
> sourcetype of its own — splunkd classifies. `linux_audit` being a Splunk
> built-in learned sourcetype is the most plausible route, but the add-on does
> not state it. Worth confirming on the lab before committing to the format.

## 2. Where the CIM mapping actually lives

`[linux_audit]` carries everything, `[auditd]` almost nothing.

`props.conf` `[linux_audit]` produces, among others:

```
FIELDALIAS-dest              hostname AS dest        FIELDALIAS-dvc   hostname AS dvc
EVAL-status                  res=="failed" -> failure
EVAL-change_type             "AAA"
EVAL-user / EVAL-user_name   from acct / id / uid depending on type=
FIELDALIAS-object / object_id  id AS object
LOOKUP-action                nix_linux_audit_action_lookup op OUTPUT action, object_category
REPORT-command               exe="/usr/sbin/x" -> command=x
```

`props.conf` `[auditd]` produces only `proctitle` and `execve_command`.

`EVAL-change_type = "AAA"` is a **Change** datamodel field, and the action lookup
outputs `action` and `object_category` — the add-on plainly intends account
management to land in Change.

**And yet `linux_audit` has no eventtype anywhere in the add-on**, so it receives
no tag, so nothing reaches a datamodel. Verified by grepping every stanza of
`eventtypes.conf`: `linux_audit` appears once, inside the `[nix_ta_data]`
sourcetype list, and nowhere else.

The action lookup (`lookups/nix_linux_audit_action_object_category.csv`) is small
and tells us exactly which operations are recognised:

```
op                                action    object_category
add-user, add-home-dir            created   user
add-group, add-shadow-group       created   group
delete-user                       deleted   user
delete-group, delete-shadow-group deleted   group
deleting-user-from-group          modified  user
deleting-user-from-shadow-group   modified  user
success / failed                  success / failure   user
```

Eleven rows. **Generating operations outside this list produces no `action` and
no `object_category`**, so the event stays out of Change even once tagged. This
list should drive the generator's repertoire, not the other way round.

## 3. What `auditd` gets, and whether it is useful

`eventtypes.conf` `[auditd]` matches `sourcetype=auditd` and `tags.conf` grants
`os unix resource file`. `[auditd_modify]` matches `source=auditd PATH` and adds
`modify`.

> **Undetermined.** Whether `os unix resource file modify` populates a CIM
> dataset cannot be settled from the add-on alone — it depends on the CIM app's
> tag definitions, which are not in `TAs/`. It is *not* the Change combination
> (`change` + `audit`) nor Endpoint.Filesystem (`endpoint` + `filesystem`).
> Resolve this on the lab with `| tstats count from datamodel=Change` before
> assuming either way.

Note also that `[auditd_modify]` keys on **`source=auditd`**, not sourcetype.
That is the literal string `auditd`, set by `inputs.conf:156 source = auditd`. If
we emit that sourcetype we must emit that source too, or the `modify` tag never
appears. This is a `hec_source` case, unlike SSH.

## 4. The decision, and the correction to it

An earlier pass of this document recommended `linux_audit` because it carries the
richer mapping. **That was wrong**: it recommended a retired path because it
looked better furnished. The furnishing is a fossil.

Both sourcetypes leave `KV_MODE` unset, so Splunk's automatic key=value
extraction runs on both — `type`, `acct`, `uid`, `res`, `exe`, `op` all land
either way. The real difference is the twenty CIM aliases only `linux_audit`
declares: `dest`, `dvc`, `user`, `src_user`, `action`, `status`, `change_type`,
`object`, `command`, and the action lookup.

**Emit `auditd`.** It is what the add-on's own input produces, it is the only one
with eventtypes and tags, and it is supported. Then add the missing CIM aliases
in a `local/props.conf` on the Splunk side — building on the supported path and
completing it, rather than building on a retired one.

Two consequences for the generator:

- **Emit the `ausearch -i` format**, not raw `audit.log`: ids resolved to names,
  timestamp `11/09/2026 18:00:00.123`, no quotes around values.
- **Emit `source=auditd`** as well. `[auditd_modify]` keys on `source=auditd PATH`,
  not on the sourcetype, so without it the `modify` tag never appears. This is a
  `hec_source` case, unlike SSH.

### The Splunk-side configuration this implies

To be dropped in `$SPLUNK_HOME/etc/apps/Splunk_TA_nix/local/`. It ports the CIM
aliases from the retired stanza onto the supported one, and nothing else.

`local/props.conf`

```ini
[auditd]
FIELDALIAS-dest_for_auditd = hostname AS dest
FIELDALIAS-dvc_for_auditd  = hostname AS dvc
EVAL-user       = case(type=="USER_AUTH", acct, type IN("USER_CMD","ADD_USER","DEL_USER","USER_MGMT"), coalesce(acct, id), true(), uid)
EVAL-user_name  = user
EVAL-src_user   = auid
EVAL-status     = if(res=="failed", "failure", res)
EVAL-change_type = "AAA"
EVAL-vendor_product = "nix"
EVAL-app        = "nix"
REPORT-command_for_auditd = command_for_auditd
LOOKUP-action_for_auditd  = nix_linux_audit_action_lookup op OUTPUT action, object_category
```

`local/transforms.conf` — the shipped `[command_for_linux_audit]` requires a
closing quote that `ausearch -i` strips, so it needs an unquoted twin:

```ini
[command_for_auditd]
REGEX = exe=(?:")?[^\s"]*\/([^\s"]+)
FORMAT = command::$1
```

`local/eventtypes.conf` and `local/tags.conf` — only if the Change datamodel is
wanted, since `os unix resource file` does not grant it:

```ini
# eventtypes.conf
[auditd_account_management]
search = sourcetype=auditd type IN (ADD_USER, DEL_USER, USER_MGMT, ADD_GROUP, DEL_GROUP, GRP_MGMT)

# tags.conf
[eventtype=auditd_account_management]
change = enabled
account = enabled
```

## 5. Event repertoire to generate

Driven by the lookup and by `EVAL-user` / `EVAL-object_attrs`, which branch on
`type=`. These are the types the add-on has logic for:

| `type=` | Covered by | Emits |
|---|---|---|
| `ADD_USER` | `EVAL-object_attrs`, `EVAL-user` | user creation |
| `DEL_USER` | idem | user deletion |
| `USER_MGMT` | idem | group membership change |
| `ADD_GROUP` / `DEL_GROUP` / `GRP_MGMT` | `EVAL-object`, `EVAL-user` | group lifecycle |
| `USER_AUTH` | `EVAL-user` reads `acct` | pam authentication |
| `USER_CMD` | `EVAL-user` reads `id` | sudo command |
| `EXECVE` | `[auditd]` `EXTRACT-execve_command` | process execution |
| `PATH` | `[auditd_modify]` | file modification |

`EVAL-op = if(op=="PAM:authentication", res, op)` means `USER_AUTH` events should
carry `op=PAM:authentication` and `res=success|failed`, which the lookup then
turns into `action=success|failure`.

## 6. Draft plan, once the option is chosen

Following `references/adding-a-source.md`:

1. **Phase 1** — `log_generators/auditd.py`. Categories mirroring §5, one message
   builder per `type=`. Inherit `AIEntityMixin`: an audit line carries both an
   account (`acct` / `auid`) and a host (`hostname`), so volet B applies.
2. **Phase 2** — registry entry, `auditd`, with `hec_source: "auditd"`, and
   datamodels reflecting whatever the tagging decision yields. `fields[]` limited to what A&I supplies:
   `hostname` → `dest`/`dvc`, `acct` → `user`, and nothing else — a uid, a
   syscall or an inode is not an environment fact.
3. **Phase 3** — `ENTITY_TYPE_ROLES['server']['auditd']` and the account roles.
4. **Phase 4** — the usual four frontend touchpoints, plus the `app.js?v=` bump.
5. **Phase 5** — a `tests/test_auditd_cim.py` parsing the shipped `.conf` the way
   `test_ssh_cim.py` does, so an add-on upgrade fails the suite rather than
   silently invalidating it.

**Attack candidates once the source exists**, all Change or Endpoint:
account created outside change window, sudo to root by a non-admin, mass user
deletion, `EXECVE` of a known offensive binary. Each needs a `datamodel` the
tagging decision above actually grants — check before declaring, as always.
