# Adding a data source, and its attacks

Methodology distilled from the three add-ons that went through it end to end:
Palo Alto, Windows and Active Directory. Every step names the file it touches
and, where possible, the command that proves it worked.

The order matters. Each phase depends on the one before it, and the documentary
phase is the one that is tempting to skip and expensive to skip.

---

## The chain a field travels

Everything below exists to serve this chain. When something does not show up in
a datamodel, the break is always at one of these five links:

```
raw field in the event
   ↓  TA extraction        props.conf  REPORT-* / EXTRACT-* / INDEXED_EXTRACTIONS
CIM field                  props.conf  FIELDALIAS-* / EVAL-* / LOOKUP-*
   ↓  eventtype match      eventtypes.conf   (matches on sourcetype= and/or source=)
eventtype
   ↓  tag                  tags.conf
datamodel
```

Two consequences worth internalising:

- **A datamodel is never declared on our side.** It is granted by a tag, which is
  granted by an eventtype, which matches on metadata we put on the wire. Writing
  `"datamodels": ["Authentication"]` in the registry is a *description* of what
  the TA will do, not an instruction.
- **`sourcetype` and `source` are not interchangeable.** Some TAs match on one,
  some on the other, some on both. Windows matches the *bare* sourcetype in its
  root eventtype and the channel in `source=`. Get this wrong and events land,
  index, and produce nothing.

---

# Part 1 — A new data source

## Phase 0 — Documentary. No code.

Get the real TA and read it. Not the docs, the `.conf` files.

- [ ] **What sourcetype does the input actually set?** Read `inputs.conf`. If its
      stanzas set no `sourcetype`, splunkd sets it and you must find out to what.
- [ ] **Does the TA rename it?** `grep "^rename" props.conf`. A `rename = X` on
      `[X:something]` is proof the *input* sends the long form and the TA collapses
      it. **The collapsed name is a result, not a value to emit.**
- [ ] **Does it split at index time?** `grep TRANSFORMS props.conf`, then read the
      transforms for `DEST_KEY = MetaData:Sourcetype`. Palo Alto ingests everything
      as `pan:log` and fans it out into `pan:traffic` / `pan:threat` / `pan:system`.
- [ ] **What does `source=` do?** `grep -c "source=" eventtypes.conf` and
      `grep "^\[source::" props.conf`. If the TA classifies on source, it is not
      optional and it is per sourcetype.
- [ ] **Is the target stanza HEC-compatible?** Look for `INDEXED_EXTRACTIONS`,
      `LINE_BREAKER`, `SHOULD_LINEMERGE`, `CHARSET`. These belong to the
      structured-file parser, which `/services/collector/event` does not run.
- [ ] **Anything routed to nullQueue?** `grep -B5 nullQueue transforms.conf`, then
      find which stanza references that transform. Usually harmless (DHCP,
      firewall headers), occasionally not.
- [ ] **Is there a syslog collection path at all?** If the TA documents none,
      record `syslog_viable: False` later.
- [ ] Write the findings to `references/<vendor>-sourcetypes.md`, separating what
      is **sourced** from what is **deduced**. `windows-sourcetypes.md` is the model.

> **The trap that cost the most.** Distinguish three things and name them out
> loud: the **final** sourcetype (what the event ends up as), the **emitted**
> sourcetype (what we put on the wire), and the **emitted source**. They are
> different for Windows, identical for most others. Emitting the final value
> instead of the emitted one produced HTTP 200 on every event and nothing in the
> index.

## Phase 1 — Generator

`log_generators/<ta>.py`

- [ ] Class with `LOG_TYPE`, `AVG_LOG_SIZE`, `METADATA`, `SOURCETYPE_CONFIG`.
- [ ] `METADATA['sources']` — one entry per category, `{id, name, sourcetype}`.
      Set `sourcetype` **only** if that category really maps to its own Splunk
      sourcetype. All-or-nothing: the emitter treats the TA as "bridged" only when
      every source declares one.
- [ ] `SOURCETYPE_CONFIG` — `param_key`, `defaults`, and if the constructor takes a
      single value rather than a list: `multi_instance: True` +
      `single_param_name`. Extra constructor args go in `extra_params_keys`.
- [ ] Register in `log_generators/__init__.py` **and** `log_generators/registry.py`.
- [ ] **If the events describe a machine through more than one field** (hostname
      *and* IP, or IP *and* MAC), or carry **both an account and a host**:
      inherit `AIEntityMixin`, call `self._new_entity()` at the top of
      `generate()`, and read each field through `self._entity_field(pool, fallback)`.

> **The trap.** Wiring the field accessors without calling `_new_entity()` makes
> every lookup fall through to the generator's own values, silently. It shipped
> once. `tests/test_entity_pairing.py` now catches it for every add-on
> automatically.

## Phase 2 — Registry

`ta_registry.py` — the single source of truth. **No wire value may be written in
a generator or in a JS file.**

- [ ] TA entry: `name`, `display_name`, `vendor`, `description`.
- [ ] Wire metadata at TA level: `hec_default_sourcetype` when the TA ingests
      under one name. Absent means "emit the sourcetype's own name". If it depends
      on an option, use a `_by_render_format`-style map instead of a flat value.
- [ ] `syslog_viable: False` when the TA documents no syslog path.
- [ ] Per sourcetype: `name`, `description`, `datamodels`, `eventtypes`, `tags`,
      `datamodel_conditions`, and `hec_source` when the TA classifies on source.
- [ ] `fields[]` — **only fields A&I can actually supply.** Anything else is
      decorative and will rot. A&I supplies exactly:
      `entity(ip, nt_host, mac, fqdn, os, name)` and `account(username, email)`.
      A SID, a process, a command line is *not* an environment fact.
- [ ] Each field: `raw_field`, `cim_field`, `datamodels`, `ai_source`,
      `direction`, `description`, `mutable`. Justify `cim_field` with the
      props.conf line that produces it.

> Fields that vary per event subtype (Windows EventCodes) have no common base —
> verify with a frequency count before assuming one exists. Prefer the fields
> with the widest **event** coverage, not the widest *subtype* coverage.

## Phase 3 — A&I injection

`environment_manager.py`

- [ ] `ENTITY_TYPE_ROLES[<entity_type>]['<ta>'] = [(pool, entity_field, cim_field)]`
- [ ] `ACCOUNT_TYPE_ROLES[<account_type>]['<ta>'] = pool`
- [ ] `DOMAIN_ROLES['<ta>']` only if the source genuinely has a domain concept.
- [ ] **Verify each pool name exists on the generator.** A pool nobody reads is
      injected silently and does nothing:

```bash
python3 -c "
from environment_manager import ENTITY_TYPE_ROLES, ACCOUNT_TYPE_ROLES
from log_generators import REGISTRY
lt='<ta>'; c=REGISTRY[lt].SOURCETYPE_CONFIG
g=REGISTRY[lt](**{c.get('single_param_name') or c['param_key']:
                  c['defaults'][0] if c.get('multi_instance') else c['defaults']})
want={p for m in ENTITY_TYPE_ROLES.values() for p,_,_ in m.get(lt,[])}
want|={m[lt] for m in ACCOUNT_TYPE_ROLES.values() if m.get(lt)}
print('pools morts :', sorted(p for p in want if not hasattr(g,p)) or 'aucun')"
```

## Phase 4 — Frontend

- [ ] `static/js/modules/sourcetype-config.js` — `checkboxGroup`, `optionKey`,
      `formGroups`, and `additionalFields` if the TA has extra options.
- [ ] `templates/index.html` — the `<div class="form-group" id="<ta>LogTypesGroup">`
      with its checkboxes.
- [ ] `static/js/modules/senders.js` — add the group to the reset that hides
      every per-technology block.
- [ ] `static/js/modules/sender-form.js` — one `STYPE_TO_GEN_OPTIONS` entry per
      registry sourcetype, mapping it to the generator categories it covers.
      `{}` when the TA has a single sourcetype.
- [ ] **Bump `app.js?v=` in `index.html`.** Forgetting it serves a stale bundle
      and you will debug a bug you already fixed.

## Phase 5 — Prove it

- [ ] `pytest -q` — `test_registry_coherence.py` and `test_entity_pairing.py`
      pick up the new add-on automatically.
- [ ] `npm test`.
- [ ] **Capture the real wire.** Point a sender at a local HTTP listener and read
      the actual payloads — path, `index`, `sourcetype`, `source`, body shape.
      Asserting on a mock proves less than a listener does.
- [ ] `grep -rn "<the emitted sourcetype>" static/js/ log_generators/` must return
      nothing. If it matches, a wire value escaped the registry.
- [ ] Send a handful of events to a real Splunk and confirm, in this order:
      1. they arrive (`index=<x>` over **All time**, no sourcetype filter);
      2. under the expected `sourcetype` and `source`;
      3. the eventtype matches (`| eval e=eventtype`);
      4. the tags follow (`| eval t=tag`);
      5. the datamodel accelerates (`| datamodel <name> search`).
      Stopping at step 1 is how you end up believing a broken mapping works.

> **Before blaming the code when nothing shows up:** HEC returning 200 means
> *queued*, not *indexed*. Check the generator host's clock against Splunk's
> (`curl -skI <hec>/services/collector/health | grep -i ^date`). An event stamped
> in Splunk's future is invisible to every relative time range, since they all
> end at `now`.

---

# Part 2 — A new attack

Attacks live in `attack_generators.py`, in `ATTACK_REGISTRY`. They are a separate
path: **they never call `inject_into`**, so A&I coherence does not apply to them.
That is deliberate — the normal senders provide the coherent baseline, attacks
provide the anomaly that has to stand out against it.

## The link to a sourcetype

- [ ] **`data_sources`** — every sourcetype the attack can land in, as
      `{log_type, sourcetype, label, formats}`. `formats` are that source's render
      formats (Windows: `xml`, `classic`); each one has its own wire sourcetype
      and source in `ta_registry.py`, and the attack **forces** them.
- [ ] Declaring it is what moves an attack to the current configuration: the
      form shows sourcetype rows (a checkbox when there are several, a format
      picker when a source has several formats), Use Environment and Noise, and
      hides the HEC Sourcetype and Source overrides. An attack without
      `data_sources` keeps the legacy fields.
- [ ] **A source syslog does not collect means no syslog either.** Windows is
      read from the event log or shipped over HEC, and `ta_registry` says so with
      `syslog_viable: False`; `attack_destinations()` drops the destination and
      `attack_destinations_note()` gives the reason the form shows.
- [ ] **Several data sources means no syslog** (`attack_destinations()`): a
      syslog stream is classified by SC4S as one source. HEC stamps each event's
      sourcetype, and a Local File receives the events exactly as HEC sends them
      (`spans_several_sources()` — no per-source delivery format). The form
      disables syslog and `SenderManager` refuses it. A source with a single
      rendering declares one format; its name (`default`) is only a label.
- [ ] **The count asked for is the count sent.** Several selected sources share
      the events evenly — one probe recorded by one device — rather than each
      replaying the whole attack. That holds because these detections aggregate
      over the datamodel: `rule` sits in the inner tstats BY but never in the
      outer grouping, so rows from different firewalls merge into one group.

> **The trap this replaces.** An earlier version of this checklist said an
> attack "inherits its TA's wire metadata automatically". It did not: attack
> generators carried no metadata, so over HEC an attack went out under whatever
> sourcetype the destination defaulted to, or whatever was typed in the form.
> `SenderManager.attack_plan()` now resolves it from `data_sources`.

- [ ] The output must be parseable by that TA — same format, same fields — **in
      every declared format**. Windows' classic format is the forwarder's
      `LogName=` / `EventCode=` header followed by `Name:\tvalue` lines, not the
      Event Viewer layout.

## The detection

- [ ] **`detection`** — copied from `splunk/security_content`, not paraphrased:
      `name`, `id`, the `datamodel` node, the `where` clause verbatim, the fields
      it returns and its `entities`. `splunk_research_url` is the detection page
      itself: `https://research.splunk.com/<category>/<id>/`.
- [ ] **`ai_fields`** — only the returned fields an environment actually holds,
      which are usually exactly the detection's `entities`.
- [ ] **Noise** — a `generate_noise()` producing the same kind of event on the
      same targets, each variant a near miss for one clause of the `where`.
      Without it the attack is a signal with nothing to stand out from.
- [ ] **`defaults`** — `events`, `noise_events`, `duration` (0 sends at once).
- [ ] **A tstats `BY` drops every row where one BY field is null.** Record the
      `by` fields and check each source fills all of them. The port scan found
      two traps: Cisco ASA `302013` built connections carry no `rule` (the
      access-list decisions `106023`/`106100` do), and a FortiGate implicit deny
      (policy 0) has no `poluuid`, the add-on's only source of `rule`.
- [ ] An aggregating detection (a count over a group, a threshold) cannot be
      judged per event. Give the generator a `plan_identities(definition,
      options, attacks, noise, environment)` classmethod: it decides every
      event's values once, so all sources render the same ones, and the noise
      can be built to stay under the threshold by construction. `count_label` /
      `count_hint` rename the count when it is not "events" (distinct
      destinations), and `identity_fields` replaces the ratio slider with one
      control per field (`single`: Random / Environment / Custom; `distinct`:
      the environment first, completed at random).
- [ ] **Not every detection reads a datamodel.** One built on a macro
      (`wineventlog_security`) searches the events themselves, so what matters is
      the raw field name the add-on produces, not a CIM alias. Record the macro
      in `detection` instead of a datamodel and check the fields the search names
      — see `tests/test_attack_sid_history.py`, which found that `SidHistory`
      exists only in the XML rendering: the classic one carries the same value
      under the message label `SID History:`, which Splunk's wel-col-kv turns
      into `SID_History`, and no add-on aliases it back. Say so in the UI rather
      than renaming a label Windows does not write.
- [ ] **A step you cannot satisfy: warn, and make it reachable.** This detection
      ends in a lookup against Enterprise Security's `identity_lookup_expanded`,
      which no generator can write. The attack carries a `warning`
      (`{text, code}`, rendered above the configuration) giving the steps and the
      exact value to copy, and the value it hands over is a **fixed** default —
      one row added to an identities lookup then matches every run. The same
      constant fills the form's field, and a test asserts the two cannot drift.
      Warn about what the reader must do; do not fake the step, and do not offer
      a random value they could never register in advance.
- [ ] **Check the field the detection names, not the field you expect.** A raw
      search compares what the add-on produced, character for character. The
      Cisco one reads `command` from
      `CFGLOG_LOGGEDCMD:\sUser:(\S+)\s\slogged command:(.+)` — two spaces, and
      nothing between the colon and the command. One space fewer and the field
      never exists; one space more and its value starts with a space, so
      `command="monitor session*"` misses. Both still parse as events. That check
      found the same bug in the plain cisco:ios sender, where none of the logged
      commands had ever been extracted.
- [ ] **Two CIM fields off one event can disagree, and sometimes that is the
      point.** `Endpoint.Processes` builds `process_path` from the image name
      and `process` from the command line, which are different raw fields:
      the SysWOW64 detection fires precisely because WOW64 redirection makes
      them disagree (the image lands in `SysWOW64`, the command line still names
      the `System32` path that was asked for). Read each field back to the raw
      field it comes from before assuming one event carries one value.
- [ ] **A CIM EVAL can be conditional — satisfy its condition.** `EVAL-process`
      takes `Process_Command_Line` only when its first token holds a backslash,
      and otherwise falls back to the image path. A command line starting with a
      bare `cmd.exe` would therefore reach `process` stripped of the very path
      the detection globs for, with no error anywhere. Every command line the
      generator writes starts with a full path, which is what Windows writes
      anyway, and `tests/test_attack_syswow64.py` pins both the condition (read
      off props.conf) and the generator's compliance.
- [ ] **Do not declare a data source you cannot check.** The SysWOW64 detection
      also lists Sysmon EventID 1, but no Sysmon add-on ships in `TAs/`, so
      nothing here can verify how a Sysmon event maps into `Endpoint.Processes`.
      The source is left undeclared, with the reason in a comment beside
      `data_sources` and a test that fails the day the add-on appears.
- [ ] Test it the way `tests/test_attack_tor.py` (a per-event `where`),
      `tests/test_attack_port_scan.py` (a tstats aggregation),
      `tests/test_attack_sid_history.py` (a macro search),
      `tests/test_attack_traffic_mirroring.py` (a macro search whose clause
      compares an extracted value) or `tests/test_attack_syswow64.py` (a
      datamodel `where` over two fields built from different raw ones) does:
      extract the detection's fields the way each TA does, from its shipped
      .conf and lookup files, and require the attack to fire and the noise not
      to.

## The datamodel

- [ ] `'datamodel'` must be one the TA **actually grants** for the events you
      emit — check `eventtypes.conf` and `tags.conf`, not intuition. An attack
      declaring `Authentication` whose events never match an authentication
      eventtype will never appear in the datamodel.
- [ ] Verify on real events, not on the declaration:
      `| datamodel Authentication search | search <your marker>`.

## The entry

- [ ] `name`, `description` — shown in the sender picker.
- [ ] `category` — groups it in the UI (`SSH`, `Network`, `Endpoint`…).
- [ ] `splunk_research_url` — the detection this exercises. Prefer an exact
      detection UUID over a search URL.
- [ ] `field_behaviors` — `fixed` or `rotating` per field. This *is* the attack's
      signature and what a detection keys on:

  | | `src_ip` fixed | `src_ip` rotating |
  |---|---|---|
  | **`user` fixed** | brute force | distributed brute force |
  | **`user` rotating** | password spraying | credential stuffing |

  Adding a variant means filling a cell of this matrix, not inventing a name.
- [ ] `ai_fields` — which fields the A&I picker offers for this attack.
- [ ] `sample_logs` — two or three real lines, shown in the UI. Never invent a
      format: copy a genuine one from the vendor's documentation.
- [ ] Overrides: the UI writes `target_<field>` into the sender options, read by
      `options.get(f'target_{field}')`. Any field in `field_behaviors` can be
      pinned by the user.

## Prove it

- [ ] The attack shows in the picker under its category, and the sourcetype list
      is hidden (attack mode has no registry sourcetype).
- [ ] Its events reach Splunk under the host TA's sourcetype and source.
- [ ] The declared eventtype, tag and datamodel all match on real events.
- [ ] Against a coherent A&I baseline running in parallel, the attack **stands
      out** — that is the actual acceptance test, and the reason volets A and B
      exist.

---

## Current state, for reference

| Complete (phases 0–5) | Legacy schema (`fields[]` empty) |
|---|---|
| all ten: paloalto, windows, active_directory, auditd, ssh, zscaler, cisco_asa, apache, cisco_ios, fortigate | — |

Two sources were dropped rather than left declaring what they could not reach:
`cisco_xr` (TA_cisco_catalyst has no `[cisco:xr]` stanza — IOS XR syslog is
handled under `cisco:ios`) and `cisco_ftd` (no longer supported).

Four sourcetypes parse but reach no datamodel, and say so rather than claiming
one: `apache:access:combined` (not listed in [access_log_event]), `apache:error`
and `cisco:ios` (`error` and `cisco network ios` are not CIM combinations), and
`zscalernss-tunnel` (no eventtype matches it). That is the add-ons' design, not a
gap: plenty of operational logging has no dataset to belong to. Our job is to
reproduce the format faithfully and record what the add-on does with it — a local
eventtype can close any of them, the way `references/splunk-local/` does for
auditd, but that is a deployment choice rather than a fix.

One more trap worth carrying forward, from Fortinet: **an add-on's own sample
is not proof its events reach a datamodel.** Three of the samples shipped with
`Splunk_TA_fortinet_fortigate` match no eventtype — the authentication one
carries `status=logout` where `[ftnt_fortigate_auth]` requires success or
failure, and both virus ones carry `action=analytics`, which
`[ftnt_fortigate_virus]` explicitly excludes. Copy the sample's *shape*; take
the *values* from the eventtype searches and the lookups.

Attacks cover ssh (4, custom rather than from research.splunk.com),
paloalto / fortigate / cisco_asa (the horizontal and vertical port scans, each
over all three), windows (TOR client execution, AD SID history addition) and
cisco_ios (traffic mirroring). Active Directory has none
despite being fully mapped — the richest ground for detections, and the obvious
next target.
