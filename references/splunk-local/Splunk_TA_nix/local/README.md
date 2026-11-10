# Splunk-side configuration for auditd

Drop `Splunk_TA_nix/local/` into `$SPLUNK_HOME/etc/apps/Splunk_TA_nix/`, then
`| extract reload=t` or restart. Nothing here overrides the add-on; it only adds
to the `[auditd]` stanza what the retired `[linux_audit]` stanza already had.

**Why this is needed.** `auditd` is the supported sourcetype in TA 10.3.4 — the
one the add-on's own `rlog.sh` input produces, and the only one with eventtypes
and tags. But every CIM alias (`dest`, `user`, `action`, `status`, `change_type`)
lives on `[linux_audit]`, which sits inside props.conf's
`BEGIN`/`END SCRIPTED INPUT CONTENT IMPORTED FROM TA-deployment-apps` block and
exists only so data from a withdrawn add-on still parses.

So the supported path has the tags and no fields, the retired path has the fields
and no tags. This ports the fields onto the supported path.

See `references/auditd-sourcetypes.md` for the documentary pass.

## What each file does

| File | Effect |
|---|---|
| `props.conf` | CIM aliases on `[auditd]`, plus the action lookup |
| `transforms.conf` | `command=` from `exe=`, without the quote the raw-format twin requires |
| `eventtypes.conf` + `tags.conf` | **optional** — only if you want account management in the Change datamodel |

The eventtype and tag are separate on purpose. The add-on grants
`os unix resource file` (and `modify` on PATH records), which is not the Change
combination. Adding `change` is a decision, not a fix, so it is opt-in.

## Checking it worked

```spl
index=<your index> sourcetype=auditd
| stats count by type, action, user, dest
```

`action` and `object_category` only populate for the eleven operations in
`lookups/nix_linux_audit_action_object_category.csv`. The generator is
constrained to those, so anything blank there is a configuration problem, not a
data problem.

With the optional files in place:

```spl
| datamodel Change search | search sourcetype=auditd | stats count by action, object_category
```
