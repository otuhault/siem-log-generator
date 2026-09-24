r"""
TA Registry — Splunk Technical Addon Metadata (v2 — field-aware)

Single source of truth for:
  - TA / sourcetype catalog
  - Datamodel mapping (with conditional rules — Splunk-style eventtype + tag matching)
  - Field-level mapping: raw_field ↔ cim_field ↔ A&I source (entity / account / network pool / random / static)
  - Wire metadata: which `source` and `sourcetype` to stamp on each event

Three distinct things, easy to conflate:
  - FINAL sourcetype  — what the event ends up as once the TA has processed it.
    That is the `name` of a sourcetype entry, and the identifier used everywhere.
  - EMITTED sourcetype — `hec_default_sourcetype` (TA level), what we put on the
    wire. Palo Alto ingests as pan:log and the TA splits it at index time.
    Absent means "emit the sourcetype's own name".
  - EMITTED source     — `hec_source` (sourcetype level), the `source` metadata.
    The Windows TA classifies almost entirely on `source=`, so it is not optional
    there. Absent means "no documented value": emit nothing rather than invent one.

Windows is the cautionary case, and its two metadata do different jobs.
eventtypes.conf splits them explicitly:

    :13  sourcetype=WinEventLog OR sourcetype=XmlWinEventLog OR sourcetype=WMI:…
    :29  source=WinEventLog:Security OR source=WMI:WinEventLog:Security
           OR source=XmlWinEventLog:Security

So the sourcetype must be BARE — the channel belongs to `source`, and `source` is
what selects the per-channel eventtype that grants the CIM tags. That is why
`hec_source` is mandatory here and why it is per sourcetype.

Which of the two bare forms applies depends on the body, i.e. on render_format,
and the TA derives `source` from the body the same way (transforms.conf):

    render_format   sourcetype        source                     TA transform
    xml             XmlWinEventLog    XmlWinEventLog:<Channel>   ta-windows-fix-xml-source
    classic         WinEventLog       WinEventLog:<Channel>      ta-windows-fix-classic-source

Both follow render_format together and the two forms are never mixed, hence
`hec_default_sourcetype_by_render_format` and `hec_source_by_render_format`
rather than flat values. active_directory has no render_format option — always
XML — so it carries the flat keys instead.

One caveat worth keeping in mind: every stanza XmlWinEventLog matches
(`[XmlWinEventLog]`, `[(::){0}XmlWinEventLog:*\S+]`) declares
INDEXED_EXTRACTIONS = XMLKV-WINEVT and LINE_BREAKER, which belong to the
structured-file parser that HEC /services/collector/event does not run. XML
events are therefore delivered but not index-time parsed, and `KV_MODE = none`
means nothing generic parses them at search time either. What populates the
fields is the TA's own search-time fallback on `[XmlWinEventLog]`:

    REPORT-0xml_block_extract = …, eventdata_xml_block, …
    REPORT-0xml_kv_extract    = …, eventdata_xml_data, …
    [eventdata_xml_data]  REGEX = <(?:\w+)\sName='([^>]*)'\/?>([^<]*)…

It depends on the sourcetype — and on the body being in the form Windows
renders: single-quoted attributes. Sixteen other transforms (process,
parent_process, the command line) share that assumption; the System ones accept
either quote. So a double-quoted template parses EventCode and Computer and
silently loses every EventData field. log_generators/windows_xml.py renders every
XML event in that form, and tests/test_windows_xml.py runs these transforms over
the output.

See references/windows-sourcetypes.md.

Schema per sourcetype:
  {
    "name": "pan:traffic",
    "description": "...",
    "datamodels":  ["Network_Traffic"],          # primary (legacy summary)
    "eventtypes":  ["pan_traffic"],              # primary (legacy summary)
    "tags":        ["network", "communicate"],   # primary (legacy summary)
    "entity_types":  [...],                      # legacy summary (auto-derived from fields[])
    "account_types": [...],                      # legacy summary (auto-derived from fields[])
    "datamodel_conditions": [
        {
          "when":       "always" | "log_subtype == 'auth'" | "default" | <human-readable>,
          "match":      <programmatic predicate, optional>,
          "eventtype":  "pan_system_auth",
          "tags":       ["authentication"],
          "datamodels": ["Authentication"],
        },
        ...
    ],
    "fields": [
        {
          "raw_field":   "dvc_name",
          "csv_position": 53,                    # 1-indexed for human-readability (documentation only)
          "cim_field":   "dvc",
          "datamodels":  ["Network_Traffic"],
          "ai_source": {                         # how to feed the field
            "type": "entity" | "account" | "network_pool" | "either" | "random" | "static",
            ...source-specific keys...
          },
          "direction":   "src" | "dest" | None,
          "description": "Firewall device hostname",
          "mutable":     True,
        },
        ...
    ]
  }

Convention `ai_source.type`:
  - entity        → {entity_type, entity_field}
  - account       → {account_type, account_field}
  - network_pool  → {role: "src_pool" | "dest_pool"}
  - either        → {options: [<entity|account|network_pool spec>, ...]}  (sender chooses)
  - random        → field stays random (default)
  - static        → user-typed comma-separated list
"""

from copy import deepcopy


# ──────────────────────────────────────────────────────────────────────────────
# Palo Alto Networks — full Phase-3 mapping
# ──────────────────────────────────────────────────────────────────────────────

PALOALTO_TRAFFIC = {
    "name": "pan:traffic",
    "description": "Firewall traffic logs (sessions, bytes, packets, actions)",
    "datamodels":  ["Network_Traffic"],
    "eventtypes":  ["pan_traffic"],
    "tags":        ["network", "communicate"],
    "datamodel_conditions": [
        {
            "when":       "always",
            "eventtype":  "pan_traffic",
            "tags":       ["network", "communicate"],
            "datamodels": ["Network_Traffic"],
        },
    ],
    "fields": [
        {
            "raw_field":   "dvc_name",
            "csv_position": 53,
            "cim_field":   "dvc",
            "datamodels":  ["Network_Traffic"],
            "ai_source":   {"type": "entity", "entity_type": "firewall", "entity_field": "nt_host"},
            "direction":   None,
            "description": "Firewall device hostname",
            "mutable":     True,
        },
        {
            "raw_field":   "src_ip",
            "csv_position": 8,
            "cim_field":   "src_ip",
            "datamodels":  ["Network_Traffic"],
            "ai_source": {
                "type": "either",
                "options": [
                    {"type": "entity",       "entity_type": "endpoint", "entity_field": "ip"},
                    {"type": "network_pool", "role": "src_pool"},
                ],
            },
            "direction":   "src",
            "description": "Source IP — internal client when outbound, external host when inbound",
            "mutable":     True,
        },
        {
            "raw_field":   "dest_ip",
            "csv_position": 9,
            "cim_field":   "dest_ip",
            "datamodels":  ["Network_Traffic"],
            "ai_source": {
                "type": "either",
                "options": [
                    {"type": "entity",       "entity_type": "server",   "entity_field": "ip"},
                    {"type": "entity",       "entity_type": "external", "entity_field": "ip"},
                    {"type": "network_pool", "role": "dest_pool"},
                ],
            },
            "direction":   "dest",
            "description": "Destination IP — external host when outbound, internal server when inbound",
            "mutable":     True,
        },
        {
            "raw_field":   "src_user",
            "csv_position": 13,
            "cim_field":   "user",
            "datamodels":  ["Network_Traffic"],
            "ai_source":   {"type": "account", "account_type": "standard", "account_field": "username"},
            "direction":   "src",
            "description": "Source user (User-ID) — typically populated on outbound sessions",
            "mutable":     True,
        },
        {
            "raw_field":   "dest_user",
            "csv_position": 14,
            "cim_field":   "user",
            "datamodels":  ["Network_Traffic"],
            "ai_source":   {"type": "account", "account_type": "standard", "account_field": "username"},
            "direction":   "dest",
            "description": "Destination user (rare in traffic logs)",
            "mutable":     True,
        },
    ],
}


PALOALTO_THREAT = {
    "name": "pan:threat",
    "description": "Threat logs (vulnerabilities, malware, spyware, URLs, files, wildfire)",
    "datamodels":  ["Intrusion_Detection", "Web"],
    "eventtypes":  ["pan_threat"],
    "tags":        ["ids", "attack"],
    "datamodel_conditions": [
        {
            "when":       "log_subtype == 'url'",
            "eventtype":  "pan_url",
            "tags":       ["web"],
            "datamodels": ["Web"],
        },
        {
            "when":       "log_subtype == 'wildfire'",
            "eventtype":  "pan_wildfire",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
        {
            "when":       "log_subtype == 'virus'",
            "eventtype":  "pan_virus",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
        {
            "when":       "log_subtype == 'spyware'",
            "eventtype":  "pan_spyware",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
        {
            "when":       "log_subtype == 'file'",
            "eventtype":  "pan_file",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
        {
            "when":       "log_subtype not in ('url','file','data')",
            "eventtype":  "pan_threat",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
    ],
    "fields": [
        {
            "raw_field":   "dvc_name",
            "csv_position": 60,
            "cim_field":   "dvc",
            "datamodels":  ["Intrusion_Detection", "Web"],
            "ai_source":   {"type": "entity", "entity_type": "firewall", "entity_field": "nt_host"},
            "direction":   None,
            "description": "Firewall device hostname",
            "mutable":     True,
        },
        {
            "raw_field":   "src_ip",
            "csv_position": 8,
            "cim_field":   "src_ip",
            "datamodels":  ["Intrusion_Detection", "Web"],
            "ai_source": {
                "type": "either",
                "options": [
                    {"type": "entity",       "entity_type": "endpoint", "entity_field": "ip"},
                    {"type": "network_pool", "role": "src_pool"},
                ],
            },
            "direction":   "src",
            "description": "Threat source IP — malicious external when inbound, internal user when outbound",
            "mutable":     True,
        },
        {
            "raw_field":   "dest_ip",
            "csv_position": 9,
            "cim_field":   "dest_ip",
            "datamodels":  ["Intrusion_Detection", "Web"],
            "ai_source": {
                "type": "either",
                "options": [
                    {"type": "entity",       "entity_type": "server",   "entity_field": "ip"},
                    {"type": "entity",       "entity_type": "external", "entity_field": "ip"},
                    {"type": "network_pool", "role": "dest_pool"},
                ],
            },
            "direction":   "dest",
            "description": "Threat destination IP — internal target when inbound, malicious site when outbound",
            "mutable":     True,
        },
        {
            "raw_field":   "src_user",
            "csv_position": 13,
            "cim_field":   "user",
            "datamodels":  ["Intrusion_Detection", "Web"],
            "ai_source":   {"type": "account", "account_type": "standard", "account_field": "username"},
            "direction":   "src",
            "description": "Source user — populated on outbound threats (User-ID)",
            "mutable":     True,
        },
    ],
}


PALOALTO_SYSTEM = {
    "name": "pan:system",
    "description": "System events — authentication, configuration, HA, upgrades, GlobalProtect",
    "datamodels":  ["Authentication", "Change"],   # depends on subtype
    "eventtypes":  ["pan_system"],
    "tags":        [],   # depends on subtype
    "datamodel_conditions": [
        {
            "when":       "log_subtype == 'auth' OR description matches /(?i)auth|Failed password/",
            "eventtype":  "pan_system_auth",
            "tags":       ["authentication"],
            "datamodels": ["Authentication"],
        },
        {
            "when":       "log_subtype == 'url-filtering'",
            "eventtype":  "pan_system_alert",
            "tags":       ["change"],
            "datamodels": ["Change"],
        },
        {
            "when":       "description matches /config cleared/",
            "eventtype":  "pan_system_change",
            "tags":       ["change"],
            "datamodels": ["Change"],
        },
        {
            "when":       "default",
            "eventtype":  "pan_system",
            "tags":       [],
            "datamodels": [],   # other subtypes (start/shutdown/HA/upgrade) → no datamodel
        },
    ],
    "fields": [
        {
            "raw_field":   "dvc_name",
            "csv_position": 23,
            "cim_field":   "dvc",
            "datamodels":  ["Authentication", "Change"],
            "ai_source":   {"type": "entity", "entity_type": "firewall", "entity_field": "nt_host"},
            "direction":   None,
            "description": "Firewall device hostname (also used as 'dest' and as 'src' for non-auth events)",
            "mutable":     True,
        },
        {
            "raw_field":   "user",
            "csv_position": None,   # extracted from `description` by transforms (REGEX)
            "cim_field":   "user",
            "datamodels":  ["Authentication"],
            "ai_source":   {"type": "account", "account_type": "admin", "account_field": "username"},
            "direction":   None,
            "description": "Admin / GlobalProtect user — extracted from description on auth events",
            "mutable":     True,
            "extracted_from": "description",
        },
        {
            "raw_field":   "src_auth",
            "csv_position": None,   # extracted from `description` by transforms
            "cim_field":   "src",
            "datamodels":  ["Authentication"],
            "ai_source": {
                "type": "either",
                "options": [
                    {"type": "entity",       "entity_type": "endpoint", "entity_field": "ip"},
                    {"type": "network_pool", "role": "src_pool"},
                ],
            },
            "direction":   "src",
            "description": "Source IP of the auth attempt — extracted from description",
            "mutable":     True,
            "extracted_from": "description",
        },
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
# TA registry
# ──────────────────────────────────────────────────────────────────────────────

# Helper — derive entity/account type lists from a fields[] list
# ──────────────────────────────────────────────────────────────────────────────
# Fortinet FortiGate — full Phase-3 mapping
#
# Everything below is granted by the add-on, never declared by us. The chain is
# always the same: `subtype=` (plus, often, `action`/`status`) selects an
# eventtype in eventtypes.conf, which tags.conf turns into tags, which the CIM
# app turns into a dataset. See references/fortinet-sourcetypes.md §6.
#
# The four `fields[]` tables carry only what A&I can actually supply — the
# firewall's own name, the two ends of the session, and the account. A policy
# id, a signature, a session id are event facts, not environment facts.
# ──────────────────────────────────────────────────────────────────────────────

#: The firewall that wrote the event. `EVAL-devname = coalesce(devname, devid)`
#: then `FIELDALIAS-…_dvc = devname as dvc`, on all four stanzas.
_FGT_DVC = {
    "raw_field":   "devname",
    "cim_field":   "dvc",
    "ai_source":   {"type": "entity", "entity_type": "firewall", "entity_field": "nt_host"},
    "direction":   None,
    "description": "Firewall hostname (props.conf EVAL-devname, then FIELDALIAS dvc)",
    "mutable":     True,
}

#: The account behind the session. `EVAL-user = coalesce(user, unauthuser)` on
#: traffic, `coalesce(app, service)`-style aliases on utm, and
#: `EVAL-user = coalesce(user_name, xauthuser)` on event.
_FGT_USER = {
    "raw_field":   "user",
    "cim_field":   "user",
    "ai_source":   {"type": "account", "account_type": "standard", "account_field": "username"},
    "direction":   "src",
    "description": "Authenticated user carried on the session (props.conf EVAL-user)",
    "mutable":     True,
}


def _fgt_src_ip(cim_field, datamodels, description):
    """srcip, which the add-on aliases to both `src` and `src_ip`."""
    return {
        "raw_field":   "srcip",
        "cim_field":   cim_field,
        "datamodels":  list(datamodels),
        "ai_source": {
            "type": "either",
            "options": [
                {"type": "entity",       "entity_type": "endpoint", "entity_field": "ip"},
                {"type": "network_pool", "role": "src_pool"},
            ],
        },
        "direction":   "src",
        "description": description,
        "mutable":     True,
    }


def _fgt_dest_ip(cim_field, datamodels, description):
    """dstip, aliased to both `dest` and `dest_ip`."""
    return {
        "raw_field":   "dstip",
        "cim_field":   cim_field,
        "datamodels":  list(datamodels),
        "ai_source": {
            "type": "either",
            "options": [
                {"type": "entity",       "entity_type": "server",   "entity_field": "ip"},
                {"type": "entity",       "entity_type": "external", "entity_field": "ip"},
                {"type": "network_pool", "role": "dest_pool"},
            ],
        },
        "direction":   "dest",
        "description": description,
        "mutable":     True,
    }


def _fgt_field(base, cim_field, datamodels):
    """One of the shared fields above, stamped with this sourcetype's datamodels."""
    field = dict(base)
    field["cim_field"] = cim_field
    field["datamodels"] = list(datamodels)
    return field


FORTIGATE_TRAFFIC = {
    "name": "fortigate_traffic",
    "description": "Forwarded sessions through a firewall policy (type=traffic)",
    # Granted, not declared: [ftnt_fortigate_traffic] -> network, communicate
    "datamodels":  ["Network_Traffic"],
    "eventtypes":  ["ftnt_fortigate_traffic"],
    "tags":        ["network", "communicate"],
    "datamodel_conditions": [
        {
            "when":       "always",
            "eventtype":  "ftnt_fortigate_traffic",
            "tags":       ["network", "communicate"],
            "datamodels": ["Network_Traffic"],
        },
    ],
    "fields": [
        _fgt_field(_FGT_DVC, "dvc", ["Network_Traffic"]),
        _fgt_src_ip("src_ip", ["Network_Traffic"],
                    "Session source — the inside client on a forwarded session"),
        _fgt_dest_ip("dest_ip", ["Network_Traffic"],
                     "Session destination — the outside host on a forwarded session"),
        _fgt_field(_FGT_USER, "user", ["Network_Traffic"]),
    ],
}


FORTIGATE_UTM = {
    "name": "fortigate_utm",
    "description": "UTM inspection verdicts — web filter, IPS, antivirus, application control",
    # Granted, not declared. eventtypes.conf keys on subtype, tags.conf grants:
    #   [ftnt_fortigate_webfilter] subtype=webfilter -> web
    #   [ftnt_fortigate_ips]       subtype=ips       -> ids, attack
    #   [ftnt_fortigate_virus]     subtype=virus AND vendor_action!=analytics
    #                                                -> malware, attack, operations
    #   [ftnt_fortigate_appctrl]   subtype=app-ctrl  -> network, communicate
    "datamodels":  ["Web", "Intrusion_Detection", "Malware", "Network_Traffic"],
    "eventtypes":  ["ftnt_fortigate_utm", "ftnt_fortigate_webfilter",
                    "ftnt_fortigate_ips", "ftnt_fortigate_virus",
                    "ftnt_fortigate_appctrl"],
    "tags":        ["web", "ids", "attack", "malware", "operations",
                    "network", "communicate"],
    "datamodel_conditions": [
        {
            "when":       "subtype == 'webfilter'",
            "match":      {"subtype": "webfilter"},
            "eventtype":  "ftnt_fortigate_webfilter",
            "tags":       ["web"],
            "datamodels": ["Web"],
        },
        {
            "when":       "subtype == 'ips'",
            "match":      {"subtype": "ips"},
            "eventtype":  "ftnt_fortigate_ips",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
        {
            # The two virus samples the add-on ships carry action=analytics and
            # are therefore excluded — those are sandbox submissions, not
            # detections. The generator emits the block verdict instead.
            "when":       "subtype == 'virus' and action != 'analytics'",
            "match":      {"subtype": "virus"},
            "eventtype":  "ftnt_fortigate_virus",
            "tags":       ["malware", "attack", "operations"],
            "datamodels": ["Malware"],
        },
        {
            "when":       "subtype == 'app-ctrl'",
            "match":      {"subtype": "app-ctrl"},
            "eventtype":  "ftnt_fortigate_appctrl",
            "tags":       ["network", "communicate"],
            "datamodels": ["Network_Traffic"],
        },
    ],
    "fields": [
        _fgt_field(_FGT_DVC, "dvc", ["Web", "Intrusion_Detection", "Malware",
                                     "Network_Traffic"]),
        _fgt_src_ip("src_ip", ["Web", "Intrusion_Detection", "Malware",
                               "Network_Traffic"],
                    "Client on the inspected session; the attacker on an inbound IPS detection"),
        _fgt_dest_ip("dest_ip", ["Web", "Intrusion_Detection", "Malware",
                                 "Network_Traffic"],
                     "Server on the inspected session; the target on an inbound IPS detection"),
        _fgt_field(_FGT_USER, "user", ["Web", "Malware", "Network_Traffic"]),
    ],
}


FORTIGATE_EVENT = {
    "name": "fortigate_event",
    "description": "Appliance events — user and admin authentication, VPN, configuration, performance",
    # Granted, not declared. Every one of these is `subtype=` plus a condition on
    # `action` (aliased to vendor_action) or `status` (vendor_status):
    #   [ftnt_fortigate_auth]                    user + authentication + success|failure
    #                                              -> authentication, default
    #   [ftnt_fortigate_auth_privileged_login]   system + login
    #                                              -> authentication, privileged
    #   [ftnt_fortigate_auth_privileged_logout]  system + logout   -> change, account
    #   [ftnt_fortigate_vpn_auth]                vpn + negotiate   -> authentication, default
    #   [ftnt_fortigate_vpn_start]               vpn + tunnel-up   -> network, session, vpn, start
    #   [ftnt_fortigate_vpn_end]                 vpn + tunnel-down -> network, session, vpn, end
    #   [ftnt_fortigate_config_change]           system + Add|Edit|delete -> change, network
    #   [ftnt_fortigate_perf_stats]              system + perf-stats
    #                                              -> os, performance, cpu, memory
    "datamodels":  ["Authentication", "Change", "Network_Sessions", "Performance"],
    "eventtypes":  ["ftnt_fortigate_event", "ftnt_fortigate_auth",
                    "ftnt_fortigate_auth_privileged_login",
                    "ftnt_fortigate_auth_privileged_logout",
                    "ftnt_fortigate_vpn_auth", "ftnt_fortigate_vpn_start",
                    "ftnt_fortigate_vpn_end", "ftnt_fortigate_config_change",
                    "ftnt_fortigate_perf_stats"],
    "tags":        ["authentication", "default", "privileged", "change",
                    "account", "network", "session", "vpn", "start", "end",
                    "os", "performance", "cpu", "memory"],
    "datamodel_conditions": [
        {
            # eventtypes.conf:77 requires vendor_status IN(success, failure).
            # The add-on's own sample carries status=logout and matches nothing.
            "when":       "subtype == 'user' and action == 'authentication'",
            "match":      {"subtype": "user"},
            "eventtype":  "ftnt_fortigate_auth",
            "tags":       ["authentication", "default"],
            "datamodels": ["Authentication"],
        },
        {
            "when":       "subtype == 'system' and action == 'login'",
            "match":      {"subtype": "system", "action": "login"},
            "eventtype":  "ftnt_fortigate_auth_privileged_login",
            "tags":       ["authentication", "privileged"],
            "datamodels": ["Authentication"],
        },
        {
            "when":       "subtype == 'system' and action == 'logout'",
            "match":      {"subtype": "system", "action": "logout"},
            "eventtype":  "ftnt_fortigate_auth_privileged_logout",
            "tags":       ["change", "account"],
            "datamodels": ["Change"],
        },
        {
            "when":       "subtype == 'vpn' and action == 'negotiate'",
            "match":      {"subtype": "vpn", "action": "negotiate"},
            "eventtype":  "ftnt_fortigate_vpn_auth",
            "tags":       ["authentication", "default"],
            "datamodels": ["Authentication"],
        },
        {
            "when":       "subtype == 'vpn' and action in ('tunnel-up', 'install_sa', 'ssl-new-con')",
            "match":      {"subtype": "vpn", "action": "tunnel-up"},
            "eventtype":  "ftnt_fortigate_vpn_start",
            "tags":       ["network", "session", "vpn", "start"],
            "datamodels": ["Network_Sessions"],
        },
        {
            "when":       "subtype == 'vpn' and action in ('tunnel-down', 'delete_ipsec_sa')",
            "match":      {"subtype": "vpn", "action": "tunnel-down"},
            "eventtype":  "ftnt_fortigate_vpn_end",
            "tags":       ["network", "session", "vpn", "end"],
            "datamodels": ["Network_Sessions"],
        },
        {
            "when":       "subtype == 'system' and action in ('Add', 'Edit', 'delete')",
            "match":      {"subtype": "system", "action": "Edit"},
            "eventtype":  "ftnt_fortigate_config_change",
            "tags":       ["change", "network"],
            "datamodels": ["Change"],
        },
        {
            "when":       "subtype == 'system' and action == 'perf-stats'",
            "match":      {"subtype": "system", "action": "perf-stats"},
            "eventtype":  "ftnt_fortigate_perf_stats",
            "tags":       ["os", "performance", "cpu", "memory"],
            "datamodels": ["Performance"],
        },
    ],
    "fields": [
        _fgt_field(_FGT_DVC, "dvc", ["Authentication", "Change",
                                     "Network_Sessions", "Performance"]),
        _fgt_src_ip("src", ["Authentication", "Change", "Network_Sessions"],
                    "Where the login or the change came from "
                    "(props.conf EVAL-src coalesces srcip, remip and the address inside ui=)"),
        _fgt_field(_FGT_USER, "user",
                   ["Authentication", "Change", "Network_Sessions"]),
    ],
}


FORTIGATE_ANOMALY = {
    "name": "fortigate_anomaly",
    "description": "DoS policy anomaly detections (type=anomaly)",
    # Granted, not declared: [ftnt_fortigate_anomaly] matches subtype=anomaly
    # under fortigate_anomaly and fortigate_utm alike -> ids, attack.
    "datamodels":  ["Intrusion_Detection"],
    "eventtypes":  ["ftnt_fortigate_anomaly"],
    "tags":        ["ids", "attack"],
    "datamodel_conditions": [
        {
            "when":       "always",
            "eventtype":  "ftnt_fortigate_anomaly",
            "tags":       ["ids", "attack"],
            "datamodels": ["Intrusion_Detection"],
        },
    ],
    "fields": [
        _fgt_field(_FGT_DVC, "dvc", ["Intrusion_Detection"]),
        _fgt_src_ip("src", ["Intrusion_Detection"],
                    "Source of the flood — outside the estate, since a DoS policy "
                    "sits on the outside interface"),
        _fgt_dest_ip("dest", ["Intrusion_Detection"],
                     "The address being flooded"),
    ],
}

def _derive_types(fields, key, type_key):
    """Walk fields[] and collect every {key}_type seen in ai_source (entity|account)."""
    types = set()
    for f in fields:
        src = f.get("ai_source") or {}
        opts = src.get("options") if src.get("type") == "either" else [src]
        for opt in opts:
            if (opt or {}).get("type") == key:
                t = opt.get(type_key)
                if t:
                    types.add(t)
    return sorted(types)


def _enrich_sourcetype(st):
    """Auto-derive entity_types/account_types from fields[] for backward compat."""
    fields = st.get("fields", [])
    if "entity_types" not in st:
        st["entity_types"] = _derive_types(fields, "entity", "entity_type")
    if "account_types" not in st:
        st["account_types"] = _derive_types(fields, "account", "account_type")
    return st


TA_REGISTRY = {
    "paloalto": {
        "name": "Splunk Add-on for Palo Alto Networks",
        "splunkbase_url": "https://splunkbase.splunk.com/app/7523",
        "add_on_package": "Splunk_TA_paloalto_networks",
        "add_on_version": "4.0.0",
        "sc4s_url": "https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/PaloaltoNetworks/panos/",
        "display_name": "Palo Alto",
        "vendor": "Palo Alto Networks",
        "description": "Logs from Palo Alto Networks firewalls (NGFW, Panorama)",
        # Sourcetype to send on the wire by default. The TA ships [pan:log] with
        # TRANSFORMS-sourcetype = pan_threat, pan_traffic, pan_system, ... which
        # rewrite MetaData:Sourcetype at index time from the 4th CSV field, so a
        # single ingestion sourcetype fans out into pan:traffic / pan:threat /
        # pan:system on the Splunk side.
        "hec_default_sourcetype": "pan:log",
        "sourcetypes": [
            _enrich_sourcetype(deepcopy(PALOALTO_TRAFFIC)),
            _enrich_sourcetype(deepcopy(PALOALTO_THREAT)),
            _enrich_sourcetype(deepcopy(PALOALTO_SYSTEM)),
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Vendors below keep the legacy lightweight schema until their Phase-3 pass.
    # `fields: []` means "no per-field A&I mapping yet" — generators fall back
    # to the old environment_manager behaviour (ENTITY_TYPE_ROLES).
    # ──────────────────────────────────────────────────────────────────────
    "windows": {
        "name": "Splunk Add-on for Microsoft Windows",
        "splunkbase_url": "https://splunkbase.splunk.com/app/742",
        "add_on_package": "Splunk_TA_windows",
        "add_on_version": "11.0.2",
        "display_name": "Windows",
        "vendor": "Microsoft",
        "description": "Windows Event Logs from hosts and domain controllers",
        # The TA normalises every WinEventLog channel to a generic sourcetype and
        # carries the channel in `source` instead:
        #   "All WinEventLogs are now assigned to either the WinEventLog or the
        #    XmlWinEventLog sourcetype and are distinguished by their source."
        # See references/windows-sourcetypes.md.
        #
        # Which of the two generic sourcetypes applies is decided by the body we
        # emit, i.e. by the sender's render_format. The TA derives `source` the
        # same way, from the body, in transforms.conf:
        #   classic -> [ta-windows-fix-classic-source] -> source::WinEventLog:$1
        #   xml     -> [ta-windows-fix-xml-source]     -> source::XmlWinEventLog:$1
        # So both metadata follow render_format together and never mix forms.
        "hec_default_sourcetype_by_render_format": {
            "xml":     "XmlWinEventLog",
            "classic": "WinEventLog",
        },
        # Windows Event Log has no documented syslog ingestion path in the TA.
        "syslog_viable": False,
        "sourcetypes": [
            {
                "name": "WinEventLog:Security",
                "hec_source_by_render_format": {
                    "xml":     "XmlWinEventLog:Security",
                    "classic": "WinEventLog:Security",
                },
                "datamodels": ["Authentication", "Change", "Endpoint"],
                "eventtypes": ["windows_logon", "windows_privilege_escalation"],
                "tags": ["windows", "endpoint", "authentication", "host"],
                "description": "Windows Security event log (logon, privilege escalation, account changes)",
                "entity_types": ["endpoint", "domain_controller", "server"],
                "account_types": ["standard", "admin", "service_account"],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dvc",
                        "datamodels": ["Authentication", "Change", "Endpoint"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Host that logged the event (<System><Computer>) — on every event",
                        "mutable": True,
                    },
                    {
                        "raw_field": "SubjectUserName",
                        "cim_field": "src_user",
                        "datamodels": ["Authentication", "Change"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "src",
                        "description": "Account that initiated the action — TA maps it to Caller_User_Name",
                        "mutable": True,
                    },
                    {
                        "raw_field": "TargetUserName",
                        "cim_field": "user",
                        "datamodels": ["Authentication", "Change"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "dest",
                        "description": "Account the action targets — TA maps it to Target_User_Name",
                        "mutable": True,
                    },
                    {
                        "raw_field": "WorkstationName",
                        "cim_field": "src",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": "src",
                        "description": "Workstation the logon came from (4624/4625) — TA maps it to Source_Workstation",
                        "mutable": True,
                    },
                    {
                        "raw_field": "IpAddress",
                        "cim_field": "src_ip",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "ip"},
                        "direction": "src",
                        "description": "Source address of the logon (4624/4625) — TA folds it into Source_Workstation",
                        "mutable": True,
                    },
                ],
            },
            {
                "name": "WinEventLog:System",
                "hec_source_by_render_format": {
                    "xml":     "XmlWinEventLog:System",
                    "classic": "WinEventLog:System",
                },
                "datamodels": ["Change", "Endpoint"],
                "eventtypes": ["windows_system"],
                "tags": ["windows", "endpoint", "system"],
                "description": "Windows System event log",
                "entity_types": ["endpoint", "domain_controller", "server"],
                "account_types": ["service_account"],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dvc",
                        "datamodels": ["Change", "Endpoint"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Host that logged the event — the only A&I-driven field on this channel",
                        "mutable": True,
                    },
                ],
            },
            {
                "name": "WinEventLog:Application",
                "hec_source_by_render_format": {
                    "xml":     "XmlWinEventLog:Application",
                    "classic": "WinEventLog:Application",
                },
                "datamodels": ["Application_State", "Updates"],
                "eventtypes": ["windows_application"],
                "tags": ["windows", "endpoint", "application"],
                "description": "Windows Application event log (app errors, installs, updates — MsiInstaller, .NET, etc.)",
                "entity_types": ["endpoint", "server"],
                "account_types": ["service_account"],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dvc",
                        "datamodels": ["Application_State", "Updates"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Host that logged the event — the only A&I-driven field on this channel",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "ssh": {
        # Shipping this source over syslog means adding RFC 3164 framing:
        # sshd already writes the BSD header;
        # only the priority is missing.
        # Absent from a TA means it already frames itself (Palo Alto, Cisco
        # ASA/FTD/XR) or is not collected over syslog at all.
        "syslog_framing": {
            "facility": "authpriv",
            "severity": "info",
            "tag": "sshd",
        },
        "name": "Splunk Add-on for Unix and Linux",
        "splunkbase_url": "https://splunkbase.splunk.com/app/833",
        "add_on_package": "Splunk_TA_nix",
        "add_on_version": "10.3.4",
        "display_name": "SSH (Linux)",
        "vendor": "OpenSSH / Linux",
        "description": "SSH authentication logs from Linux/Unix servers (/var/log/secure)",
        # sshd writes to /var/log/secure (RHEL) or /var/log/auth.log (Debian),
        # which [monitor:///var/log] picks up with no sourcetype of its own —
        # splunkd classifies it as linux_secure. That name matters: the TA runs
        # two parallel paths and only linux_secure gets the modern one.
        #   linux_secure  -> [sshd_session_start] / [sshd_session_end]
        #                    plus the sshd-session-* extractions
        #   anything else -> [ssh_open] / [failed_login], which are keyed on
        #                    fragile `punct=` values and explicitly exclude
        #                    linux_secure
        "sourcetypes": [
            {
                "name": "linux_secure",
                # A file monitor, not a scripted input: [monitor:///var/log]
                # (inputs.conf:177) whitelists `secure` and sets no source, so
                # splunkd fills in the path. Nothing in the TA classifies on it —
                # unlike auditd, where [auditd_modify] keys on source=auditd — so
                # this is faithful metadata rather than a behavioural switch.
                #
                # RHEL writes /var/log/secure, Debian /var/log/auth.log. A lab is
                # one or the other, so a single default beats a random mix; the
                # per-sourcetype Source row in the sender form overrides it.
                "hec_source": "/var/log/secure",
                # Granted, not declared. eventtypes.conf + tags.conf:
                #   [sshd_authentication] -> authentication, remote
                #   [sshd_session_start]  -> network, session, start
                #   [sshd_session_end]    -> network, session, end
                "datamodels": ["Authentication", "Network_Sessions"],
                "eventtypes": ["sshd_authentication", "sshd_session_start",
                               "sshd_session_end"],
                "tags": ["authentication", "remote", "network", "session",
                         "start", "end"],
                "description": "sshd authentication and session events (/var/log/secure)",
                "entity_types": ["endpoint", "server"],
                "account_types": ["standard", "admin", "service_account"],
                "datamodel_conditions": [
                    {
                        "when": "the line carries an sshd auth verdict",
                        "eventtype": "sshd_authentication",
                        "tags": ["authentication", "remote"],
                        "datamodels": ["Authentication"],
                    },
                    {
                        "when": "the line opens a session (Accepted/Failed password, "
                                "invalid user, negotiation or banner failure)",
                        "eventtype": "sshd_session_start",
                        "tags": ["network", "session", "start"],
                        "datamodels": ["Network_Sessions"],
                    },
                    {
                        "when": "the line closes a session (disconnect, timeout, "
                                "session closed) and is not an invalid user",
                        "eventtype": "sshd_session_end",
                        "tags": ["network", "session", "end"],
                        "datamodels": ["Network_Sessions"],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "hostname",
                        "cim_field": "dest",
                        "datamodels": ["Authentication", "Network_Sessions"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "server",
                             "entity_field": "nt_host"},
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "nt_host"}]},
                        "direction": "dest",
                        "description": "Host that logged the line (syslog header) — "
                                       "REPORT-dest_for_linux_secure, then FIELDALIAS-dvc",
                        "mutable": True,
                    },
                    {
                        "raw_field": "user",
                        "cim_field": "user",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "dest",
                        "description": "Account being authenticated — extracted by the "
                                       "sshd-session-* and ssh-login-* transforms",
                        "mutable": True,
                    },
                    {
                        "raw_field": "src_ip",
                        "cim_field": "src",
                        "datamodels": ["Authentication", "Network_Sessions"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Address the connection came from — "
                                       "REPORT-src_for_linux_secure folds src_ip into src",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "active_directory": {
        # The add-on, not the source: these are Security events off a domain
        # controller, and Splunk_TA_windows is what parses them. `display_name`
        # is what names the source in the UI.
        "name": "Splunk Add-on for Microsoft Windows",
        "splunkbase_url": "https://splunkbase.splunk.com/app/742",
        "add_on_package": "Splunk_TA_windows",
        "add_on_version": "11.0.2",
        "display_name": "Active Directory",
        "vendor": "Microsoft",
        "description": "Active Directory event logs from domain controllers",
        # Same wire contract as the Windows TA: the generator emits XML on the
        # Security channel for all five categories (4720/4728/4662/4768/4741...).
        # It has no render_format option — always XML — so unlike `windows` these
        # two values are fixed rather than keyed on the format.
        "hec_default_sourcetype": "XmlWinEventLog",
        "syslog_viable": False,
        "sourcetypes": [
            {
                "name": "WinEventLog:Security",
                "hec_source": "XmlWinEventLog:Security",
                "datamodels": ["Authentication", "Change"],
                "eventtypes": ["ad_user_created", "ad_group_membership"],
                "tags": ["active_directory", "authentication", "change"],
                "description": "AD security logs (user creation, group membership, logons)",
                "entity_types": ["domain_controller"],
                "account_types": ["standard", "admin", "service_account"],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dvc",
                        "datamodels": ["Authentication", "Change", "Endpoint"],
                        "ai_source": {"type": "entity", "entity_type": "domain_controller",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Domain controller that logged the event",
                        "mutable": True,
                    },
                    {
                        "raw_field": "SubjectUserName",
                        "cim_field": "src_user",
                        "datamodels": ["Authentication", "Change"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "src",
                        "description": "Account that initiated the action — TA maps it to Caller_User_Name",
                        "mutable": True,
                    },
                    {
                        "raw_field": "TargetUserName",
                        "cim_field": "user",
                        "datamodels": ["Authentication", "Change"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "dest",
                        "description": "Account the action targets — TA maps it to Target_User_Name",
                        "mutable": True,
                    },
                    {
                        "raw_field": "WorkstationName",
                        "cim_field": "src",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": "src",
                        "description": "Workstation the logon came from (4624/4625) — TA maps it to Source_Workstation",
                        "mutable": True,
                    },
                    {
                        "raw_field": "IpAddress",
                        "cim_field": "src_ip",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "ip"},
                        "direction": "src",
                        "description": "Source address of the logon (4624/4625) — TA folds it into Source_Workstation",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "auditd": {
        # Shipping this source over syslog means adding RFC 3164 framing:
        # audisp-syslog is what forwards audit
        # records to syslog, and audispd is the program name SC4S keys on.
        # Absent from a TA means it already frames itself (Palo Alto, Cisco
        # ASA/FTD/XR) or is not collected over syslog at all.
        "syslog_framing": {
            "facility": "authpriv",
            "severity": "notice",
            "tag": "audispd",
        },
        "name": "Splunk Add-on for Unix and Linux",
        "splunkbase_url": "https://splunkbase.splunk.com/app/833",
        "add_on_package": "Splunk_TA_nix",
        "add_on_version": "10.3.4",
        "display_name": "Linux auditd",
        "vendor": "Linux audit daemon",
        "description": "Linux audit records — authentication, account management, "
                       "sudo, execution and watched file access",
        # `auditd` is the supported sourcetype in TA 10.3.4: it is what the
        # add-on's own [script://./bin/rlog.sh] input produces, and the only one
        # with eventtypes and tags. `linux_audit`, which looks better furnished,
        # sits inside props.conf's BEGIN/END "SCRIPTED INPUT CONTENT IMPORTED
        # FROM TA-deployment-apps" block — kept only so data from a withdrawn
        # add-on still parses. See references/auditd-sourcetypes.md.
        #
        # `source` is not decoration here: [auditd_modify] keys on
        # `source=auditd PATH`, not on the sourcetype, so without it the `modify`
        # tag never appears.
        "sourcetypes": [
            {
                "name": "auditd",
                "hec_source": "auditd",
                # Granted, not declared. eventtypes.conf + tags.conf:
                #   [auditd]        -> os, unix, resource, file
                #   [auditd_modify] -> modify   (needs source=auditd and a PATH record)
                # Which CIM dataset that combination feeds is undetermined from
                # the add-on alone; the Change datamodel needs `change`, which
                # only a local eventtype adds. Recorded as the add-on grants it,
                # not as we would like it.
                "datamodels": [],
                "eventtypes": ["auditd", "auditd_modify"],
                "tags": ["os", "unix", "resource", "file", "modify"],
                "description": "Linux audit records in ausearch -i form (/var/log/audit)",
                "entity_types": ["server", "endpoint"],
                "account_types": ["standard", "admin", "service_account"],
                "datamodel_conditions": [
                    {
                        "when": "always",
                        "eventtype": "auditd",
                        "tags": ["os", "unix", "resource", "file"],
                        "datamodels": [],
                    },
                    {
                        "when": "a PATH record, and source=auditd is on the wire",
                        "eventtype": "auditd_modify",
                        "tags": ["modify"],
                        "datamodels": [],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "hostname",
                        "cim_field": "dest",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "server",
                             "entity_field": "nt_host"},
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "nt_host"}]},
                        "direction": "dest",
                        "description": "Host the record came from — aliased to dest/dvc "
                                       "only once the local props are in place",
                        "mutable": True,
                    },
                    {
                        "raw_field": "acct",
                        "cim_field": "user",
                        "datamodels": [],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": "dest",
                        "description": "Account the record is about (USER_AUTH acct=, "
                                       "account management id=)",
                        "mutable": True,
                    },
                    {
                        "raw_field": "addr",
                        "cim_field": "src",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Address the session originated from, when the "
                                       "record carries one",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "apache": {
        "name": "Splunk Add-on for Apache Web Server",
        "splunkbase_url": "https://splunkbase.splunk.com/app/3186",
        "add_on_package": "Splunk_TA_apache",
        "add_on_version": "3.0.0",
        "display_name": "Apache",
        "vendor": "Apache",
        "description": "Apache HTTP Server access and error logs",
        # The add-on knows five access shapes, and only three reach the Web
        # datamodel: [access_log_event] lists apache:access, :kv and :json —
        # :combined is deliberately not in it. Two index-time transforms reroute
        # apache:access to :kv or :json on the body's first bytes (`^time=` and
        # `^{"time":"`), the same pattern as pan:log.
        #
        # We emit the final names rather than relying on that reroute: whether
        # index-time transforms run over /services/collector/event is
        # undetermined, and [access_log_event] accepts the final name anyway.
        "syslog_framing": {
            "facility": "local0",
            "severity": "info",
            "tag": "httpd",
        },
        "sourcetypes": [
            {
                "name": "apache:access:kv",
                # Granted, not declared: [access_log_event] -> web
                "datamodels": ["Web"],
                "eventtypes": ["access_log_event"],
                "tags": ["web"],
                "description": "Access log in the key-value LogFormat — full CIM mapping",
                "entity_types": ["endpoint", "server"],
                "account_types": [],
                "datamodel_conditions": [
                    {
                        "when": "always",
                        "eventtype": "access_log_event",
                        "tags": ["web"],
                        "datamodels": ["Web"],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "client",
                        "cim_field": "src",
                        "datamodels": ["Web"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Requesting client — FIELDALIAS-src = client as src",
                        "mutable": True,
                    },
                    {
                        "raw_field": "server",
                        "cim_field": "dest",
                        "datamodels": ["Web"],
                        "ai_source": {"type": "entity", "entity_type": "server",
                                      "entity_field": "nt_host"},
                        "direction": "dest",
                        "description": "Server that answered — FIELDALIAS-dest = server as dest",
                        "mutable": True,
                    },
                ],
            },
            {
                "name": "apache:access:combined",
                # Extracted in full by EXTRACT-apache_access_combined, and then
                # tagged by nothing: [access_log_event] lists apache:access,
                # :kv and :json, not :combined. So the fields populate and no
                # datamodel is reached. Recorded as the add-on leaves it.
                "datamodels": [],
                "eventtypes": [],
                "tags": [],
                "description": "Combined Log Format — parsed, but reaches no datamodel",
                "entity_types": ["endpoint"],
                "account_types": [],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "client",
                        "cim_field": "src",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Requesting client, first field of the combined format",
                        "mutable": True,
                    },
                ],
            },
            {
                "name": "apache:error",
                # [error_log_event] -> `error`, which is not a CIM datamodel tag:
                # Web needs `web`. The fields extract; nothing accelerates.
                "datamodels": [],
                "eventtypes": ["error_log_event"],
                "tags": ["error"],
                "description": "Apache error log — extracted, no CIM datamodel",
                "entity_types": ["endpoint"],
                "account_types": [],
                "datamodel_conditions": [
                    {
                        "when": "always",
                        "eventtype": "error_log_event",
                        "tags": ["error"],
                        "datamodels": [],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "client",
                        "cim_field": "src",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Client in the [client x.x.x.x:port] prefix",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "cisco_asa": {
        "name": "Splunk Add-on for Cisco ASA",
        "splunkbase_url": "https://splunkbase.splunk.com/app/1620",
        "add_on_package": "Splunk_TA_cisco-asa",
        "add_on_version": "6.1.2",
        "sc4s_url": "https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/cisco_asa/",
        "display_name": "Cisco ASA",
        "vendor": "Cisco",
        "description": "Cisco ASA firewall syslog — connections, AAA, VPN, ACL, intrusion",
        # The add-on extracts per message id: ~182 transforms covering 230 ids.
        # An id outside that set yields no field, and an id outside an
        # eventtype's list reaches no datamodel however well it parses — the
        # message id drives the repertoire, not the other way round.
        "sourcetypes": [
            {
                "name": "cisco:asa",
                # Granted, not declared. Every eventtype keys on
                # sourcetype="cisco:asa" AND a message_id set.
                "datamodels": ["Network_Traffic", "Authentication",
                               "Intrusion_Detection", "Network_Sessions", "Change"],
                "eventtypes": ["cisco_connection", "cisco_authentication",
                               "cisco_intrusion", "cisco_vpn_start", "cisco_vpn_end",
                               "cisco_asa_network_sessions", "cisco_asa_audit_change"],
                # No start/end: those come from cisco_network_session_start/_end,
                # whose message ids (302022+) this generator does not emit.
                "tags": ["communicate", "network", "authentication", "attack",
                         "ids", "session", "vpn", "change"],
                "description": "ASA syslog (%ASA-<sev>-<message_id>)",
                "entity_types": ["endpoint", "server", "external", "firewall"],
                "account_types": ["standard", "admin"],
                "datamodel_conditions": [
                    {
                        "when": "message_id in the connection set (302013/302014/...)",
                        "eventtype": "cisco_connection",
                        "tags": ["communicate", "network"],
                        "datamodels": ["Network_Traffic"],
                    },
                    {
                        "when": "message_id in the AAA set (605004/605005/113004/...)",
                        "eventtype": "cisco_authentication",
                        "tags": ["authentication"],
                        "datamodels": ["Authentication"],
                    },
                    {
                        "when": "message_id in the intrusion set (106016/106017/400032/430001)",
                        "eventtype": "cisco_intrusion",
                        "tags": ["attack", "ids"],
                        "datamodels": ["Intrusion_Detection"],
                    },
                    {
                        "when": "message_id opens or closes a VPN session (716001/716002/...)",
                        "eventtype": "cisco_vpn_start / cisco_vpn_end",
                        "tags": ["network", "session", "vpn"],
                        "datamodels": ["Network_Sessions"],
                    },
                    {
                        "when": "message_id records a configuration change (111009/771002/...)",
                        "eventtype": "cisco_asa_audit_change",
                        "tags": ["change"],
                        "datamodels": ["Change"],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "src_ip",
                        "cim_field": "src_ip",
                        "datamodels": ["Network_Traffic"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Session source — extracted per message id",
                        "mutable": True,
                    },
                    {
                        "raw_field": "dest_ip",
                        "cim_field": "dest_ip",
                        "datamodels": ["Network_Traffic"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "server",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "dest_pool"}]},
                        "direction": "dest",
                        "description": "Session destination — extracted per message id",
                        "mutable": True,
                    },
                    {
                        "raw_field": "user",
                        "cim_field": "user",
                        "datamodels": ["Authentication"],
                        "ai_source": {"type": "account", "account_type": "admin",
                                      "account_field": "username"},
                        "direction": "src",
                        "description": "Account in AAA and VPN messages",
                        "mutable": True,
                    },
                    {
                        "raw_field": "host",
                        "cim_field": "dvc",
                        "datamodels": ["Network_Traffic", "Authentication"],
                        "ai_source": {"type": "entity", "entity_type": "firewall",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Appliance that logged the message — FIELDALIAS-dvc = host as dvc",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "cisco_ios": {
        # An IOS device writes no RFC 3164 header. It sends the priority and then
        # the body it prints to the console — `seq: timestamp: %FAC-SEV-MNEM: msg`
        # — and SC4S has a parser for exactly that shape
        # (app-almost-syslog-cisco_syslog), which splits the leftover header off
        # at the first `: %` and digs the hostname out of it.
        #
        # The priority is the part that is not optional. SC4S's source only
        # offers a message to those parsers when it matches `^\<\d+\>`; without
        # one it falls through to the short `app-raw-*` list, which has no IOS
        # entry. Observed directly: our unframed lines land in `sc4s:fallback`
        # carrying `PRI=13`, which is the user.notice syslog-ng assigns when a
        # message arrives with no priority at all.
        #
        # The hostname has to travel inside the message because there is no
        # header to carry it — `logging origin-id hostname` on the device, which
        # is what SC4S's setup requirements mean by "Hostname as device-id".
        # SC4S's host regex refuses a run of four or more digits, so the sequence
        # number cannot stand in for it.
        #
        # Facility local7 is the IOS default; the severity is the digit in
        # %FACILITY-SEVERITY-MNEMONIC, which is where IOS takes its own PRI from.
        "syslog_framing": {
            "facility": "local7",
            "severity": "notice",
            "header": "origin-id",
            "severity_pattern": r"%[A-Z0-9_]+-(\d)-",
        },
        # And there is no second way off the device. ssh, auditd and apache write
        # a file a universal forwarder could tail, so `delivery_format` is a real
        # choice there; a router writes to its console, its buffer and syslog.
        # Framing on the syslog sink is not an option to turn on, it is the only
        # thing the sink can mean — and leaving it behind a checkbox is how these
        # events spent a day arriving without a priority.
        "forwarder_viable": False,
        "name": "Cisco Enterprise Networking Add-on for Splunk",
        "splunkbase_url": "https://splunkbase.splunk.com/app/7538",
        "add_on_package": "TA_cisco_catalyst",
        "add_on_version": "4.0.35",
        "sc4s_url": "https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/cisco_ios/",
        "display_name": "Cisco IOS / IOS-XE",
        "vendor": "Cisco",
        "description": "Cisco IOS and IOS-XE switch and router syslog",
        # The add-on parses this sourcetype in full — extract_cisco_ios-general
        # yields facility, mnemonic, severity_id, event_id, device_time and
        # message_text on every line, and four lookups enrich them — but its
        # eventtype grants `cisco network ios`, which is not a CIM combination.
        #
        # So these events parse and reach no datamodel. That is the add-on's
        # design, not a gap on our side: plenty of operational syslog has no CIM
        # dataset to belong to. Recorded as it is rather than dressed up.
        #
        # The same stanza also covers IOS-XE, XR and ACI, via sibling extractions
        # in the same REPORT list — which is why there is no separate cisco_xr.
        "sourcetypes": [
            {
                "name": "cisco:ios",
                "datamodels": [],
                "eventtypes": ["cisco_ios"],
                "tags": ["cisco", "network", "ios"],
                "description": "IOS / IOS-XE syslog (%FACILITY-SEVERITY-MNEMONIC)",
                "entity_types": ["endpoint", "router"],
                "account_types": ["admin"],
                "datamodel_conditions": [
                    {
                        "when": "always",
                        "eventtype": "cisco_ios",
                        "tags": ["cisco", "network", "ios"],
                        "datamodels": [],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "host",
                        "cim_field": "dvc",
                        "datamodels": [],
                        "ai_source": {"type": "entity", "entity_type": "router",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Device that emitted the message",
                        "mutable": True,
                    },
                    {
                        "raw_field": "src_ip",
                        "cim_field": "src_ip",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Address in the messages that carry one "
                                       "(SEC-6-IPACCESSLOG, SEC_LOGIN, SNMP-3-AUTHFAIL)",
                        "mutable": True,
                    },
                    {
                        "raw_field": "src_mac",
                        "cim_field": "src_mac",
                        "datamodels": [],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "mac"},
                        "direction": "src",
                        "description": "Client MAC in AUTHMGR / dot1x messages",
                        "mutable": True,
                    },
                    {
                        "raw_field": "user",
                        "cim_field": "user",
                        "datamodels": [],
                        "ai_source": {"type": "account", "account_type": "admin",
                                      "account_field": "username"},
                        "direction": "src",
                        "description": "Administrator in AAA and SEC_LOGIN messages",
                        "mutable": True,
                    },
                ],
            },
        ],
    },
    "zscaler": {
        "name": "Zscaler Technical Add-On for Splunk (CIM)",
        "splunkbase_url": "https://splunkbase.splunk.com/app/3865",
        "add_on_package": "TA-Zscaler_CIM",
        "add_on_version": "4.1.5",
        "sc4s_url": "https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Zscaler/nss/",
        "display_name": "Zscaler",
        "vendor": "Zscaler",
        "description": "Zscaler Internet Access — NSS web proxy transactions and tunnel sessions",
        # The add-on declares eleven sourcetypes, none of them `zscaler`. NSS
        # feeds land on zscalernss-<feed>, and the two we generate are the web
        # proxy and the tunnel. Same class of mistake as ssh's `syslog`: a name
        # that looks right and matches no stanza.
        "syslog_framing": {
            "facility": "local0",
            "severity": "info",
            "tag": "zscaler",
        },
        "sourcetypes": [
            {
                "name": "zscalernss-web",
                # Granted, not declared. eventtypes.conf + tags.conf:
                #   [Zscaler_Proxy_General] -> communicate, end, network, proxy,
                #                              session, start, web
                #   [Zscaler_Proxy_DLP]     -> dlp, incident   (ruletype="DLP")
                #   [Zscaler_Proxy_Malware] -> attack, ids, malware
                #                              (threatname!="None")
                "datamodels": ["Web", "Network_Traffic", "Network_Sessions",
                               "Data_Loss_Prevention", "Intrusion_Detection", "Malware"],
                "eventtypes": ["Zscaler_Proxy_General", "Zscaler_Proxy_DLP",
                               "Zscaler_Proxy_Malware"],
                "tags": ["communicate", "end", "network", "proxy", "session",
                         "start", "web", "dlp", "incident", "attack", "ids",
                         "malware"],
                "description": "NSS web proxy transactions (URL, threat, DLP, user)",
                "entity_types": ["endpoint"],
                "account_types": ["standard", "admin"],
                "datamodel_conditions": [
                    {
                        "when": "always",
                        "eventtype": "Zscaler_Proxy_General",
                        "tags": ["communicate", "network", "proxy", "session",
                                 "start", "end", "web"],
                        "datamodels": ["Web", "Network_Traffic", "Network_Sessions"],
                    },
                    {
                        "when": "ruletype == 'DLP' — a DLP engine matched",
                        "eventtype": "Zscaler_Proxy_DLP",
                        "tags": ["dlp", "incident"],
                        "datamodels": ["Data_Loss_Prevention"],
                    },
                    {
                        "when": "threatname != 'None' — a threat was named",
                        "eventtype": "Zscaler_Proxy_Malware",
                        "tags": ["attack", "ids", "malware"],
                        "datamodels": ["Intrusion_Detection", "Malware"],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "ClientIP",
                        "cim_field": "src_ip",
                        "datamodels": ["Web", "Network_Traffic"],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Client address — FIELDALIAS ClientIP AS src, src_ip",
                        "mutable": True,
                    },
                    {
                        "raw_field": "devicename",
                        "cim_field": "src_nt_host",
                        "datamodels": ["Web"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": "src",
                        "description": "Device the transaction came from",
                        "mutable": True,
                    },
                    {
                        "raw_field": "deviceostype",
                        "cim_field": "os",
                        "datamodels": ["Web"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "os"},
                        "direction": "src",
                        "description": "OS of that same device — kept with it, not drawn apart",
                        "mutable": True,
                    },
                    {
                        "raw_field": "user",
                        "cim_field": "src_user",
                        "datamodels": ["Web", "Data_Loss_Prevention"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "email"},
                        "direction": "src",
                        "description": "User identity — Zscaler names users by email, "
                                       "so an account without one contributes nothing",
                        "mutable": True,
                    },
                ],
            },
            {
                "name": "zscalernss-tunnel",
                # No eventtype anywhere in the add-on matches this sourcetype, so
                # it receives no tag and reaches no datamodel. Recorded as the
                # add-on leaves it rather than as we would like it.
                "datamodels": [],
                "eventtypes": [],
                "tags": [],
                "description": "IPSec/GRE tunnel session records",
                "entity_types": ["endpoint"],
                "account_types": ["standard"],
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "sourceip",
                        "cim_field": "src_ip",
                        "datamodels": [],
                        "ai_source": {"type": "either", "options": [
                            {"type": "entity", "entity_type": "endpoint",
                             "entity_field": "ip"},
                            {"type": "network_pool", "role": "src_pool"}]},
                        "direction": "src",
                        "description": "Tunnel source address",
                        "mutable": True,
                    },
                    {
                        "raw_field": "user",
                        "cim_field": "user",
                        "datamodels": [],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "email"},
                        "direction": "src",
                        "description": "Tunnel user identity (email)",
                        "mutable": True,
                    },
                ],
            },
        ],
    },

    "fortigate": {
        "name": "Fortinet FortiGate Add-On for Splunk",
        "splunkbase_url": "https://splunkbase.splunk.com/app/2846",
        "add_on_package": "Splunk_TA_fortinet_fortigate",
        "add_on_version": "1.6.10",
        "sc4s_url": "https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Fortinet/fortios/",
        "display_name": "Fortinet FortiGate",
        "vendor": "Fortinet",
        "description": "FortiOS key=value logs — traffic, UTM, appliance events and DoS anomalies",
        # No hec_default_sourcetype: the add-on does ship an umbrella
        # ([fortigate_log] fans out on `type=` at index time, transforms.conf:2),
        # but we know the category from the sender, so each event carries its own
        # sourcetype the way SC4S sets it.
        #
        # In TA 1.6 the canonical stanzas are `fortigate_*`; the `fgt_*` names the
        # README and the SC4S table still quote are empty stanzas that
        # `rename` into them (props.conf:65-66, 122-123, 169-170, 230-231). Both
        # spellings are covered by every eventtype, so both work — this is the one
        # a 1.6 deployment is configured for, and matches
        # SC4S_OPTION_FORTINET_SOURCETYPE_PREFIX=fortigate.
        #
        # No hec_source: nothing in the add-on classifies on `source` — zero
        # occurrences in eventtypes.conf, no [source::...] stanza in props.conf.
        #
        # FortiOS sends the priority and then its own payload, with no RFC 3164
        # timestamp or hostname in between: every stanza sets TIME_PREFIX = ^, so
        # a header would be read as the event's timestamp instead of its `date=`.
        # The severity follows the event's own `level=`, whose vocabulary is
        # lookups/ftnt_severity_info.csv.
        # See references/fortinet-sourcetypes.md §4.
        "syslog_framing": {
            "facility": "local7",
            "severity": "notice",
            "header": "none",
            "severity_field": "level",
        },
        "sourcetypes": [
            _enrich_sourcetype(deepcopy(FORTIGATE_TRAFFIC)),
            _enrich_sourcetype(deepcopy(FORTIGATE_UTM)),
            _enrich_sourcetype(deepcopy(FORTIGATE_EVENT)),
            _enrich_sourcetype(deepcopy(FORTIGATE_ANOMALY)),
        ],
    },
    "sysmon": {
        # Sysmon publishes one channel and says what an event means with its
        # EventID. The add-on follows that: seven eventtypes split the ~29 IDs
        # into groups, each granting different tags and so a different
        # datamodel. This entry describes the five the generator emits. The two
        # left — WMI (19, 20, 21) and service state (4, 16, 255) — carry two
        # published detections between them and none respectively, so they are
        # not worth the events; declaring them would claim datamodels no sender
        # here reaches.
        #
        # The wire metadata is the part to get right. inputs.conf sets no
        # sourcetype — with renderXml = 1 splunkd settles on XmlWinEventLog —
        # and everything that matters keys on the *source*: all 62 EVALs live in
        # a [source::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational] stanza
        # and all seven eventtypes match on source=. The sourcetype stanza is
        # only `rename = XmlWinEventLog`, so field extraction itself is done by
        # Splunk_TA_windows' generic XML handling, the same path the 4688
        # attacks already use.
        "name": "Splunk Add-on for Sysmon",
        "splunkbase_url": "https://splunkbase.splunk.com/app/5709",
        "add_on_package": "Splunk_TA_microsoft_sysmon",
        "add_on_version": "5.0.1",
        "display_name": "Sysmon",
        "vendor": "Microsoft",
        "description": "Sysinternals Sysmon — registry activity from Windows endpoints",
        # Windows event logs do not travel as syslog, and this add-on ships no
        # non-XML stanza at all: renderXml = 1 on both inputs, zero
        # [WinEventLog:Microsoft-Windows-Sysmon...] stanzas. So there is no
        # render_format choice here, unlike the Windows add-on.
        "hec_default_sourcetype": "XmlWinEventLog",
        "syslog_viable": False,
        "sourcetypes": [
            _enrich_sourcetype({
                "name": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "hec_source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "datamodels": ["Endpoint", "Network_Traffic", "Network_Resolution"],
                "eventtypes": ["ms-sysmon-process", "ms-sysmon-network",
                               "ms-sysmon-dns", "ms-sysmon-filemod",
                               "ms-sysmon-regmod"],
                "tags": ["process", "report", "network", "communicate", "resolution",
                         "dns", "endpoint", "filesystem", "registry"],
                "description": "Sysmon process creation and image load (EventID 1, 7), "
                               "network connection (3), DNS query (22), file creation "
                               "(11) and registry events (12, 13, 14)",
                "entity_types": ["endpoint", "server", "domain_controller"],
                "account_types": ["standard", "admin", "service_account"],
                "datamodel_conditions": [
                    {
                        "when": "EventCode in (1, 7) — a process started or loaded an image",
                        "eventtype": "ms-sysmon-process",
                        "tags": ["process", "report"],
                        "datamodels": ["Endpoint"],
                    },
                    {
                        "when": "EventCode == 3 — a process opened a connection",
                        "eventtype": "ms-sysmon-network",
                        "tags": ["network", "communicate"],
                        "datamodels": ["Network_Traffic"],
                    },
                    {
                        "when": "EventCode == 22 — a process resolved a name",
                        "eventtype": "ms-sysmon-dns",
                        "tags": ["network", "resolution", "dns"],
                        "datamodels": ["Network_Resolution"],
                    },
                    {
                        "when": "EventCode == 11 — a file was written",
                        "eventtype": "ms-sysmon-filemod",
                        "tags": ["endpoint", "filesystem"],
                        "datamodels": ["Endpoint"],
                    },
                    {
                        "when": "EventCode in (12, 13, 14) — a registry event",
                        "eventtype": "ms-sysmon-regmod",
                        "tags": ["endpoint", "registry"],
                        "datamodels": ["Endpoint"],
                    },
                ],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dest",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Endpoint the registry was written on "
                                       "(<System><Computer>) — on every event",
                        "mutable": True,
                    },
                    {
                        "raw_field": "User",
                        "cim_field": "user",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": None,
                        "description": "Account the writing process ran as; the add-on "
                                       "strips the domain prefix",
                        "mutable": True,
                    },
                    {
                        "raw_field": "Image",
                        "cim_field": "process_path",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Process that touched the registry. Note the "
                                       "add-on reads Image, not ProcessPath — no "
                                       "add-on produces a field by that name",
                        "mutable": False,
                    },
                    {
                        "raw_field": "TargetObject",
                        "cim_field": "registry_path",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Full registry path. Also feeds registry_hive, "
                                       "but only under HKLM\\System\\, HKU\\ or "
                                       "HKLM\\SOFTWARE\\ — other hives leave it empty",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Details",
                        "cim_field": "registry_value_data",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Value written (EventID 13 only). A transform "
                                       "lifts the payload out of `DWORD (0x...)`; any "
                                       "other shape is passed through verbatim",
                        "mutable": False,
                    },
                    {
                        "raw_field": "EventType",
                        "cim_field": "action",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "CreateKey / DeleteKey / DeleteValue / SetValue / "
                                       "RenameKey. Decides `action` on an EventID 12: "
                                       "created or deleted",
                        "mutable": False,
                    },
                    {
                        "raw_field": "CommandLine",
                        "cim_field": "process",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Full command line of the process created "
                                       "(EventID 1 only)",
                        "mutable": False,
                    },
                    {
                        "raw_field": "ParentImage",
                        "cim_field": "parent_process_path",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Process that started it; also feeds "
                                       "parent_process_name and parent_process_exec",
                        "mutable": False,
                    },
                    {
                        "raw_field": "TargetFilename",
                        "cim_field": "file_path",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "File written (EventID 11); also feeds "
                                       "file_name. Sysmon carries no hash, size or "
                                       "ACL on a file creation; the datamodel "
                                       "defaults those to \"unknown\"",
                        "mutable": False,
                    },
                    {
                        "raw_field": "CreationUtcTime",
                        "cim_field": "file_create_time",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "When the file was created. The add-on compares "
                                       "it with UtcTime to decide whether action is "
                                       "created or modified",
                        "mutable": False,
                    },
                    {
                        "raw_field": "ProcessGuid",
                        "cim_field": "process_guid",
                        "datamodels": ["Endpoint"],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Sysmon's per-process identifier, passed through "
                                       "untouched — detections group by it",
                        "mutable": False,
                    },
                ],
            }),
        ],
    },
    "powershell": {
        # The odd one out: a Windows source that reaches no datamodel at all.
        #
        # Splunk_TA_windows grants this channel exactly two lines, in a
        # [source::XmlWinEventLog:Microsoft-Windows-PowerShell/Operational]
        # stanza — Computer_as_dest, and an EVAL-signature covering 4103 and
        # 4104. No eventtype matches the channel beyond the two every Windows
        # event gets (windows_event_signature on sourcetype=XmlWinEventLog,
        # windows_ta_data on source=XmlWinEventLog:*), and between them they
        # carry one tag, track_event_signatures, which is not a CIM tag. So
        # there is no datamodel to declare here, and none is declared.
        #
        # That is not a gap in the coverage: all 121 published detections on
        # this data source are raw searches over ScriptBlockText, and
        # security_content's own data_sources entry lists no supported_TA.
        # The value of the channel is the script text itself.
        #
        # Everything else is extracted by the generic [XmlWinEventLog] stanza,
        # the same path the 4688 attacks and Sysmon already use.
        "name": "Splunk Add-on for Microsoft Windows",
        "splunkbase_url": "https://splunkbase.splunk.com/app/742",
        "add_on_package": "Splunk_TA_windows",
        "add_on_version": "11.0.2",
        "display_name": "PowerShell",
        "vendor": "Microsoft",
        "description": "Windows PowerShell script block logging (EventID 4104)",
        # Windows event logs do not travel as syslog. inputs.conf ships no
        # PowerShell channel input at all, so there is no classic/XML choice to
        # offer either: the channel is generated as XML, which is what the
        # 121 detections and the `powershell` macro expect.
        "hec_default_sourcetype": "XmlWinEventLog",
        "syslog_viable": False,
        "sourcetypes": [
            _enrich_sourcetype({
                "name": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
                "hec_source": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
                "datamodels": [],
                "eventtypes": ["windows_event_signature", "windows_ta_data"],
                "tags": ["track_event_signatures"],
                "description": "PowerShell script block logging (EventID 4104) — the "
                               "source text of every block the engine compiled. Reaches "
                               "no CIM datamodel; the 121 published detections read the "
                               "raw fields directly",
                "entity_types": ["endpoint", "server", "domain_controller"],
                "account_types": ["standard", "admin", "service_account"],
                # Deliberately empty. The two eventtypes this channel matches
                # grant one tag between them, and it is not a CIM tag.
                "datamodel_conditions": [],
                "fields": [
                    {
                        "raw_field": "Computer",
                        "cim_field": "dest",
                        "datamodels": [],
                        "ai_source": {"type": "entity", "entity_type": "endpoint",
                                      "entity_field": "nt_host"},
                        "direction": None,
                        "description": "Endpoint the block was compiled on "
                                       "(<System><Computer>). The add-on's only "
                                       "REPORT for this channel, Computer_as_dest, "
                                       "builds `dest` from it; 109 detections group "
                                       "by one or the other",
                        "mutable": True,
                    },
                    {
                        "raw_field": "UserID",
                        "cim_field": "user_id",
                        "datamodels": [],
                        "ai_source": {"type": "account", "account_type": "standard",
                                      "account_field": "username"},
                        "direction": None,
                        "description": "The caller's SID, from <Security UserID=...>. "
                                       "This channel carries no user *name* anywhere, "
                                       "so an A&I account is represented as a SID "
                                       "derived from it — stable, so the same account "
                                       "always groups together. Scripts run by a "
                                       "management agent carry S-1-5-18",
                        "mutable": True,
                    },
                    {
                        "raw_field": "ScriptBlockText",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "The block's source text — the field the whole "
                                       "channel exists for, read by all 121 detections "
                                       "and by 377 clauses among them. No CIM mapping: "
                                       "searches read it under this name. Note the "
                                       "add-on excludes it from indexed extraction "
                                       "(XML_IE_EXCLUDE), so it is built at search "
                                       "time by eventdata_xml_data",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Path",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Script file the block was compiled from, empty "
                                       "for anything typed at a prompt. Both are real "
                                       "states and both are generated; one detection "
                                       "groups by Path with no fillnull, so only "
                                       "file-backed blocks can reach it",
                        "mutable": False,
                    },
                    {
                        "raw_field": "ScriptBlockId",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Per-block GUID. A block over ~20 KB is split "
                                       "across several events sharing this id, with "
                                       "MessageNumber counting to MessageTotal; "
                                       "nothing here is that large, so every event is "
                                       "1 of 1",
                        "mutable": False,
                    },
                    {
                        "raw_field": "EventID",
                        "cim_field": "signature_id",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "4104. Becomes EventCode, which every detection "
                                       "filters on, and signature_id through the "
                                       "generic stanza's EVAL",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Provider Name",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "Microsoft-Windows-PowerShell. Extracted as "
                                       "`Name` from the System block's attributes; "
                                       "107 detections group by it",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Provider Guid",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}, "
                                       "extracted as `Guid`. Grouped by, so it has to "
                                       "be the real provider GUID",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Opcode",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "15 on a 4104. Carries no meaning for the "
                                       "searches but 107 of them group by it, so it "
                                       "has to be present",
                        "mutable": False,
                    },
                    {
                        "raw_field": "Execution ProcessID",
                        "cim_field": "",
                        "datamodels": [],
                        "ai_source": {"type": "random"},
                        "direction": None,
                        "description": "The PowerShell host process, extracted as "
                                       "`ProcessID` from the System block. Grouped by, "
                                       "and distinct from the CIM `process_id` no "
                                       "eventtype here produces",
                        "mutable": False,
                    },
                ],
            }),
        ],
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_ta(ta_name: str) -> dict:
    """Get TA metadata by name."""
    return TA_REGISTRY.get(ta_name)


def list_tas() -> list:
    """List all TAs."""
    return list(TA_REGISTRY.keys())


def get_sourcetype_info(ta_name: str, sourcetype: str) -> dict:
    """Get sourcetype info from a TA."""
    ta = get_ta(ta_name)
    if not ta:
        return None
    for st in ta.get("sourcetypes", []):
        if st["name"] == sourcetype:
            return st
    return None


def get_datamodels_for_sourcetype(ta_name: str, sourcetype: str) -> list:
    """Get primary datamodels for a given TA + sourcetype."""
    info = get_sourcetype_info(ta_name, sourcetype)
    return info.get("datamodels", []) if info else []


def get_entity_types_for_sourcetype(ta_name: str, sourcetype: str) -> list:
    """Get entity types that can contribute to a sourcetype."""
    info = get_sourcetype_info(ta_name, sourcetype)
    return info.get("entity_types", []) if info else []


def get_account_types_for_sourcetype(ta_name: str, sourcetype: str) -> list:
    """Get account types that can contribute to a sourcetype."""
    info = get_sourcetype_info(ta_name, sourcetype)
    return info.get("account_types", []) if info else []


def get_fields_for_sourcetype(ta_name: str, sourcetype: str) -> list:
    """Get the field-level mapping table for a TA + sourcetype (Phase 3+ only)."""
    info = get_sourcetype_info(ta_name, sourcetype)
    return info.get("fields", []) if info else []


def wire_metadata(ta_name: str, sourcetype: str, render_format: str = None):
    """(sourcetype, source) to put on the wire for one registry sourcetype.

    The TA's documented ingestion sourcetype when it has one (pan:log, or the
    render_format-dependent XmlWinEventLog / WinEventLog), else the sourcetype's
    own name; and the documented `source`, or None when the registry gives none —
    a source that cannot be sourced from here must not be invented.
    """
    ta = get_ta(ta_name) or {}
    by_format = ta.get("hec_default_sourcetype_by_render_format")
    wire_sourcetype = (by_format.get(render_format or "xml") if by_format
                       else ta.get("hec_default_sourcetype")) or sourcetype

    info = get_sourcetype_info(ta_name, sourcetype) or {}
    by_format = info.get("hec_source_by_render_format")
    source = (by_format.get(render_format or "xml") if by_format
              else info.get("hec_source"))
    return wire_sourcetype, source


def get_datamodel_conditions(ta_name: str, sourcetype: str) -> list:
    """Get the conditional datamodel matching rules (eventtype + tag + when)."""
    info = get_sourcetype_info(ta_name, sourcetype)
    return info.get("datamodel_conditions", []) if info else []
