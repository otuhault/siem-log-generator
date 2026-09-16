"""
A&I Mapping — adapter over ta_registry.py (Phase 3+).

The TA Registry is the single source of truth for the field ↔ CIM ↔ A&I source
mapping. This module exposes the legacy API (get_mapping / get_entity_types_for_sourcetype /
get_account_types_for_sourcetype) so existing consumers (environment_manager, app.py)
keep working without changes while reading derived data from the registry.

Legacy mapping shape returned by `get_mapping(ta, st)`:
  {
    "<raw_field>": {
        "entity_type":  "firewall",          # if ai_source.type=entity (or first 'entity' option in 'either')
        "entity_field": "nt_host",
        "account_type": "standard",          # if ai_source.type=account (or first 'account' option in 'either')
        "account_field":"username",
        "cim_field":   "dvc",
        "datamodels":  ["Network_Traffic"],
        "direction":   "src" | "dest" | None,
        "description": "...",
        "mutable":     True,
    },
    ...
  }

Fields without an A&I source (random / static / extracted-only) are skipped here —
they are still visible via `ta_registry.get_fields_for_sourcetype()`.
"""

from typing import Optional

from ta_registry import (
    get_sourcetype_info,
    get_fields_for_sourcetype,
    list_tas,
)


# ──────────────────────────────────────────────────────────────────────────────
# Internal: project a registry field row into the legacy flat dict
# ──────────────────────────────────────────────────────────────────────────────

def _project_field(field: dict) -> Optional[dict]:
    """Convert one registry `fields[]` row into the legacy mapping shape.

    Returns None if the field has no A&I source (random / static).
    For 'either' sources, picks the first option (entity preferred over network_pool)
    so legacy consumers see *something* — the full options list stays accessible
    via ta_registry.get_fields_for_sourcetype().
    """
    src = field.get("ai_source") or {}
    if src.get("type") in (None, "random", "static"):
        return None

    base = {
        "cim_field":  field.get("cim_field"),
        "datamodels": field.get("datamodels", []),
        "direction":  field.get("direction"),
        "description": field.get("description", ""),
        "mutable":    field.get("mutable", True),
    }

    if src["type"] == "entity":
        return {**base,
                "entity_type":  src.get("entity_type"),
                "entity_field": src.get("entity_field")}

    if src["type"] == "account":
        return {**base,
                "account_type":  src.get("account_type"),
                "account_field": src.get("account_field")}

    if src["type"] == "network_pool":
        return {**base,
                "network_pool_role": src.get("role")}

    if src["type"] == "either":
        # Prefer entity, then account, then network_pool — to keep legacy view useful
        order = {"entity": 0, "account": 1, "network_pool": 2}
        for opt in sorted(src.get("options", []),
                          key=lambda o: order.get(o.get("type"), 99)):
            picked = _project_field({**field, "ai_source": opt})
            if picked:
                # Surface the full alternatives for callers that care
                picked["alternatives"] = src.get("options")
                return picked

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public API (kept stable for environment_manager.py and app.py)
# ──────────────────────────────────────────────────────────────────────────────

class AIMappingManager:
    """Thin adapter over the TA registry. No persistence — all data is derived."""

    def __init__(self, *_args, **_kwargs):
        # Accept legacy positional/keyword args (e.g. config_file=) silently.
        pass

    # -- core lookups -----------------------------------------------------------

    def get_mapping(self, ta_name: str, sourcetype: str) -> dict:
        """Return {raw_field: <legacy mapping dict>} for every A&I-sourced field."""
        out = {}
        for f in get_fields_for_sourcetype(ta_name, sourcetype):
            projected = _project_field(f)
            if projected is None:
                continue
            out[f["raw_field"]] = projected
        return out

    def get_field_mapping(self, ta_name: str, sourcetype: str, field: str) -> Optional[dict]:
        return self.get_mapping(ta_name, sourcetype).get(field)

    def list_mutable_fields(self, ta_name: str, sourcetype: str) -> list:
        return [f for f, m in self.get_mapping(ta_name, sourcetype).items()
                if m.get("mutable", False)]

    # -- type aggregations ------------------------------------------------------

    def get_entity_types_for_sourcetype(self, ta_name: str, sourcetype: str) -> set:
        """Set of entity_type values reachable for a sourcetype (incl. 'either' options)."""
        types = set()
        for f in get_fields_for_sourcetype(ta_name, sourcetype):
            src = f.get("ai_source") or {}
            options = src.get("options") if src.get("type") == "either" else [src]
            for opt in options or []:
                if (opt or {}).get("type") == "entity":
                    et = opt.get("entity_type")
                    if et:
                        types.add(et)
        # Fallback: legacy registries that still carry entity_types[] inline
        if not types:
            info = get_sourcetype_info(ta_name, sourcetype) or {}
            types.update(info.get("entity_types", []))
        return types

    def get_account_types_for_sourcetype(self, ta_name: str, sourcetype: str) -> set:
        types = set()
        for f in get_fields_for_sourcetype(ta_name, sourcetype):
            src = f.get("ai_source") or {}
            options = src.get("options") if src.get("type") == "either" else [src]
            for opt in options or []:
                if (opt or {}).get("type") == "account":
                    at = opt.get("account_type")
                    if at:
                        types.add(at)
        if not types:
            info = get_sourcetype_info(ta_name, sourcetype) or {}
            types.update(info.get("account_types", []))
        return types

    def get_network_pool_roles_for_sourcetype(self, ta_name: str, sourcetype: str) -> set:
        """Set of network pool roles ('src_pool' / 'dest_pool') used by a sourcetype."""
        roles = set()
        for f in get_fields_for_sourcetype(ta_name, sourcetype):
            src = f.get("ai_source") or {}
            options = src.get("options") if src.get("type") == "either" else [src]
            for opt in options or []:
                if (opt or {}).get("type") == "network_pool":
                    r = opt.get("role")
                    if r:
                        roles.add(r)
        return roles

    # -- introspection ----------------------------------------------------------

    def get_stats(self) -> dict:
        """Per-TA stats: number of sourcetypes mapped, mutable field count."""
        stats = {}
        for ta in list_tas():
            ta_stats = {}
            ta_info = get_sourcetype_info(ta, "_") or {}  # noqa: harmless probe
            for st in (ta_info.get("sourcetypes") or []) or get_sourcetype_list_for_stats(ta):
                pass
        # Simpler implementation using the registry directly
        from ta_registry import TA_REGISTRY
        stats = {}
        for ta_name, ta in TA_REGISTRY.items():
            per_st = {}
            for st in ta.get("sourcetypes", []):
                fields = st.get("fields", [])
                per_st[st["name"]] = {
                    "fields_count":   len(fields),
                    "mutable_count":  sum(1 for f in fields if f.get("mutable", True)),
                }
            stats[ta_name] = per_st
        return stats

    # -- write API kept as no-op for backward compat ----------------------------

    def add_mapping(self, *_args, **_kwargs):
        """No-op — mappings now live in ta_registry.py. Edit the registry to change them."""
        raise NotImplementedError(
            "Mappings are managed in ta_registry.py since Phase 3. "
            "Edit the registry directly to add or change a sourcetype mapping."
        )

    def delete_mapping(self, *_args, **_kwargs):
        raise NotImplementedError(
            "Mappings are managed in ta_registry.py since Phase 3."
        )


def get_sourcetype_list_for_stats(ta_name):  # tiny helper used above
    from ta_registry import TA_REGISTRY
    return (TA_REGISTRY.get(ta_name) or {}).get("sourcetypes", [])
