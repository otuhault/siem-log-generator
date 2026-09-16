"""Windows identity fields: what A&I drives, and what stays coherent.

Three defects motivated this suite, all visible in generated events before the
fix: the same account appeared under five domains at once, its SID was redrawn
on every event, and the entity IPs A&I collected were written to a pool the
Windows generator never read.
"""

import re

import pytest

from environment_manager import DOMAIN_ROLES, EnvironmentManager
from log_generators import REGISTRY
from ta_registry import get_sourcetype_info


@pytest.fixture
def env(tmp_path):
    """An EnvironmentManager over a throwaway file, with a small lab in it."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager.create_entity(name="PC-ALICE", entity_type="endpoint",
                          ip="10.0.0.11", nt_host="PC-ALICE")
    manager.create_entity(name="PC-BOB", entity_type="endpoint",
                          ip="10.0.0.12", nt_host="PC-BOB")
    manager.create_account(username="alice", account_type="standard")
    manager.create_account(username="bob", account_type="admin")
    return manager


def _windows(env=None, ratio=100, channel="Security"):
    gen = REGISTRY["windows"](source=channel, render_format="xml")
    if env is not None:
        env.inject_into(gen, "windows", ratio=ratio)
    return gen


def _field(body, name):
    match = re.search(rf"<Data Name='{name}'>([^<]*)</Data>", body)
    return match.group(1) if match else None


def _sample(gen, n=250):
    return [gen.generate() for _ in range(n)]


# ── environment-wide settings ───────────────────────────────────────────────

def test_settings_default_to_empty(tmp_path):
    """A file with no settings key must not break, and must change nothing."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    assert manager.get_settings() == {"ad_domain": "", "ad_domain_dns": ""}


def test_settings_round_trip_and_ignore_unknown_keys(tmp_path):
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager.update_settings({"ad_domain": "  CONTOSO  ", "nope": "x"})

    assert manager.get_settings()["ad_domain"] == "CONTOSO", "value must be trimmed"
    assert "nope" not in manager.get_settings()

    reloaded = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    assert reloaded.get_settings()["ad_domain"] == "CONTOSO", "not persisted"


# ── the domain is environment-wide, not a per-event draw ────────────────────

def test_no_domain_configured_leaves_the_generator_alone(env):
    """Someone who never opens the setting keeps the sample domains."""
    untouched = REGISTRY["windows"](source="Security").domains
    assert _windows(env).domains == untouched


@pytest.mark.parametrize("ratio", [100, 50, 1], ids=["full", "half", "sliver"])
def test_a_configured_domain_pins_every_event(env, ratio):
    """One account must never appear under several domains, at any ratio.

    The domain is not blended like the other pools: mixing it is precisely what
    split one account into several CIM identities.
    """
    env.update_settings({"ad_domain": "LAB"})

    bodies = _sample(_windows(env, ratio=ratio))

    # "-" is Windows' own literal for "no domain here" (4688 TargetDomainName);
    # it is hard-coded in the event body, not drawn from the pool.
    domains = {d for b in bodies
               for d in (_field(b, "SubjectDomainName"), _field(b, "TargetDomainName"))
               if d and d != "-"}
    assert domains == {"LAB"}, f"expected only LAB, got {domains}"


def test_active_directory_also_gets_the_dns_domain(env):
    env.update_settings({"ad_domain": "LAB", "ad_domain_dns": "lab.local"})
    gen = REGISTRY["active_directory"](event_categories=["authentication"])
    env.inject_into(gen, "active_directory", ratio=100)

    assert gen.domains == ["LAB"]
    assert gen.domain_dns == ["lab.local"]


def test_only_the_microsoft_generators_take_a_domain(env):
    """The domain is not a common field — nothing else may be touched by it."""
    assert set(DOMAIN_ROLES) == {"windows", "active_directory"}

    env.update_settings({"ad_domain": "LAB"})
    for log_type in ("paloalto", "ssh", "apache"):
        config = REGISTRY[log_type].SOURCETYPE_CONFIG
        # multi_instance generators take one value, the others take the list.
        if config.get("multi_instance"):
            key, value = config["single_param_name"], config["defaults"][0]
        else:
            key, value = config["param_key"], config["defaults"]
        gen = REGISTRY[log_type](**{key: value})
        env.inject_into(gen, log_type, ratio=100)
        assert not hasattr(gen, "domains"), f"{log_type} grew a domain pool"


# ── SIDs track accounts ─────────────────────────────────────────────────────

def test_one_account_has_one_sid(env):
    """TargetUserSid must identify the account, not the event."""
    env.update_settings({"ad_domain": "LAB"})
    bodies = _sample(_windows(env))

    by_account = {}
    for body in bodies:
        user, sid = _field(body, "TargetUserName"), _field(body, "TargetUserSid")
        if user and sid:
            by_account.setdefault(user, set()).add(sid)

    assert by_account, "no event carried a target account"
    for user, sids in by_account.items():
        assert len(sids) == 1, f"{user} was given {len(sids)} different SIDs"


def test_accounts_of_one_domain_share_the_domain_part(env):
    """S-1-5-21-<domain>-<rid>: the domain part is per-domain, the RID per user."""
    gen = _windows()
    sids = [gen._sid_for(name, "LAB") for name in ("alice", "bob", "carol")]

    prefixes = {s.rsplit("-", 1)[0] for s in sids}
    assert len(prefixes) == 1, f"domain part differs between accounts: {prefixes}"
    assert len({s.rsplit("-", 1)[1] for s in sids}) == 3, "RIDs collided"


def test_the_same_account_in_another_domain_is_another_sid(env):
    gen = _windows()
    assert gen._sid_for("alice", "LAB") != gen._sid_for("alice", "OTHER")


def test_sids_are_stable_across_generator_instances(env):
    """Two senders on the same environment must agree on an account's SID."""
    assert _windows()._sid_for("alice", "LAB") == _windows()._sid_for("alice", "LAB")


# ── the IP pool A&I fills is actually read ──────────────────────────────────

def test_entity_ips_reach_the_logon_events(env):
    """The pool used to be written and never read, so IpAddress stayed random."""
    gen = _windows(env)
    assert gen.ip_addresses, "premise: A&I filled the pool"

    ips = {ip for b in _sample(gen) if (ip := _field(b, "IpAddress"))}

    assert ips, "no event carried an IpAddress"
    assert ips <= set(gen.ip_addresses), f"addresses invented outside A&I: {ips}"


def test_without_an_environment_the_ip_is_still_produced():
    """No A&I must not mean no address."""
    ips = {ip for b in _sample(_windows()) if (ip := _field(b, "IpAddress"))}
    assert ips, "the fallback address disappeared"


# ── the registry describes exactly what A&I can feed ────────────────────────

@pytest.mark.parametrize("ta, sourcetype, expected", [
    ("windows", "WinEventLog:Security",
     {"Computer", "SubjectUserName", "TargetUserName", "WorkstationName", "IpAddress"}),
    ("windows", "WinEventLog:System", {"Computer"}),
    ("windows", "WinEventLog:Application", {"Computer"}),
    ("active_directory", "WinEventLog:Security",
     {"Computer", "SubjectUserName", "TargetUserName", "WorkstationName", "IpAddress"}),
])
def test_registry_lists_the_a_and_i_driven_fields(ta, sourcetype, expected):
    fields = get_sourcetype_info(ta, sourcetype)["fields"]
    assert {f["raw_field"] for f in fields} == expected


def test_every_declared_field_names_a_source_a_and_i_can_supply():
    """No descriptive-only entries: each field must map onto the A&I schema."""
    from environment_manager import ACCOUNT_TYPES, ENTITY_TYPES

    entity_fields = {"name", "type", "ip", "nt_host", "mac", "fqdn", "os"}
    account_fields = {"username", "email"}

    for ta in ("windows", "active_directory"):
        for sourcetype in [s["name"] for s in
                           __import__("ta_registry").get_ta(ta)["sourcetypes"]]:
            for field in get_sourcetype_info(ta, sourcetype)["fields"]:
                source = field["ai_source"]
                if source["type"] == "entity":
                    assert source["entity_type"] in ENTITY_TYPES, field["raw_field"]
                    assert source["entity_field"] in entity_fields, field["raw_field"]
                elif source["type"] == "account":
                    assert source["account_type"] in ACCOUNT_TYPES, field["raw_field"]
                    assert source["account_field"] in account_fields, field["raw_field"]
                else:
                    pytest.fail(f"{field['raw_field']}: unsupported {source['type']}")
