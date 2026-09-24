r"""Every source and every attack, swept for the wiring people forget.

A new source touches six files and nothing fails when one is missed. Sysmon
shipped in v1.1.0 receiving no Assets & Identities at all: it was absent from
ENTITY_TYPE_ROLES and ACCOUNT_TYPE_ROLES, `ta_registry.py` advertised
`ai_source` for Computer and User anyway, and the Catalog showed that promise to
the reader. Nothing failed, because every check that could have caught it was
keyed on a list the new source was not in:

  - `test_entity_pairing.py` sweeps a hand-written `MULTI_FIELD` constant;
  - the dead-pool check in `references/adding-a-source.md` asks whether a pool
    named in the role tables is missing from the generator — for a source in
    neither table it asks nothing, and reports a clean bill of health.

So these are parametrised over `REGISTRY` and `ATTACK_REGISTRY` themselves.
Registering a source or an attack enrols it; there is no list to remember.

Two principles keep the sweep honest across a registry that is not uniform:

**The registry's promise is the specification.** `ai_source` in `ta_registry.py`
is what the Catalog shows the reader, and until now it drove nothing. Here it
decides what is required: a source whose registry promises an `account` must put
one on the wire, and a source that promises none — Apache names a client address
and no person — is not asked for one. Adding a field with an `ai_source` is
therefore a commitment these tests enforce.

**Behaviour, not membership.** The assertions build an environment, feed a
generator, and read the output. Membership in the role tables is checked too,
because that failure reads plainly, but a source could sit in both tables under
a pool nobody reads and look identical from the tables while producing nothing.
"""

import collections
import re

import pytest

from attack_generators import ATTACK_REGISTRY, AttackGeneratorFactory
from environment_manager import (ACCOUNT_TYPE_ROLES, ENTITY_TYPE_ROLES,
                                 EnvironmentManager)
from log_generators import REGISTRY
from log_senders import SenderManager
from ta_registry import get_sourcetype_info, get_ta

#: Values distinctive enough that finding one in an event means it came from the
#: environment rather than from a generator's own defaults.
PROBE = {
    "ip": "10.253.71.9",
    "nt_host": "AI-PROBE-HOST",
    "mac": "02:00:5e:10:00:09",
    "fqdn": "ai-probe-host.probe.local",
    "os": "Windows 11 Probe",
}
PROBE_ACCOUNT = "ai.probe.user"
PROBE_EMAIL = "ai.probe.user@probe.local"


# ── what each source's registry promises ────────────────────────────────────

def promised(log_type):
    """The A&I kinds this source's registry advertises: 'entity', 'account'.

    `either` is unfolded, because a field offered as "an account or a pool"
    still promises an account when the reader picks that option.
    """
    kinds = set()

    def walk(source):
        kind = (source or {}).get("type")
        if kind == "either":
            for option in source.get("options") or []:
                walk(option)
        elif kind in ("entity", "account"):
            kinds.add(kind)

    for sourcetype in (get_ta(log_type) or {}).get("sourcetypes", []):
        for field in sourcetype.get("fields", []):
            walk(field.get("ai_source"))
    return kinds


def account_appears_as(log_type, username, email):
    """The string an account turns into on this source's wire.

    Most write the name. Two do not, and both are deliberate: Zscaler identifies
    a person by email, and the PowerShell channel carries no user name anywhere,
    only a SID the generator derives from the account so the same person always
    groups together.

    A source that encodes an account some third way fails the sweep rather than
    quietly looking unwired — the encoding has to be stated here to count.
    """
    if log_type == "zscaler":
        return email
    if log_type == "powershell":
        from log_generators.powershell import user_sid
        return user_sid(username)
    return username


def environment_for(log_type, tmp_path):
    """An environment holding one entity of every type this source draws from."""
    env = EnvironmentManager(config_file=str(tmp_path / f"{log_type}.json"))
    env._data["entities"].clear()          # drop the seeded defaults
    env._data["accounts"].clear()

    for entity_type, log_map in ENTITY_TYPE_ROLES.items():
        if log_map.get(log_type):
            env.create_entity(f"probe-{entity_type}", entity_type, **PROBE)
    for account_type, log_map in ACCOUNT_TYPE_ROLES.items():
        if log_map.get(log_type):
            env.create_account(PROBE_ACCOUNT, email=PROBE_EMAIL,
                               account_type=account_type)
    env._save()
    return env


def build(log_type):
    """One generator, built from its own SOURCETYPE_CONFIG defaults."""
    cls = REGISTRY[log_type]
    config = cls.SOURCETYPE_CONFIG
    defaults = config.get("defaults") or []
    if config.get("multi_instance"):
        return cls(**{config["single_param_name"]: defaults[0]})
    if config.get("param_key") and defaults:
        return cls(**{config["param_key"]: list(defaults)})
    return cls()


# ── sources ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_type", sorted(REGISTRY))
def test_every_source_is_in_the_role_tables_its_registry_commits_it_to(log_type):
    """Presence, which is exactly what Sysmon was missing.

    Asserted separately from the behaviour below because the failure names the
    table, where an empty wire only says that nothing arrived.
    """
    kinds = promised(log_type)
    in_entities = any(log_map.get(log_type) for log_map in ENTITY_TYPE_ROLES.values())
    in_accounts = any(log_map.get(log_type) for log_map in ACCOUNT_TYPE_ROLES.values())

    if "entity" in kinds:
        assert in_entities, (
            f"{log_type} promises an entity field in ta_registry but is in no "
            f"ENTITY_TYPE_ROLES entry, so no asset can reach it")
    if "account" in kinds:
        assert in_accounts, (
            f"{log_type} promises an account field in ta_registry but is in no "
            f"ACCOUNT_TYPE_ROLES entry, so no identity can reach it")


@pytest.mark.parametrize("log_type", sorted(REGISTRY))
def test_every_pool_named_in_the_role_tables_exists_on_the_generator(log_type):
    """A pool nobody reads is injected into the void."""
    generator = build(log_type)
    wanted = {pool for log_map in ENTITY_TYPE_ROLES.values()
              for pool, _field, _cim in log_map.get(log_type, [])}
    wanted |= {log_map[log_type] for log_map in ACCOUNT_TYPE_ROLES.values()
               if log_map.get(log_type)}
    dead = sorted(pool for pool in wanted if not hasattr(generator, pool))
    assert not dead, f"{log_type} declares pools its generator does not have: {dead}"


@pytest.mark.parametrize("log_type", sorted(REGISTRY))
def test_every_source_puts_on_the_wire_what_its_registry_promises(log_type, tmp_path):
    """The one that would have caught Sysmon: inject, generate, look.

    Not "is it in the table" but "does it come out". At ratio 100 against an
    environment holding a single entity and a single account, finding neither
    over 200 events means nothing is wired through.
    """
    kinds = promised(log_type)
    if not kinds:
        pytest.skip(f"{log_type} promises no A&I field in ta_registry")

    env = environment_for(log_type, tmp_path)
    generator = build(log_type)
    env.inject_into(generator, log_type, 100)
    events = "\n".join(generator.generate() for _ in range(200))

    if "entity" in kinds:
        fields = {field for log_map in ENTITY_TYPE_ROLES.values()
                  for _pool, field, _cim in log_map.get(log_type, [])}
        expected = sorted({PROBE[f] for f in fields if f in PROBE})
        assert expected, f"{log_type} declares no entity field worth checking"
        assert any(value in events for value in expected), (
            f"{log_type}: none of {expected} reached the wire — the source is in "
            f"ENTITY_TYPE_ROLES but nothing reads the pool")

    if "account" in kinds:
        account = account_appears_as(log_type, PROBE_ACCOUNT, PROBE_EMAIL)
        assert account in events, (
            f"{log_type}: the account never reached the wire as {account!r}. If "
            f"this source encodes an account differently, say so in "
            f"account_appears_as() rather than dropping the check.")


# ── attacks ─────────────────────────────────────────────────────────────────

ATTACKS = sorted(ATTACK_REGISTRY)

#: Attacks that declare `data_sources` run through SenderManager.attack_plan and
#: have their sourcetype and source forced. The four SSH ones predate that and
#: take an older path — attack_plan cannot even be called on them — so the
#: assertions about planning apply to the sourced ones.
SOURCED = [key for key in ATTACKS if ATTACK_REGISTRY[key].get("data_sources")]


def declared_sourcetypes(definition):
    """(log_type, sourcetype) pairs, falling back to the source's own list."""
    sources = definition.get("data_sources")
    if sources:
        return [(s["log_type"], s["sourcetype"]) for s in sources]
    log_type = definition.get("log_type")
    return [(log_type, st["name"])
            for st in (get_ta(log_type) or {}).get("sourcetypes", [])]


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_attack_claims_only_a_datamodel_its_source_grants(attack):
    """An attack is filed in the Catalog under the datamodel it names.

    Claiming none is allowed and means the detection is a raw or macro search —
    the PowerShell channel reaches no datamodel at all, and the SID-history
    attack reads a macro over raw events. Naming one nothing grants is not: it
    puts the attack under a heading its events never populate.
    """
    definition = ATTACK_REGISTRY[attack]
    claimed = definition.get("datamodel") or ""
    if not claimed:
        return

    granted = set()
    for log_type, sourcetype in declared_sourcetypes(definition):
        info = get_sourcetype_info(log_type, sourcetype)
        granted |= set((info or {}).get("datamodels") or [])
    assert claimed in granted, (
        f"{attack} claims {claimed!r}, but its sources grant "
        f"{sorted(granted) or 'none'}")


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_attack_declares_a_source_the_registry_knows(attack):
    definition = ATTACK_REGISTRY[attack]
    pairs = declared_sourcetypes(definition)
    assert pairs, f"{attack} names no source at all"
    for log_type, sourcetype in pairs:
        assert log_type in REGISTRY, (attack, log_type)
        assert get_sourcetype_info(log_type, sourcetype), (attack, sourcetype)

    for source in definition.get("data_sources") or []:
        assert source.get("formats"), (attack, source["sourcetype"])
        by_format = (get_ta(source["log_type"]) or {}).get(
            "hec_default_sourcetype_by_render_format")
        if by_format:
            assert set(source["formats"]) <= set(by_format), attack
        else:
            assert len(source["formats"]) == 1, (attack, source["formats"])


@pytest.mark.parametrize("attack", SOURCED)
def test_every_sourced_attack_sends_the_count_it_is_asked_for(attack):
    """The count asked for is the count sent, and every event is one line."""
    plan = SenderManager.attack_plan(
        attack, {"attack_events_count": 6, "attack_noise": True,
                 "attack_noise_count": 6}, "configuration")
    kinds = collections.Counter(event.kind for event in plan)
    assert kinds["attack"] == 6, (attack, dict(kinds))
    assert kinds["noise"] == 6, (attack, dict(kinds))

    generator = AttackGeneratorFactory.get_generator(attack, {})
    for event in plan:
        generator.use_identity(event.identity)
        line = (generator.generate() if event.kind == "attack"
                else generator.generate_noise())
        assert isinstance(line, str) and line.strip(), attack
        assert "\n" not in line, f"{attack} emitted a multi-line event"


#: The identity kinds this sweep knows how to type into and to recognise coming
#: back. An address is left out on purpose: the two port scans sweep addresses
#: around the one they are given, so a single environment IP is correctly *not*
#: what every event carries, and asserting otherwise would be wrong.
TYPEABLE = {"hostname": "TYPED-HOST-01", "username": "typed.user"}


def typeable_fields(definition):
    return [f for f in definition.get("identity_fields") or []
            if f.get("kind") in TYPEABLE]


#: Attacks that predate the per-field identity picker and steer their
#: identities through the environment ratio instead, which test_attack_tor.py
#: covers. Pinned rather than derived: the two sweeps below skip these, and
#: without the pin a new attack could join the skip list by simply not
#: declaring a picker — the vacuous pass this whole file exists to prevent.
NO_IDENTITY_PICKER = {
    "paloalto_horizontal_port_scan",
    "paloalto_vertical_port_scan",
    "ssh_bruteforce",
    "ssh_credential_stuffing",
    "ssh_distributed_bruteforce",
    "ssh_password_spraying",
    "windows_tor_client_execution",
}


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_field_with_an_ai_story_also_has_a_picker(attack):
    """`ai_fields` and `identity_fields` describe the same fields, or one is dead.

    Dropping a single field from `identity_fields` is invisible to the sweeps
    below as long as another field survives: they check what is declared, so a
    field that quietly stops being offered is simply not checked. `ai_fields`
    is the second declaration that makes the loss show up.
    """
    if attack in NO_IDENTITY_PICKER:
        pytest.skip(f"{attack} predates the picker")
    definition = ATTACK_REGISTRY[attack]
    offered = {f["field"] for f in definition.get("identity_fields") or []}
    orphaned = sorted(set(definition.get("ai_fields") or {}) - offered)
    assert not orphaned, (
        f"{attack}: {orphaned} declare an A&I source but the form offers no "
        f"picker for them, so nobody can choose one")


def test_only_the_known_legacy_attacks_offer_no_identity_picker():
    """A new attack cannot opt out of the identity sweeps by staying silent."""
    without = {key for key in ATTACKS if not typeable_fields(ATTACK_REGISTRY[key])}
    assert without == NO_IDENTITY_PICKER, (
        "an attack offers no hostname or username picker. Give it identity_fields "
        "so the two sweeps below apply, or add it here on purpose — the name then "
        "shows up in review.")


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_attack_honours_a_value_typed_into_the_form(attack):
    """A field that renders but steers nothing is the quiet failure here.

    The operator types a hostname, the form accepts it, and the events name
    somebody else's machine.
    """
    definition = ATTACK_REGISTRY[attack]
    fields = typeable_fields(definition)
    if not fields:
        pytest.skip(f"{attack} offers no hostname or username field")

    typed = {f["field"]: TYPEABLE[f["kind"]] for f in fields}
    plan = SenderManager.attack_plan(
        attack, {"attack_events_count": 5,
                 "attack_identity": {name: {"mode": "custom", "value": value}
                                     for name, value in typed.items()}},
        "configuration")
    for name, value in typed.items():
        seen = {event.identity.get(name) for event in plan if event.kind == "attack"}
        assert seen == {value}, (
            f"{attack}: typing {value!r} into {name} produced "
            f"{sorted(str(s) for s in seen)}")


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_attack_field_offered_as_an_asset_can_come_from_the_environment(
        attack, tmp_path, monkeypatch):
    """The A&I mode the form offers, exercised for every attack that offers it."""
    import log_senders

    definition = ATTACK_REGISTRY[attack]
    fields = [f for f in typeable_fields(definition)
              if f.get("picker") in ("assets", "identities")]
    if not fields:
        pytest.skip(f"{attack} offers no asset-backed hostname or username field")

    env = EnvironmentManager(config_file=str(tmp_path / f"{attack}.json"))
    env._data["entities"].clear()
    env._data["accounts"].clear()
    # Every type, because an attack may target a router or a firewall rather
    # than a workstation — cisco_traffic_mirroring names a router.
    from environment_manager import ENTITY_TYPES
    for entity_type in ENTITY_TYPES:
        env.create_entity(f"probe-{entity_type}", entity_type, **PROBE)
    for account_type in ("standard", "admin", "service_account"):
        env.create_account(PROBE_ACCOUNT, email=PROBE_EMAIL, account_type=account_type)
    env._save()
    monkeypatch.setattr(log_senders, "_env_manager", env)

    plan = SenderManager.attack_plan(
        attack, {"attack_events_count": 5,
                 "attack_identity": {f["field"]: {"mode": "ai"} for f in fields}},
        "configuration")
    attack_events = [event for event in plan if event.kind == "attack"]
    assert attack_events, attack

    from_environment = set(PROBE.values()) | {PROBE_ACCOUNT, PROBE_EMAIL}
    for field in fields:
        name = field["field"]
        values = {event.identity.get(name) for event in attack_events}
        assert values <= from_environment, (
            f"{attack}: {name} asked for A&I and got "
            f"{sorted(str(v) for v in values - from_environment)}")


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_attack_that_links_a_detection_links_a_real_one(attack):
    """The URL carries the detection's own id, and the id is a UUID."""
    definition = ATTACK_REGISTRY[attack]
    url = definition.get("splunk_research_url")
    if not url:
        return
    assert re.fullmatch(
        r"https://research\.splunk\.com/[a-z_]+/"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/", url), attack
    detection_id = (definition.get("detection") or {}).get("id")
    assert detection_id and url.rstrip("/").endswith(detection_id), attack
