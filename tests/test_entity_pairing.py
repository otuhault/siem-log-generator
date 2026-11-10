"""An event describes one machine, so its fields must come from one entity.

EnvironmentManager used to flatten entities into one list per field, and
generators drew from each list independently — so an event could carry the
hostname of one machine with the IP of another, even though A&I holds the
correct pairing. Five combinations across four add-ons were affected.

These tests are written against ENTITY_TYPE_ROLES rather than a fixed list, so
an add-on added later is covered without touching this file.
"""

import re

import pytest

from environment_manager import (ACCOUNT_TYPE_ROLES, ENTITY_TYPE_ROLES,
                                 EnvironmentManager)
from log_generators import REGISTRY
from log_generators.ai_entity import AIEntityMixin


#: log_type -> entity_type, for every add-on whose events describe one machine
#: through more than one field. These are the ones pairing can be lost in.
MULTI_FIELD = sorted(
    (log_type, entity_type)
    for entity_type, log_map in ENTITY_TYPE_ROLES.items()
    for log_type, roles in log_map.items()
    if len(roles) > 1
)


@pytest.fixture
def env(tmp_path):
    """Two endpoints and one server whose fields are all distinguishable.

    The addresses sit in a range no generator template hard-codes, so a match in
    generated output can only have come from here.
    """
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    # A fresh store triggers the legacy migration, which reads a file relative
    # to the working directory. Start from nothing whatever it found.
    manager._data["entities"], manager._data["accounts"] = {}, {}
    manager.create_entity(name="PC-ALICE", entity_type="endpoint", ip="172.31.7.11",
                          nt_host="PC-ALICE", mac="aa:aa:aa:11:11:11", os="Windows 11")
    manager.create_entity(name="PC-BOB", entity_type="endpoint", ip="172.31.7.12",
                          nt_host="PC-BOB", mac="bb:bb:bb:22:22:22", os="Windows 10")
    manager.create_entity(name="SRV-DB", entity_type="server", ip="172.31.7.20",
                          nt_host="SRV-DB", mac="cc:cc:cc:33:33:33", os="Linux")
    return manager


def _build(log_type):
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    if config.get("multi_instance"):
        return REGISTRY[log_type](**{config["single_param_name"]: config["defaults"][0]})
    return REGISTRY[log_type](**{config["param_key"]: config["defaults"]})


def test_the_defect_is_worth_a_suite():
    """Guard the premise: several add-ons really do read two fields of one host."""
    assert len(MULTI_FIELD) >= 4, MULTI_FIELD


@pytest.mark.parametrize("log_type, entity_type", MULTI_FIELD,
                         ids=[f"{lt}-{et}" for lt, et in MULTI_FIELD])
def test_every_multi_field_generator_takes_a_roster(env, log_type, entity_type):
    """Pairing is impossible unless the generator receives whole entities."""
    generator = _build(log_type)
    assert isinstance(generator, AIEntityMixin), (
        f"{log_type} reads {len(ENTITY_TYPE_ROLES[entity_type][log_type])} fields of "
        f"one {entity_type} but cannot keep them together"
    )

    env.inject_into(generator, log_type, ratio=100)
    assert getattr(generator, "_ai_entity_roster", ()), "no roster was published"


@pytest.mark.parametrize("log_type, entity_type", MULTI_FIELD,
                         ids=[f"{lt}-{et}" for lt, et in MULTI_FIELD])
def test_every_multi_field_generator_draws_once_per_event(env, log_type, entity_type):
    """Publishing a roster is not enough — the generator must draw from it.

    cisco_ios shipped with its field accessors wired but no draw, so every
    lookup silently fell through to the generator's own values.
    """
    generator = _build(log_type)
    env.inject_into(generator, log_type, ratio=100)

    generator._ai_entity = None
    generator.generate()

    assert generator._ai_entity is not None, (
        f"{log_type}.generate() never calls _new_entity()"
    )


def test_a_roster_record_holds_one_entity(env):
    """Each record must be a real machine, not a mix of several."""
    roster = env._entity_roster("windows")

    assert roster.get("src"), "no windows src record built"
    known = {(e["nt_host"], e["ip"]) for e in env.get_all_entities()}
    for record in roster["src"]:
        pair = (record.get("workstations"), record.get("ip_addresses"))
        assert pair in known, f"{pair} belongs to no single entity"


def test_the_roster_is_grouped_by_the_part_each_entity_plays(env):
    """An event has two ends; the roster must be able to fill both at once."""
    from environment_manager import SIDES

    roster = env._entity_roster("paloalto")

    assert set(roster) <= set(SIDES), roster
    assert roster["src"] and roster["dest"], "both ends must be available"
    assert all("internal_ips" in r for r in roster["src"])
    assert all("internal_ips" in r for r in roster["dest"])
    # And they are drawn from different entity types, so they can differ.
    assert {r["internal_ips"] for r in roster["src"]} != \
           {r["internal_ips"] for r in roster["dest"]}


def test_entities_with_nothing_to_contribute_are_skipped(tmp_path):
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager._data["entities"], manager._data["accounts"] = {}, {}
    manager.create_entity(name="ghost", entity_type="endpoint")  # no ip, no nt_host

    assert manager._entity_roster("windows") == {}


# ── observable pairing, add-on by add-on ────────────────────────────────────

def _pairs(generator, patterns, n=400):
    """Distinct tuples of the captured groups across `n` generated events."""
    seen = set()
    for _ in range(n):
        line = generator.generate()
        found = [m.group(1) for p in patterns if (m := re.search(p, line))]
        if len(found) == len(patterns):
            seen.add(tuple(found))
    return seen


def test_windows_pairs_hostname_and_address(env):
    generator = _build("windows")
    env.inject_into(generator, "windows", ratio=100)

    pairs = _pairs(generator, [r"<Data Name='WorkstationName'>([^<]*)</Data>",
                               r"<Data Name='IpAddress'>([^<]*)</Data>"])

    assert pairs, "no logon event carried both fields"
    assert pairs <= {("PC-ALICE", "172.31.7.11"), ("PC-BOB", "172.31.7.12")}, pairs


def test_ssh_names_two_machines_because_there_are_two(env):
    """`SRV-A sshd: Accepted for alice from 10.0.0.5` is a host and a caller.

    Pairing them, as the first pass did, claimed every login came from the very
    machine being logged into. They are two ends, and the roster now fills both.
    """
    generator = _build("ssh")
    env.inject_into(generator, "ssh", ratio=100)

    pairs = _pairs(generator, [r'^\w{3} +\d+ [\d:]+ (\S+) ',
                               r'from (\d+\.\d+\.\d+\.\d+)'])

    assert pairs, "no line carried both fields"
    hosts = {h for h, _ in pairs}
    addresses = {a for _, a in pairs}
    assert hosts <= {e["nt_host"] for e in env.get_all_entities()}, hosts
    assert addresses <= {e["ip"] for e in env.get_all_entities()}, addresses
    assert len(pairs) > max(len(hosts), len(addresses)), (
        "the two ends still move together — they are not independent"
    )


def test_zscaler_pairs_name_address_and_os(env):
    generator = _build("zscaler")
    env.inject_into(generator, "zscaler", ratio=100)

    triples = _pairs(generator, [r'devicename=([^\t]*)',
                                 r'ClientIP=(\d+\.\d+\.\d+\.\d+)',
                                 r'deviceostype=([^\t]*)'])

    assert triples, "no record carried all three fields"
    known = {(e["nt_host"], e["ip"], e["os"]) for e in env.get_all_entities()}
    assert triples <= known, triples


# ── the mechanism itself ────────────────────────────────────────────────────

def test_without_an_environment_nothing_changes():
    """A generator built with no A&I keeps producing its own values."""
    generator = _build("windows")
    assert generator._ai_entity_roster == {}
    assert generator._new_entity() == {}
    assert generator._entity_field("workstations", lambda: "fallback") == "fallback"


def test_a_ratio_below_one_hundred_leaves_room_for_defaults(env):
    """Mixing happens on whole records, never inside one."""
    generator = _build("windows")
    env.inject_into(generator, "windows", ratio=40)

    roster = generator._ai_entity_roster["src"]
    assert len(roster) == 100
    assert sum(1 for r in roster if not r) == 60, "the default share is wrong"
    for record in roster:
        if record:
            assert (record["workstations"], record["ip_addresses"]) in {
                ("PC-ALICE", "172.31.7.11"), ("PC-BOB", "172.31.7.12")}


def test_a_zero_ratio_publishes_no_roster(env):
    generator = _build("windows")
    env.inject_into(generator, "windows", ratio=0)
    assert getattr(generator, "_ai_entity_roster", {}) == {}


def test_two_generators_do_not_share_a_drawn_entity(env):
    """The current entity is per instance, so parallel senders stay independent."""
    first, second = _build("windows"), _build("windows")
    env.inject_into(first, "windows", ratio=100)
    env.inject_into(second, "windows", ratio=100)

    first._new_entity()
    second._ai_entity_roster = {
        "src": [{"workstations": "OTHER", "ip_addresses": "172.31.9.9"}]}
    second._new_entity()

    assert first._ai_entity != second._ai_entity
    assert first._entity_field("workstations", lambda: None) in {"PC-ALICE", "PC-BOB"}


def test_cisco_ios_reads_both_fields_from_a_and_i(env):
    """cisco_ios has nothing to pair *within* one message, but must still obey A&I.

    Its address and MAC live in different message types — 0 messages out of 1500
    carry both — so pairing is unobservable there today. What is observable is
    that each field comes from the environment, and the wiring is in place for a
    future message type that carries both.
    """
    generator = _build("cisco_ios")
    env.inject_into(generator, "cisco_ios", ratio=100)

    known_ips = {e["ip"] for e in env.get_all_entities()}
    known_macs = {e["mac"].replace(":", "") for e in env.get_all_entities() if e["mac"]}

    seen_ips, seen_macs = set(), set()
    for _ in range(1500):
        line = generator.generate()
        for ip in re.findall(r"\b172\.31\.7\.\d+\b", line):
            seen_ips.add(ip)
        for mac in re.findall(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", line):
            seen_macs.add(mac.replace(".", ""))

    assert seen_ips and seen_ips <= known_ips, seen_ips
    assert seen_macs and seen_macs <= known_macs, seen_macs


# ── volet B: an account pinned to a machine stays on it ─────────────────────

#: log_type -> account pool, for add-ons that emit both an account and a host.
WITH_ACCOUNTS = sorted(
    (log_type, pool)
    for account_map in [ACCOUNT_TYPE_ROLES]
    for log_map in account_map.values()
    for log_type, pool in log_map.items()
    if pool and any(log_type in m for m in ENTITY_TYPE_ROLES.values())
)


@pytest.fixture
def linked(tmp_path):
    """alice is pinned to her machine, roamer is pinned to nothing."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager._data["entities"], manager._data["accounts"] = {}, {}
    alice_pc = manager.create_entity(name="PC-ALICE", entity_type="endpoint",
                                     ip="172.31.7.11", nt_host="PC-ALICE")
    manager.create_entity(name="PC-FREE", entity_type="endpoint",
                          ip="172.31.7.99", nt_host="PC-FREE")
    manager.create_account(username="alice", account_type="standard",
                           linked_entity=alice_pc)
    manager.create_account(username="roamer", account_type="standard")
    return manager


def test_a_linked_account_rides_inside_its_entity_record(linked):
    roster = linked._entity_roster("windows")["src"]

    pinned = [r for r in roster if r.get("usernames")]
    assert len(pinned) == 1, roster
    assert pinned[0]["usernames"] == "alice"
    assert pinned[0]["workstations"] == "PC-ALICE"


def test_a_linked_account_is_removed_from_the_free_pool(linked):
    """Left in the flat pool it could be drawn for somebody else's machine."""
    generator = _build("windows")
    linked.inject_into(generator, "windows", ratio=100)

    assert "alice" not in generator.usernames, "alice can still roam"
    assert "roamer" in generator.usernames


def test_an_unlinked_account_still_has_somewhere_to_go(linked):
    """Pinning one account must not strand the others."""
    generator = _build("windows")
    linked.inject_into(generator, "windows", ratio=100)

    pairs = _pairs(generator, [r"<Data Name='TargetUserName'>([^<]*)</Data>",
                               r'<Computer>([^<]*)</Computer>'], n=600)
    pairs = {(u, h) for u, h in pairs if u != "-"}   # "-" is Windows' own literal

    assert ("alice", "PC-ALICE") in pairs
    assert ("roamer", "PC-FREE") in pairs
    assert not [p for p in pairs if p[0] == "alice" and p[1] != "PC-ALICE"], (
        f"alice appeared away from her machine: {pairs}"
    )


def test_an_entity_with_no_linked_account_keeps_a_plain_record(linked):
    roster = linked._entity_roster("windows")["src"]
    free = [r for r in roster if not r.get("usernames")]

    assert len(free) == 1
    assert free[0]["workstations"] == "PC-FREE"


def test_an_account_linked_to_an_irrelevant_entity_is_not_pinned(tmp_path):
    """A link to an entity this add-on does not read must not hide the account."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager._data["entities"], manager._data["accounts"] = {}, {}
    # `firewall` is not among the entity types the windows add-on reads.
    fw = manager.create_entity(name="FW", entity_type="firewall", ip="172.31.7.1")
    manager.create_account(username="netadmin", account_type="admin", linked_entity=fw)

    generator = _build("windows")
    manager.inject_into(generator, "windows", ratio=100)

    assert "netadmin" in generator.usernames, (
        "the account vanished: pinned to an entity windows never emits"
    )


def test_an_account_without_a_usable_value_is_not_pinned(tmp_path):
    """Zscaler identifies users by email; an account without one pins nothing."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager._data["entities"], manager._data["accounts"] = {}, {}
    pc = manager.create_entity(name="PC", entity_type="endpoint",
                               ip="172.31.7.11", nt_host="PC", os="Windows 11")
    manager.create_account(username="noemail", account_type="standard", linked_entity=pc)

    records = [r for side in manager._entity_roster("zscaler").values() for r in side]
    assert all(not r.get("_USERS") for r in records)


@pytest.mark.parametrize("log_type, pool", WITH_ACCOUNTS,
                         ids=[f"{lt}-{p}" for lt, p in WITH_ACCOUNTS])
def test_every_account_bearing_generator_can_be_pinned(linked, log_type, pool):
    """An add-on that emits both an account and a host must honour the link."""
    generator = _build(log_type)
    assert isinstance(generator, AIEntityMixin), (
        f"{log_type} emits accounts and hosts but cannot pin one to the other"
    )
    linked.inject_into(generator, log_type, ratio=100)

    generator._ai_entity = None
    generator.generate()
    assert generator._ai_entity is not None, (
        f"{log_type}.generate() never calls _new_entity()"
    )


# ── volet C: an event has two ends, and both are real ───────────────────────

#: log_type -> the sides its roles cover, from ENTITY_TYPE_ROLES alone.
def _sides_of(log_type):
    from environment_manager import role_side
    return {role_side(cim)
            for log_map in ENTITY_TYPE_ROLES.values()
            for _, _, cim in log_map.get(log_type, [])}


TWO_ENDED = sorted(lt for lt in {lt for m in ENTITY_TYPE_ROLES.values() for lt in m}
                   if {"src", "dest"} <= _sides_of(lt))


@pytest.fixture
def two_ends(tmp_path):
    """Clients and servers in ranges that cannot be confused."""
    manager = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    manager._data["entities"], manager._data["accounts"] = {}, {}
    manager.create_entity(name="PC-A", entity_type="endpoint",
                          ip="172.31.7.11", nt_host="PC-A")
    manager.create_entity(name="PC-B", entity_type="endpoint",
                          ip="172.31.7.12", nt_host="PC-B")
    manager.create_entity(name="SRV-1", entity_type="server",
                          ip="172.31.9.21", nt_host="SRV-1")
    manager.create_entity(name="SRV-2", entity_type="server",
                          ip="172.31.9.22", nt_host="SRV-2")
    # windows reads its dest end from a domain controller, not a server.
    manager.create_entity(name="DC-1", entity_type="domain_controller",
                          ip="172.31.9.30", nt_host="DC-1", fqdn="dc-1.lab.local")
    return manager


def test_the_defect_spans_several_add_ons():
    """Guard the premise: this is not a Palo Alto quirk."""
    assert len(TWO_ENDED) >= 4, TWO_ENDED


@pytest.mark.parametrize("log_type", TWO_ENDED)
def test_both_ends_are_offered_separately(two_ends, log_type):
    roster = two_ends._entity_roster(log_type)
    assert roster.get("src"), f"{log_type} has no src record"
    assert roster.get("dest"), f"{log_type} has no dest record"


@pytest.mark.parametrize("log_type", ["paloalto", "cisco_asa"])
def test_a_session_runs_from_a_client_to_a_server(two_ends, log_type):
    """internal_ips feeds both ends; drawing from one flat pool made a session
    look like two unrelated machines, or a host talking to itself."""
    clients = {"172.31.7.11", "172.31.7.12"}
    servers = {"172.31.9.21", "172.31.9.22"}

    generator = _build(log_type)
    two_ends.inject_into(generator, log_type, ratio=100)
    lines = [generator.generate() for _ in range(600)]

    seen_src = {ip for line in lines
                for ip in re.findall(r"\b172\.31\.\d+\.\d+\b", line)} & clients
    seen_dest = {ip for line in lines
                 for ip in re.findall(r"\b172\.31\.\d+\.\d+\b", line)} & servers

    assert seen_src, "no client address reached the output"
    assert seen_dest, "no server address reached the output"


def test_palo_alto_never_puts_a_server_where_the_client_goes(two_ends):
    """The one add-on whose CSV positions make the two ends unambiguous."""
    generator = _build("paloalto")
    two_ends.inject_into(generator, "paloalto", ratio=100)

    known = {"172.31.7.11", "172.31.7.12", "172.31.9.21", "172.31.9.22"}
    sources, destinations = set(), set()
    for _ in range(800):
        fields = generator.generate().split(",")
        if len(fields) > 9:
            if fields[7] in known:
                sources.add(fields[7])
            if fields[8] in known:
                destinations.add(fields[8])

    assert sources == {"172.31.7.11", "172.31.7.12"}, sources
    assert destinations == {"172.31.9.21", "172.31.9.22"}, destinations


def test_apache_names_the_server_as_well_as_the_client(two_ends):
    """The case that opened volet C: the line has the client, the header the server."""
    from syslog_framing import SyslogFramedGenerator, SyslogFramer, host_pool_for
    from ta_registry import get_ta

    generator = _build("apache")
    two_ends.inject_into(generator, "apache", ratio=100)
    framed = SyslogFramedGenerator(
        generator, SyslogFramer(get_ta("apache")["syslog_framing"],
                                host_pool_for("apache")))

    pairs = set()
    for _ in range(200):
        line = framed.generate()
        header = re.match(r"^<\d+>\w{3}\s+\d+\s[\d:]+\s(\S+)\s", line)
        client = re.search(r"httpd: (\d+\.\d+\.\d+\.\d+)", line)
        assert header and client, line[:90]
        pairs.add((header.group(1), client.group(1)))

    hosts = {h for h, _ in pairs}
    clients = {c for _, c in pairs}
    assert hosts <= {"SRV-1", "SRV-2"}, f"the header named a client: {hosts}"
    assert clients <= {"172.31.7.11", "172.31.7.12"}, clients
    assert "localhost" not in hosts, "still falling back to the placeholder"


def test_an_ambiguous_pool_needs_the_side_spelled_out(two_ends):
    """internal_ips is on both ends, so it must not resolve on its own."""
    generator = _build("paloalto")
    two_ends.inject_into(generator, "paloalto", ratio=100)

    assert "internal_ips" not in generator._ai_pool_sides, (
        "a pool used on both ends must stay ambiguous, or one end wins silently"
    )
    generator._new_entity()   # the draw an event does before reading anything

    assert generator._entity_field("internal_ips", lambda: "fallback") == "fallback"
    assert generator._entity_field(
        "internal_ips", lambda: "fallback", side="src") in {"172.31.7.11", "172.31.7.12"}
    assert generator._entity_field(
        "internal_ips", lambda: "fallback", side="dest") in {"172.31.9.21", "172.31.9.22"}


def test_a_single_ended_pool_still_resolves_on_its_own(two_ends):
    generator = _build("windows")
    two_ends.inject_into(generator, "windows", ratio=100)

    assert generator._ai_pool_sides.get("workstations") == "src"
    generator._new_entity()
    assert generator._entity_field("workstations", lambda: None) in {"PC-A", "PC-B"}


def test_the_side_of_a_role_is_read_off_its_cim_field():
    from environment_manager import ROLE_SIDE_OVERRIDES, role_side

    assert role_side("src_ip") == "src"
    assert role_side("dest_nt_host") == "dest"
    assert role_side("dvc") == "device"
    # And where the name lies, an override says so rather than a special case.
    assert role_side("deviceostype") == "src"
    assert "deviceostype" in ROLE_SIDE_OVERRIDES
