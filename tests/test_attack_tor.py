"""Windows TOR Client Execution, against the detection it is meant to trigger.

The detection (splunk/security_content, windows_tor_client_execution.yml) reads
Endpoint.Processes where

    process_name = "tor.exe"
    OR (process_path = "*\\BraveSoftware\\Brave-Browser*" AND process_path = "*\\tor-*")

For a 4688, Splunk_TA_windows sets process_path from NewProcessName (classic:
New_Process_Name) and process_name from its last path segment. So the tests take
each generated event, extract those two fields the way the add-on does, and
evaluate the registry's own copy of that `where` clause: every attack event must
match it, and no noise event may.
"""

import collections
import re
from pathlib import Path

import pytest

import log_senders
from attack_generators import ATTACK_REGISTRY, AttackGeneratorFactory
from log_senders import SenderManager

ATTACK = "windows_tor_client_execution"
TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_windows" / "default"


# ── the detection's where clause, evaluated ─────────────────────────────────

_CLAUSE = re.compile(r'\s*(?:(\()|(\))|(AND|OR)\b|(\w+)\s*=\s*"([^"]*)")')


def _matches_where(where, fields):
    """Evaluate a tstats `where` of `field = "glob"` terms, AND over OR.

    tstats compares these case-insensitively, with `*` as the only wildcard.
    """
    tokens, pos = [], 0
    while pos < len(where):
        m = _CLAUSE.match(where, pos)
        assert m, f"cannot read the detection's where clause at {where[pos:]!r}"
        pos = m.end()
        tokens.append(m.group(1) or m.group(2) or m.group(3) or (m.group(4), m.group(5)))

    def term(i):
        if tokens[i] == "(":
            value, i = either(i + 1)
            assert tokens[i] == ")"
            return value, i + 1
        field, pattern = tokens[i]
        value = (fields.get(field) or "").lower()
        regex = "^" + ".*".join(re.escape(p) for p in pattern.lower().split("*")) + "$"
        return re.match(regex, value, re.S) is not None, i + 1

    def both(i):
        value, i = term(i)
        while i < len(tokens) and tokens[i] == "AND":
            right, i = term(i + 1)
            value = value and right
        return value, i

    def either(i):
        value, i = both(i)
        while i < len(tokens) and tokens[i] == "OR":
            right, i = both(i + 1)
            value = value or right
        return value, i

    result, end = either(0)
    assert end == len(tokens)
    return result


WHERE = ATTACK_REGISTRY[ATTACK]["detection"]["where"]


def test_the_evaluator_reads_the_clause_as_splunk_does():
    """Guard the guard: the Brave branch needs both halves."""
    assert _matches_where(WHERE, {"process_name": "TOR.EXE", "process_path": "x"})
    assert _matches_where(WHERE, {"process_name": "tor-0.4.8.10-win32-brave-2.exe",
                                  "process_path": r"C:\Users\a\AppData\Local\BraveSoftware\Brave-Browser\User Data\x\tor-0.4.8.10-win32-brave-2.exe"})
    assert not _matches_where(WHERE, {"process_name": "brave.exe",
                                      "process_path": r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"})
    assert not _matches_where(WHERE, {"process_name": "tor-browser-installer.exe",
                                      "process_path": r"C:\Users\a\Downloads\tor-browser-installer.exe"})


# ── field extraction, the add-on's way ──────────────────────────────────────

def _xml_process_path(event):
    """NewProcessName, through [eventdata_xml_block] and [eventdata_xml_data]."""
    block = re.search(r"(?ms)<EventData(?:\s+[^>]+)?>(.*?)</EventData>", event).group(1)
    fields = dict(re.findall(r"<(?:\w+)\sName='([^>]*)'/?>([^<]*)", block))
    return fields["NewProcessName"]


def _classic_process_path(event):
    """New_Process_Name, through Splunk's wel-col-kv key: value extraction.

    That transform ships in Splunk's system defaults, not in the add-on, so it is
    written out here: a `Name:` label, whitespace, then the value to end of line.
    """
    fields = {k.strip().replace(" ", "_"): v.strip()
              for k, v in re.findall(r"\n\s*([^:\n]+):\s+([^\n]*)", event)}
    return fields["New_Process_Name"]


def _endpoint_fields(event, render_format):
    path = _xml_process_path(event) if render_format == "xml" else _classic_process_path(event)
    # [extract_new_process_name*]: REGEX = (?:.*\\)?(.*)
    name = re.match(r"(?:.*\\)?(.*)", path).group(1)
    return {"process_path": path, "process_name": name}


def _generator(render_format, **options):
    return AttackGeneratorFactory.get_generator(ATTACK, {"render_format": render_format, **options})


@pytest.mark.parametrize("render_format", ["xml", "classic"])
def test_every_attack_event_triggers_the_detection(render_format):
    generator = _generator(render_format)
    names = collections.Counter()
    for _ in range(400):
        fields = _endpoint_fields(generator.generate(), render_format)
        assert _matches_where(WHERE, fields), f"not detected: {fields}"
        names[fields["process_name"] == "tor.exe"] += 1
    # Both branches of the rule are exercised, not only process_name = tor.exe.
    assert names[True] and names[False], names


@pytest.mark.parametrize("render_format", ["xml", "classic"])
def test_no_noise_event_triggers_the_detection(render_format):
    generator = _generator(render_format)
    for _ in range(400):
        fields = _endpoint_fields(generator.generate_noise(), render_format)
        assert not _matches_where(WHERE, fields), f"noise detected: {fields}"


def test_the_classic_rendering_carries_what_the_add_on_keys_on():
    event = _generator("classic").generate()
    assert re.search(r"(?m)^LogName=Security\s*$", event), "[ta-windows-fix-classic-source]"
    assert re.search(r"(?m)^ComputerName=[^.\s]+", event), "[WinEventHostOverride]"
    assert re.search(r"(?m)^EventCode=4688$", event)
    assert "Creator Process Name:\t" in event


# ── what the attack sends ───────────────────────────────────────────────────

class _Recorder:
    def __init__(self):
        self.sent = []
        self.hosts = []

    def send_event(self, line, sourcetype=None, source=None, host=None):
        self.sent.append((line, sourcetype, source))
        self.hosts.append(host)
        return True

    def close(self):
        pass


def _run(options, monkeypatch, tmp_path):
    manager = SenderManager.__new__(SenderManager)
    manager._data = {"a": {"logs_generated": 0}}
    manager.threads = {}
    manager._save = lambda: None
    recorder = _Recorder()
    manager._build_hec_sender = lambda config_id, opts: (recorder.opts.update(opts) or recorder)
    recorder.opts = {}
    sleeps = []
    monkeypatch.setattr(log_senders.time, "sleep", lambda s: sleeps.append(s))

    import threading
    manager._execute_attack("a", {"log_type": ATTACK, "destination_type": "configuration",
                                  "configuration_id": "c", "options": options},
                            threading.Event())
    return manager, recorder, sleeps


@pytest.mark.parametrize("render_format, sourcetype, source", [
    ("xml", "XmlWinEventLog", "XmlWinEventLog:Security"),
    ("classic", "WinEventLog", "WinEventLog:Security"),
])
def test_the_selected_format_forces_sourcetype_and_source(render_format, sourcetype, source,
                                                          monkeypatch, tmp_path):
    """A typed override cannot win: it would be wrong for any other sourcetype,
    and the Windows add-on classifies on `source`."""
    options = {"attack_sources": [{"log_type": "windows", "sourcetype": "WinEventLog:Security",
                                   "render_format": render_format}],
               "hec_sourcetype": "bogus", "hec_source": "bogus", "hec_index": "attacks"}
    manager, recorder, _ = _run(options, monkeypatch, tmp_path)

    assert {(st, src) for _, st, src in recorder.sent} == {(sourcetype, source)}
    assert "hec_sourcetype" not in recorder.opts and "hec_source" not in recorder.opts
    assert recorder.opts.get("hec_index") == "attacks", "the index override must survive"


def test_defaults_are_five_events_no_noise_over_one_second(monkeypatch, tmp_path):
    manager, recorder, sleeps = _run({}, monkeypatch, tmp_path)
    assert len(recorder.sent) == 5
    assert sleeps == [0.2] * 5, "the default second is spread across the events"
    assert manager._data["a"]["attack_status"].startswith("Done")


def test_a_duration_of_zero_still_sends_everything_at_once(monkeypatch, tmp_path):
    _, recorder, sleeps = _run({"attack_duration": 0}, monkeypatch, tmp_path)
    assert len(recorder.sent) == 5 and sleeps == []


def test_noise_adds_benign_events_when_enabled(monkeypatch, tmp_path):
    manager, recorder, _ = _run({"attack_noise": True}, monkeypatch, tmp_path)
    detected = sum(_matches_where(WHERE, _endpoint_fields(line, "xml")) for line, _, _ in recorder.sent)
    assert len(recorder.sent) == 25
    assert detected == 5, "noise must add 20 events the detection does not match"


def test_a_duration_spreads_the_events(monkeypatch, tmp_path):
    _, recorder, sleeps = _run({"attack_duration": 10, "attack_events_count": 4},
                               monkeypatch, tmp_path)
    assert len(recorder.sent) == 4 and sleeps == [2.5] * 4


def test_several_sources_share_the_count_and_keep_their_own_wire_metadata(monkeypatch):
    """The count asked for is the count sent, dealt between the sources.

    Each source keeps the sourcetype and source of the format chosen for it, so
    the split never mislabels an event.
    """
    monkeypatch.setitem(ATTACK_REGISTRY[ATTACK], "data_sources", [
        {"log_type": "windows", "sourcetype": "WinEventLog:Security", "formats": ["xml", "classic"]},
        {"log_type": "windows", "sourcetype": "WinEventLog:System", "formats": ["xml", "classic"]},
    ])
    plan = SenderManager.attack_plan(ATTACK, {"attack_events_count": 40, "attack_sources": [
        {"log_type": "windows", "sourcetype": "WinEventLog:Security", "render_format": "xml"},
        {"log_type": "windows", "sourcetype": "WinEventLog:System", "render_format": "classic"},
    ]})

    by_wire = collections.Counter((e.sourcetype, e.source) for e in plan)
    assert sum(by_wire.values()) == 40, "two sources must not double the attack"
    assert set(by_wire) == {("XmlWinEventLog", "XmlWinEventLog:Security"),
                            ("WinEventLog", "WinEventLog:System")}
    assert max(by_wire.values()) - min(by_wire.values()) <= 1, by_wire

    # And each event is rendered in its own source's format.
    for event in plan:
        line = event.render()
        xml = line.startswith("<Event")
        assert xml == (event.sourcetype == "XmlWinEventLog"), event.sourcetype


def test_an_unknown_selection_falls_back_to_the_first_declared_source():
    plan = SenderManager.attack_plan(ATTACK, {"attack_sources": [
        {"log_type": "windows", "sourcetype": "Nope", "render_format": "xml"}]})
    assert {(e.sourcetype, e.source) for e in plan} == {("XmlWinEventLog", "XmlWinEventLog:Security")}


# ── the environment ─────────────────────────────────────────────────────────
#
# Reported: the slider behaved as an on/off switch. Measured before the fix —
# five events at 50%, twenty runs: [5, 0, 5, 0, 0, 0, 5, 5, ...], never a mix,
# and the noise followed the attack's single coin. user and dest are `fixed`, so
# they were drawn once, and the ratio only decided that one draw.

import random as _random

from attack_generators import draw_environment_identity, environment_flags

ENV_USERS = {"alice", "bob", "carol"}
HOST_OF = {"alice": "WKS-ALICE", "bob": "WKS-BOB", "carol": "WKS-CAROL"}
_USER = re.compile(r"<Data Name='SubjectUserName'>([^<]+)</Data>")
_HOST = re.compile(r"<Computer>([^<]+)</Computer>")


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    for name, host in HOST_OF.items():
        entity = env.create_entity(name, "endpoint", nt_host=host)
        env.create_account(name, account_type="standard", linked_entity=entity)
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def _who(plan):
    """(kind, user, host, from_environment) for every rendered event."""
    out = []
    for event in plan:
        line = event.render()
        user, host = _USER.search(line).group(1), _HOST.search(line).group(1)
        out.append((event.kind, user, host, user in ENV_USERS))
    return out


def _plan(ratio, **extra):
    options = {"use_assets_identities": True, "assets_identities_ratio": ratio, **extra}
    return SenderManager.attack_plan(ATTACK, options, "configuration")


def test_half_of_five_events_is_two_or_three_never_all_or_none(environment):
    counts = collections.Counter(
        sum(env for _, _, _, env in _who(_plan(50))) for _ in range(60))
    assert set(counts) <= {2, 3}, f"the ratio is not applied per event: {dict(counts)}"
    assert counts[2] and counts[3], "the fraction is never left to chance"


@pytest.mark.parametrize("ratio, expected", [(0, 0), (100, 5), (20, 1), (60, 3)])
def test_whole_shares_are_exact(environment, ratio, expected):
    for _ in range(10):
        assert sum(env for _, _, _, env in _who(_plan(ratio))) == expected


def test_over_many_runs_the_share_is_the_ratio(environment):
    runs = [sum(env for _, _, _, env in _who(_plan(30))) for _ in range(400)]
    assert abs(sum(runs) / len(runs) - 1.5) < 0.15, sum(runs) / len(runs)


def test_the_noise_gets_its_own_share_at_the_same_ratio(environment):
    for _ in range(10):
        events = _who(_plan(50, attack_noise=True, attack_noise_count=20))
        attack = [env for kind, _, _, env in events if kind == "attack"]
        noise = [env for kind, _, _, env in events if kind == "noise"]
        assert len(attack) == 5 and sum(attack) in (2, 3)
        assert len(noise) == 20 and sum(noise) == 10


def test_an_environment_user_is_always_on_their_own_host(environment):
    for kind, user, host, from_env in _who(_plan(100, attack_noise=True)):
        assert from_env and host == HOST_OF[user], (kind, user, host)


def test_the_other_events_draw_from_the_pools_one_event_at_a_time(environment):
    """Reported: the random part used one user and one host for the whole run,
    out of a pool of thirteen. Each event now draws its own — attack and noise
    alike, with or without the environment."""
    from attack_generators import WINDOWS_ATTACK_USERS, WINDOWS_WORKSTATIONS

    for plan in (_plan(0, attack_noise=True, attack_noise_count=20),
                 SenderManager.attack_plan(ATTACK, {"attack_noise": True, "attack_noise_count": 20})):
        events = _who(plan)
        assert not any(env for *_, env in events)
        assert {user for _, user, _, _ in events} <= set(WINDOWS_ATTACK_USERS)
        assert {host for _, _, host, _ in events} <= set(WINDOWS_WORKSTATIONS)
        assert len({user for _, user, _, _ in events}) >= 5, "the run is stuck on a few users"
        assert len({host for _, _, host, _ in events}) >= 5, "the run is stuck on a few hosts"
        noise_users = {user for kind, user, _, _ in events if kind == "noise"}
        assert len(noise_users) >= 5, "the noise does not vary"


def test_a_typed_target_wins_for_every_event(environment):
    for _, user, host, _ in _who(_plan(100, target_user="mallory")):
        assert user == "mallory"
        assert host in HOST_OF.values(), "the host still comes from the environment"


def test_splitting_over_sources_keeps_the_ratio_and_the_person_together(environment, monkeypatch):
    """Sharing the events between sources changes neither the share drawn from
    the environment nor the rule that an account appears on its own host."""
    monkeypatch.setitem(ATTACK_REGISTRY[ATTACK], "data_sources", [
        {"log_type": "windows", "sourcetype": "WinEventLog:Security", "formats": ["xml"]},
        {"log_type": "windows", "sourcetype": "WinEventLog:System", "formats": ["xml"]},
    ])
    plan = _plan(50, attack_events_count=40, attack_sources=[
        {"log_type": "windows", "sourcetype": "WinEventLog:Security"},
        {"log_type": "windows", "sourcetype": "WinEventLog:System"}])

    assert len(plan) == 40, "two sources must not double the attack"
    assert len({e.source for e in plan}) == 2

    people = _who(plan)
    assert sum(env for _, _, _, env in people) == 20, "the 50% share is over the total"
    for _kind, user, host, from_environment in people:
        if from_environment:
            assert host == HOST_OF[user], "a linked account left its own host"


def test_an_unlinked_account_may_appear_but_a_linked_one_stays_home():
    environment = {
        "entities": {"dest": [{"value": "WKS-A", "linked": {"user": ["alice"]}},
                              {"value": "KIOSK", "linked": {}}]},
        "unlinked": {"user": ["temp"]},
    }
    rng = _random.Random(3)
    for _ in range(200):
        identity = draw_environment_identity(environment, rng=rng)
        if identity["dest"] == "WKS-A":
            assert identity["user"] == "alice"
        else:
            assert identity["user"] == "temp", "alice was shown on a machine that is not hers"


@pytest.mark.parametrize("count, ratio", [(5, 50), (7, 33), (1, 50), (20, 50), (0, 50)])
def test_environment_flags_round_only_the_fraction(count, ratio):
    exact = count * ratio / 100
    for seed in range(50):
        chosen = sum(environment_flags(count, ratio, rng=_random.Random(seed)))
        assert int(exact) <= chosen <= int(exact) + 1


def test_the_form_lists_the_detection_entities_with_their_counts(environment):
    rows = {r["field"]: r for r in environment.get_attack_impact(ATTACK_REGISTRY[ATTACK]["ai_fields"])}
    assert set(rows) == set(ATTACK_REGISTRY[ATTACK]["detection"]["entities"])
    assert rows["dest"]["count"] == 3 and rows["user"]["count"] == 3


# ── registry coherence ──────────────────────────────────────────────────────

def test_declared_sources_exist_and_their_formats_are_real():
    from ta_registry import get_sourcetype_info, get_ta
    for key, definition in ATTACK_REGISTRY.items():
        for source in definition.get("data_sources", []):
            assert get_sourcetype_info(source["log_type"], source["sourcetype"]), (key, source)
            ta = get_ta(source["log_type"])
            by_format = ta.get("hec_default_sourcetype_by_render_format")
            if by_format:
                assert set(source["formats"]) <= set(by_format), (key, source["formats"], by_format)
            else:
                # One rendering, so one format: its name is only a label.
                assert len(source["formats"]) == 1, (key, source["formats"])


def test_the_api_offers_formats_as_sourcetypes_and_leaves_other_attacks_alone():
    types = AttackGeneratorFactory.get_available_attack_types()
    formats = types[ATTACK]["data_sources"][0]["formats"]
    assert [f["sourcetype"] for f in formats] == ["XmlWinEventLog", "WinEventLog"]
    assert types[ATTACK]["noise"] is True
    assert types["ssh_bruteforce"]["data_sources"] == [], "a legacy attack changed shape"
