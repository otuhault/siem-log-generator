r"""PowerView Domain Reconnaissance, against the seventeen rules it trips.

Unlike every other attack here there is no datamodel to simulate: the PowerShell
channel reaches none, and all 121 published detections on this data source are
raw searches over ScriptBlockText. So the check is the searches themselves —
each one's leading filter, parsed into a boolean AST and evaluated against what
the generator emits. The oracle and its limits live in test_powershell_4104.py.

What makes this attack worth having is the breadth: PowerView is one module, so
one operator session is one attack, and a full sweep of it satisfies seventeen
separate published rules. They are named below rather than counted, so a
detection that stops firing says which one.

The noise is the same administrator asking the same questions with Microsoft's
ActiveDirectory module. That is a real near miss — `Get-ADTrust` next to
`Get-DomainTrust` — and a sharp one, because the AD module is itself covered:
`Get-ADUser`, `Get-ADComputer` and `Get-ADGroup` each have a rule, and
`Get-ADDomainController` trips the anchor detection by containing the string
`get-addomain`. The set that ships was chosen by measurement, and this file
re-measures it.
"""

import collections

import pytest

import log_senders
from attack_generators import (ATTACK_REGISTRY, POWERVIEW_NOISE, POWERVIEW_RECON,
                               AttackGeneratorFactory, attack_destinations)
from log_senders import SenderManager
from test_powershell_4104 import CATCH_ALL, extract, fired_by, needs_ta

ATTACK = "powershell_powerview_domain_recon"
DEFINITION = ATTACK_REGISTRY[ATTACK]

#: Every published rule a full sweep satisfies, by file. Spelled out so a rule
#: that drops out is named, not just missing from a count.
EXPECTED_DETECTIONS = {
    "powershell_domain_enumeration.yml",
    "powershell_4104_hunting.yml",
    "get_domainuser_with_powershell_script_block.yml",
    "getdomaingroup_with_powershell_script_block.yml",
    "getdomaincomputer_with_powershell_script_block.yml",
    "getdomaincontroller_with_powershell_script_block.yml",
    "get_domainpolicy_with_powershell_script_block.yml",
    "get_domaintrust_with_powershell_script_block.yml",
    "windows_forest_discovery_with_getforestdomain.yml",
    "windows_find_domain_organizational_units_with_getdomainou.yml",
    "windows_find_interesting_acl_with_findinterestingdomainacl.yml",
    "windows_get_local_admin_with_findlocaladminaccess.yml",
    "windows_powerview_unconstrained_delegation_discovery.yml",
    "windows_powerview_constrained_delegation_discovery.yml",
    "windows_powerview_spn_discovery.yml",
    "windows_powerview_kerberos_service_ticket_request.yml",
    "windows_file_share_discovery_with_powerview.yml",
}


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, options, "configuration")


def _rendered(plan):
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    out = []
    for event in plan:
        generator.use_identity(event.identity)
        out.append((event.kind,
                    generator.generate() if event.kind == "attack"
                    else generator.generate_noise()))
    return out


def _script(line):
    return extract(line)["ScriptBlockText"]


# ── the seventeen ───────────────────────────────────────────────────────────

@needs_ta
def test_a_full_sweep_satisfies_every_rule_it_claims():
    fired = set()
    for kind, line in _rendered(_plan(attack_events_count=len(POWERVIEW_RECON))):
        assert kind == "attack"
        fired |= set(fired_by(_script(line)))

    missing = EXPECTED_DETECTIONS - fired
    extra = fired - EXPECTED_DETECTIONS - {CATCH_ALL}
    assert not missing, f"no longer fired: {sorted(missing)}"
    assert not extra, f"fired but never claimed: {sorted(extra)}"


def test_the_claim_in_the_description_matches_the_list():
    """17 is written in the catalog text, so it has to stay true."""
    assert len(EXPECTED_DETECTIONS) == 17
    assert "17 published detections" in DEFINITION["description"]


@needs_ta
def test_every_recon_line_earns_its_place():
    """A line that fires nothing is padding; each one is here for a rule."""
    silent = [text for text in POWERVIEW_RECON if not fired_by(text)]
    assert not silent, silent


def test_the_sequence_is_dealt_in_order_and_wraps():
    """`plan_identities` deals the sweep in order; the plan then shuffles it.

    SenderManager.attack_plan shuffles twice on purpose — which device records a
    probe should not follow the order the identities were planned in — so the
    order is only observable one level down. What survives the shuffle, and is
    what the count hint promises, is *which* cmdlets a short run covers: the
    first N of the sequence.
    """
    attacks, _noise = DEFINITION["generator_class"].plan_identities(
        DEFINITION, {}, 4, 0, None)
    assert [a["script_block_text"] for a in attacks] == POWERVIEW_RECON[:4]

    over = len(POWERVIEW_RECON) + 3
    attacks, _noise = DEFINITION["generator_class"].plan_identities(
        DEFINITION, {}, over, 0, None)
    assert [a["script_block_text"] for a in attacks] == \
        POWERVIEW_RECON + POWERVIEW_RECON[:3]


@needs_ta
def test_a_short_run_covers_the_start_of_the_sweep():
    """The promise in count_hint, checked through the plan the sender uses."""
    sent = {_script(line) for _kind, line in _rendered(_plan(attack_events_count=5))}
    assert sent == set(POWERVIEW_RECON[:5])


# ── the noise ───────────────────────────────────────────────────────────────

@needs_ta
def test_no_noise_event_fires_any_published_rule():
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True,
                              attack_noise_count=120) if e.kind == "noise"]
    offenders = {}
    for _kind, line in _rendered(noise):
        text = _script(line)
        hits = fired_by(text)
        if hits:
            offenders[text[:70]] = hits
    assert not offenders, offenders


@needs_ta
def test_the_noise_is_the_same_question_asked_with_the_supported_tool():
    """Not unrelated traffic: it pairs with the attack, cmdlet for cmdlet."""
    pairs = [("Get-ADTrust", "Get-DomainTrust"),
             ("Get-ADOrganizationalUnit", "Get-DomainOU")]
    for benign, hostile in pairs:
        assert any(line.startswith(benign) for line in POWERVIEW_NOISE), benign
        assert any(hostile in line for line in POWERVIEW_RECON), hostile
        assert fired_by(next(l for l in POWERVIEW_NOISE if l.startswith(benign))) == []


@needs_ta
def test_the_cmdlets_that_look_safe_but_are_not_stayed_out():
    """Measured, not assumed — these three are covered by rules of their own."""
    for covered in ("Get-ADUser -Filter *",
                    "Get-ADComputer -Filter * -Properties OperatingSystem",
                    "Get-ADGroup -Filter * | Select-Object Name",
                    "Get-ADDomainController -Filter * | Select-Object HostName"):
        assert fired_by(covered), f"{covered} no longer fires — the noise could include it"
        assert not any(line.startswith(covered.split(" ")[0] + " ")
                       for line in POWERVIEW_NOISE), covered


# ── one operator, one console ───────────────────────────────────────────────

def test_the_endpoint_and_the_account_hold_for_the_whole_session():
    plan = _plan(attack_events_count=12, attack_noise=True, attack_noise_count=12)
    assert len({e.identity["dest"] for e in plan}) == 1
    assert len({e.identity["user"] for e in plan}) == 1


@needs_ta
def test_the_typed_values_reach_the_event():
    from log_generators.powershell import user_sid

    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "custom", "value": "WKS-LAB-07"},
        "user": {"mode": "custom", "value": "svc_legacy"}})
    for _kind, line in _rendered(plan):
        fields = extract(line)
        assert fields["dest"] == "WKS-LAB-07"
        # The channel carries no user name, only a SID derived from the account.
        assert fields["user_id"] == user_sid("svc_legacy")
        assert "svc_legacy" not in line


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("laptop", "endpoint", nt_host="WKS-ENV-01")
    env.create_account("env.user", account_type="standard")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_values_are_used(environment):
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "ai"}, "user": {"mode": "ai"}})
    assert {e.identity["dest"] for e in plan} == {"WKS-ENV-01"}
    assert {e.identity["user"] for e in plan} == {"env.user"}


# ── the shape of the events ─────────────────────────────────────────────────

@needs_ta
def test_every_event_is_an_interactive_invocation():
    """Path empty, one part of one — the shape Splunk's own datasets carry.

    The other half of a real PowerView signal is the module source compiled on
    import, ~41 parts of ~19 KB each with the .ps1 in Path. That is multi-line
    and is deliberately not reproduced; see the generator's docstring.
    """
    for _kind, line in _rendered(_plan(attack_events_count=16, attack_noise=True,
                                       attack_noise_count=16)):
        fields = extract(line)
        assert fields["Path"] == ""
        assert (fields["MessageNumber"], fields["MessageTotal"]) == ("1", "1")
        assert fields["EventCode"] == "4104"
        assert "\n" not in line


@needs_ta
def test_the_anchor_detections_grouped_fields_are_all_present():
    """No fillnull is not the issue here — the anchor has one — but the 13
    fields it groups by should still all arrive, or the row is thin."""
    for _kind, line in _rendered(_plan(attack_events_count=16)):
        fields = extract(line)
        missing = [name for name in DEFINITION["detection"]["by"]
                   if name != "Path" and not fields.get(name)]
        assert not missing, (missing, line[:160])


# ── the registry ────────────────────────────────────────────────────────────

def test_the_api_declares_one_powershell_source_and_no_datamodel():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["datamodel"] == "", "this channel reaches no CIM datamodel"
    assert [s["sourcetype"] for s in DEFINITION["data_sources"]] == \
        ["XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"]
    assert attack_destinations(DEFINITION) == ["file", "configuration"]


def test_the_default_event_count_covers_the_whole_sweep():
    assert DEFINITION["defaults"]["events"] == len(POWERVIEW_RECON)


@needs_ta
def test_a_standalone_render_is_still_a_powerview_cmdlet():
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    for _ in range(20):
        assert fired_by(_script(generator.generate()))
