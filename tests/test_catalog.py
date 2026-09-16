"""The Catalog tab lists what the generator can produce, read off the registries.

These tests hold the one promise that makes a catalog worth having: it cannot
say something a sender would not do. Every entry is compared with the registry
that owns it rather than with a restated expectation.
"""

import re
from pathlib import Path

import pytest

from attack_generators import ATTACK_REGISTRY
from catalog import build_catalog
from log_generators import REGISTRY
from ta_registry import get_ta


@pytest.fixture(scope="module")
def catalog():
    return build_catalog()


def test_every_generator_and_every_attack_is_listed_once(catalog):
    assert sorted(s["key"] for s in catalog["sources"]) == sorted(REGISTRY)
    assert sorted(a["key"] for a in catalog["attacks"]) == sorted(ATTACK_REGISTRY)


def test_sourcetypes_and_datamodels_are_the_registry_s(catalog):
    for source in catalog["sources"]:
        ta = get_ta(source["key"])
        assert [st["name"] for st in source["sourcetypes"]] == \
            [st["name"] for st in ta["sourcetypes"]], source["key"]
        for listed, declared in zip(source["sourcetypes"], ta["sourcetypes"]):
            assert listed["datamodels"] == declared.get("datamodels", []), listed["name"]


def test_a_source_s_attacks_are_the_ones_that_target_it(catalog):
    """An attack with declared data sources is listed under each of them."""
    def sent_as(attack):
        declared = {s["log_type"] for s in attack.get("data_sources") or []}
        return declared or {attack.get("log_type")}

    for source in catalog["sources"]:
        expected = sorted(k for k, a in ATTACK_REGISTRY.items() if source["key"] in sent_as(a))
        assert source["attacks"] == expected, source["key"]

    by_key = {s["key"]: s for s in catalog["sources"]}
    for log_type in ("paloalto", "fortigate", "cisco_asa"):
        assert "paloalto_horizontal_port_scan" in by_key[log_type]["attacks"], log_type


def test_every_attack_points_at_a_listed_source(catalog):
    listed = {s["key"] for s in catalog["sources"]}
    for attack in catalog["attacks"]:
        assert attack["source"] in listed, attack["key"]


#: The SC4S source page for each technology it parses, confirmed to resolve and
#: to assign the sourcetype the source targets (splunk.github.io, 2026-09-15).
SC4S_PAGES = {
    "paloalto": "vendor/PaloaltoNetworks/panos/",     # pan:log …
    "cisco_asa": "vendor/Cisco/cisco_asa/",           # cisco:asa
    "cisco_ios": "vendor/Cisco/cisco_ios/",           # cisco:ios
    "fortigate": "vendor/Fortinet/fortios/",          # fgt_* / fortigate_* by option
    "zscaler": "vendor/Zscaler/nss/",                 # zscalernss-web …
}
#: Syslog can carry these, but SC4S would not file them as the add-on's own
#: sourcetype — a *nix daemon lands under nix:syslog, and Apache has no page at
#: all — so the badge would promise something that does not happen.
NOT_SC4S = {"ssh", "auditd", "apache"}


def test_only_a_source_sc4s_actually_parses_is_badged(catalog):
    base = "https://splunk.github.io/splunk-connect-for-syslog/main/sources/"
    for source in catalog["sources"]:
        key, url = source["key"], source["sc4s_url"]
        if key in SC4S_PAGES:
            assert url == base + SC4S_PAGES[key], key
        else:
            assert url is None, f"{key} is badged SC4S compatible without a page"

    # The two halves account for every source, so adding one forces a decision.
    badged = {s["key"] for s in catalog["sources"] if s["sc4s_url"]}
    not_syslog = {k for k in REGISTRY if (get_ta(k) or {}).get("syslog_viable") is False}
    assert badged == set(SC4S_PAGES)
    assert badged | NOT_SC4S | not_syslog == set(REGISTRY)


def test_a_source_syslog_cannot_carry_is_never_badged(catalog):
    for source in catalog["sources"]:
        if (get_ta(source["key"]) or {}).get("syslog_viable") is False:
            assert source["sc4s_url"] is None, source["key"]


# ── the links the catalog offers ────────────────────────────────────────────

#: The Splunkbase app id behind each source, looked up on splunkbase.splunk.com
#: (2026-09-15) and matched to the `label` the add-on declares in its own
#: app.conf. Nothing on disk carries the id, so this table is the second copy
#: that keeps a typo from quietly sending readers to somebody else's add-on.
SPLUNKBASE_APPS = {
    "windows": 742,           # Splunk Add-on for Microsoft Windows
    "active_directory": 742,  # ditto: a domain controller's Security events
    "ssh": 833,               # Splunk Add-on for Unix and Linux
    "auditd": 833,            # ditto
    "cisco_asa": 1620,        # Splunk Add-on for Cisco ASA
    "fortigate": 2846,        # Fortinet FortiGate Add-On for Splunk
    "apache": 3186,           # Splunk Add-on for Apache Web Server
    "zscaler": 3865,          # Zscaler Technical Add-On for Splunk
    "paloalto": 7523,         # Splunk Add-on for Palo Alto Networks — not the
                              # deprecated 2757, which is a different package
    "cisco_ios": 7538,        # Cisco Enterprise Networking Add-on for Splunk
}


def test_every_source_links_to_the_add_on_that_parses_it(catalog):
    """One Splunkbase page per source, so the reader can install what reads it."""
    assert set(SPLUNKBASE_APPS) == set(REGISTRY), "a source was added without its add-on link"
    for source in catalog["sources"]:
        assert source["add_on_url"] == \
            f"https://splunkbase.splunk.com/app/{SPLUNKBASE_APPS[source['key']]}", source["key"]


def test_an_attack_links_only_to_a_real_detection_page(catalog):
    """A research.splunk.com search is not a detection: the SSH attacks are ours."""
    for attack in catalog["attacks"]:
        url = attack["research_url"]
        if not url:
            continue
        assert re.fullmatch(
            r"https://research\.splunk\.com/[a-z_]+/"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/", url), attack["key"]

    ssh = [a for a in catalog["attacks"] if a["key"].startswith("ssh_")]
    assert ssh and all(not a["research_url"] for a in ssh), "the SSH attacks have no detection page"


def test_the_catalog_no_longer_carries_field_behaviours(catalog):
    assert all("behaviors" not in a for a in catalog["attacks"])


def test_the_version_shown_is_the_add_on_actually_on_disk():
    """The registry states the version each source was modelled against.

    It is declared rather than read at run time, because the add-ons are not
    shipped with this application and TAs/ is absent from an installed copy.
    Declared means it can drift, so wherever the add-on *is* present its own
    app.conf settles it.
    """
    tas = Path(__file__).resolve().parents[1] / "TAs"
    checked = []
    for log_type in REGISTRY:
        ta = get_ta(log_type) or {}
        package, claimed = ta.get("add_on_package"), ta.get("add_on_version")
        assert package and claimed, log_type

        app_conf = tas / package / "default" / "app.conf"
        if not app_conf.exists():
            continue
        shipped = re.search(r"(?m)^version\s*=\s*(\S+)", app_conf.read_text(errors="replace")).group(1)
        assert claimed == shipped, f"{log_type}: registry says {claimed}, {package} ships {shipped}"
        checked.append(log_type)

    if tas.exists():
        assert len(checked) == len(REGISTRY), f"not checked against disk: {set(REGISTRY) - set(checked)}"


def test_the_catalog_shows_that_version(catalog):
    for source in catalog["sources"]:
        assert re.fullmatch(r"\d+(\.\d+)+", source["add_on_version"]), source["key"]
    by_key = {s["key"]: s["add_on_version"] for s in catalog["sources"]}
    assert by_key["windows"] == by_key["active_directory"], "one add-on, one version"
    assert by_key["ssh"] == by_key["auditd"]


# ── the data models view ────────────────────────────────────────────────────

def test_a_datamodel_is_listed_only_because_a_sourcetype_grants_it(catalog):
    """Built by inverting the sources, so it cannot claim one nothing reaches."""
    granted = {dm for s in catalog["sources"] for st in s["sourcetypes"]
               for dm in st["datamodels"]}
    assert {d["name"] for d in catalog["datamodels"]} == granted
    assert [d["name"] for d in catalog["datamodels"]] == sorted(granted), "listed A→Z"


def test_each_datamodel_names_exactly_the_sourcetypes_that_reach_it(catalog):
    for entry in catalog["datamodels"]:
        expected = {(s["name"], st["name"]) for s in catalog["sources"]
                    for st in s["sourcetypes"] if entry["name"] in st["datamodels"]}
        assert {(st["source"], st["name"]) for st in entry["sourcetypes"]} == expected, \
            entry["name"]
        assert entry["sources"] == sorted({st["source"] for st in entry["sourcetypes"]})
        # Every sourcetype named here belongs to a source listed on the page.
        keys = {s["key"] for s in catalog["sources"]}
        assert {st["source_key"] for st in entry["sourcetypes"]} <= keys


def test_an_attack_is_listed_under_the_datamodel_it_declares(catalog):
    by_name = {d["name"]: d for d in catalog["datamodels"]}
    for attack in catalog["attacks"]:
        entry = by_name.get(attack["datamodel"])
        if entry is not None:
            assert attack["name"] in entry["attacks"], attack["key"]
    # And nothing is listed that did not declare it.
    for entry in catalog["datamodels"]:
        for name in entry["attacks"]:
            declared = next(a["datamodel"] for a in catalog["attacks"] if a["name"] == name)
            assert declared == entry["name"]


def test_an_attack_on_a_macro_search_is_not_filed_under_a_datamodel(catalog):
    """Some detections read the events themselves; they claim no datamodel and
    must not be invented one to sit under."""
    listed = {name for d in catalog["datamodels"] for name in d["attacks"]}
    for attack in catalog["attacks"]:
        if not attack["datamodel"]:
            assert attack["name"] not in listed, attack["key"]


# ── the mapping the Sourcetypes view absorbed ───────────────────────────────

def test_each_sourcetype_carries_the_mapping_the_registry_records(catalog):
    """Configuration → Sourcetype Mapping read this from /api/ta-registry and
    said the same things the catalog did. One view now, still one source."""
    for source in catalog["sources"]:
        registry = {st["name"]: st for st in (get_ta(source["key"]) or {}).get("sourcetypes", [])}
        for shown in source["sourcetypes"]:
            actual = registry[shown["name"]]
            assert [c["eventtype"] for c in shown["datamodel_conditions"]] == \
                [c.get("eventtype", "") for c in actual.get("datamodel_conditions", [])]
            assert [f["raw_field"] for f in shown["fields"]] == \
                [f["raw_field"] for f in actual.get("fields", [])]
            assert [f["cim_field"] for f in shown["fields"]] == \
                [f["cim_field"] for f in actual.get("fields", [])]
            assert shown["entity_types"] == list(actual.get("entity_types", []))
            assert shown["account_types"] == list(actual.get("account_types", []))


def test_every_field_in_the_registry_says_where_its_value_comes_from(catalog):
    """An undeclared origin is a registry gap, and the view must show it as one.

    All 62 fields declare one today. The catalog passes the declaration straight
    through rather than defaulting a missing one to "random", so a field added
    without an origin surfaces here instead of being quietly labelled.
    """
    for source in catalog["sources"]:
        registry = {st["name"]: st for st in (get_ta(source["key"]) or {}).get("sourcetypes", [])}
        for sourcetype in source["sourcetypes"]:
            actual = {f["raw_field"]: f for f in registry[sourcetype["name"]].get("fields", [])}
            for field in sourcetype["fields"]:
                declared = actual[field["raw_field"]].get("ai_source")
                assert declared, (source["key"], field["raw_field"], "no ai_source declared")
                assert field["ai_source"] == declared, "the catalog substituted an origin"


def test_the_rules_shown_grant_the_datamodels_claimed(catalog):
    """A sourcetype's datamodels are the union of what its rules grant — if the
    two disagreed, the badge and the detail below it would contradict."""
    for source in catalog["sources"]:
        for sourcetype in source["sourcetypes"]:
            if not sourcetype["datamodel_conditions"]:
                continue
            granted = {dm for c in sourcetype["datamodel_conditions"] for dm in c["datamodels"]}
            assert granted == set(sourcetype["datamodels"]), \
                (source["key"], sourcetype["name"])
