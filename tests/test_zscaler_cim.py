"""Zscaler events must satisfy TA-Zscaler_CIM, read from disk rather than restated.

The add-on declares eleven sourcetypes and none of them is `zscaler`. NSS feeds
land on `zscalernss-<feed>`, and the two we generate are the web proxy and the
tunnel — the same class of mistake as ssh's `syslog`: a name that looks right and
matches no stanza.

The web feed carries three conditional eventtypes, so what an event reaches
depends on what it contains, not only on its sourcetype.
"""

import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info, get_ta

TA = Path(__file__).resolve().parents[1] / "TAs" / "TA-Zscaler_CIM" / "default"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="TA-Zscaler_CIM not present in TAs/"
)


def _stanzas(path):
    out, cur = {}, None
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            out[cur] = {}
        elif cur and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            out[cur][key.strip()] = value.strip()
    return out


@pytest.fixture(scope="module")
def conf():
    return {name: _stanzas(TA / f"{name}.conf")
            for name in ("props", "eventtypes", "tags")}


def _web(n=3000):
    generator = REGISTRY["zscaler"](log_type="web")
    return [generator.generate() for _ in range(n)]


# ── the sourcetype names are the add-on's, not ours ─────────────────────────

def test_the_declared_sourcetypes_exist_in_the_add_on(conf):
    for sourcetype in (s["name"] for s in get_ta("zscaler")["sourcetypes"]):
        assert sourcetype in conf["props"], f"{sourcetype} is not in props.conf"


def test_the_old_name_never_existed(conf):
    """Guard the finding: `zscaler` matches no stanza, so nothing parsed it."""
    assert "zscaler" not in conf["props"]


def test_each_category_declares_the_sourcetype_it_produces():
    """Without the bridge the emitter cannot split one sender into two feeds."""
    sources = REGISTRY["zscaler"].METADATA["sources"]
    assert {s["id"]: s.get("sourcetype") for s in sources} == {
        "web": "zscalernss-web",
        "tunnel": "zscalernss-tunnel",
    }


# ── the registry mirrors what the add-on grants ─────────────────────────────

def _tags_of(conf, eventtype):
    stanza = conf["tags"].get(f"eventtype={eventtype}", {})
    return {k for k, v in stanza.items() if v == "enabled"}


def test_web_eventtypes_and_tags_match_the_add_on(conf):
    info = get_sourcetype_info("zscaler", "zscalernss-web")
    granted = set()
    for eventtype in info["eventtypes"]:
        assert eventtype in conf["eventtypes"], f"{eventtype} is gone"
        granted |= _tags_of(conf, eventtype)

    assert set(info["tags"]) == granted, (
        f"registry says {sorted(info['tags'])}, add-on grants {sorted(granted)}"
    )


def test_the_tunnel_feed_claims_no_datamodel(conf):
    """No eventtype anywhere matches it, so it reaches none — say so."""
    for stanza in conf["eventtypes"].values():
        assert "zscalernss-tunnel" not in stanza.get("search", "")

    info = get_sourcetype_info("zscaler", "zscalernss-tunnel")
    assert info["datamodels"] == []
    assert info["eventtypes"] == []


def test_each_condition_names_the_field_the_add_on_keys_on(conf):
    """The registry's conditions must describe the add-on's actual searches."""
    searches = {name: stanza.get("search", "")
                for name, stanza in conf["eventtypes"].items()}

    assert 'ruletype="DLP"' in searches["Zscaler_Proxy_DLP"]
    assert 'threatname!="None"' in searches["Zscaler_Proxy_Malware"]


# ── generated events reach those eventtypes ─────────────────────────────────

def test_every_web_event_reaches_the_general_eventtype():
    """[Zscaler_Proxy_General] matches the sourcetype alone, so all of them."""
    assert all("urlcategory=" in line for line in _web(200))


def test_the_conditional_eventtypes_fire_without_swamping_the_feed():
    """A proxy sees overwhelmingly clean traffic.

    Before weighting, five transactions in six carried a threat and four in five
    a DLP verdict — that is a malware feed, not a proxy log, and every detection
    built on it would fire constantly.
    """
    lines = _web()
    malware = sum(1 for l in lines if re.search(r"threatname=(?!None\b)", l)) / len(lines)
    dlp = sum(1 for l in lines if re.search(r"\bruletype=DLP\b", l)) / len(lines)

    assert 0.02 <= malware <= 0.30, f"threat share is {malware:.1%}"
    assert 0.01 <= dlp <= 0.20, f"DLP share is {dlp:.1%}"


def test_ruletype_is_emitted_and_consistent_with_the_event():
    """It decides the DLP eventtype, and was absent until now."""
    values = {m.group(1) for line in _web(1000)
              if (m := re.search(r"ruletype=([^\t]*)", line))}
    assert values <= {"DLP", "Malware", "URL Filtering"}, values
    assert "DLP" in values

    for line in _web(400):
        rule = re.search(r"ruletype=([^\t]*)", line).group(1)
        engine = re.search(r"dlpengine=([^\t]*)", line).group(1)
        if rule == "DLP":
            assert engine != "None", "DLP verdict with no engine"
        elif engine != "None":
            pytest.fail("an engine matched but the verdict is not DLP")


# ── the fields the add-on aliases ───────────────────────────────────────────

@pytest.mark.parametrize("raw, alias", [
    ("ClientIP", "src"), ("ClientIP", "src_ip"), ("user", "src_user"),
])
def test_the_aliased_fields_are_present(conf, raw, alias):
    aliases = " ".join(v for k, v in conf["props"]["zscalernss-web"].items()
                       if k.startswith("FIELDALIAS"))
    assert f"{raw} AS {alias}" in aliases, f"{raw} AS {alias} is gone from the add-on"
    assert any(re.search(rf"\b{raw}=\S+", line) for line in _web(200)), raw


def test_registry_fields_only_name_what_a_and_i_can_supply():
    from environment_manager import ACCOUNT_TYPES, ENTITY_TYPES

    entity_fields = {"name", "type", "ip", "nt_host", "mac", "fqdn", "os"}
    account_fields = {"username", "email"}

    for sourcetype in (s["name"] for s in get_ta("zscaler")["sourcetypes"]):
        for field in get_sourcetype_info("zscaler", sourcetype)["fields"]:
            source = field["ai_source"]
            options = source.get("options", [source])
            for option in options:
                if option["type"] == "entity":
                    assert option["entity_type"] in ENTITY_TYPES
                    assert option["entity_field"] in entity_fields
                elif option["type"] == "account":
                    assert option["account_type"] in ACCOUNT_TYPES
                    assert option["account_field"] in account_fields
                else:
                    assert option["type"] == "network_pool", option
