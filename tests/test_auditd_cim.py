"""auditd events must satisfy Splunk_TA_nix, read from disk rather than restated.

`auditd` is the supported sourcetype in TA 10.3.4: it is what the add-on's own
rlog.sh input produces, and the only one carrying eventtypes and tags.
`linux_audit` looks better furnished but sits inside props.conf's
BEGIN/END "SCRIPTED INPUT CONTENT IMPORTED FROM TA-deployment-apps" block, kept
only so data from a withdrawn add-on still parses.

See references/auditd-sourcetypes.md.
"""

import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info

TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_nix" / "default"
LOOKUPS = TA.parent / "lookups"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="Splunk_TA_nix not present in TAs/"
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
            for name in ("eventtypes", "tags", "props", "inputs")}


@pytest.fixture(scope="module")
def lines():
    config = REGISTRY["auditd"].SOURCETYPE_CONFIG
    generator = REGISTRY["auditd"](**{config["param_key"]: config["defaults"]})
    return [generator.generate() for _ in range(2000)]


# ── the sourcetype choice is defensible, not a preference ───────────────────

def test_linux_audit_is_inside_the_retired_block():
    """The reason we do not target it. If the add-on moves it out, revisit."""
    text = (TA / "props.conf").read_text(errors="replace").splitlines()
    begin = next(i for i, l in enumerate(text)
                 if "BEGIN SCRIPTED INPUT CONTENT" in l)
    end = next(i for i, l in enumerate(text)
               if "END SCRIPTED INPUT CONTENT" in l)
    positions = {name: i for i, l in enumerate(text)
                 for name in ("[linux_audit]", "[auditd]") if l.strip() == name}

    assert begin < positions["[linux_audit]"] < end, (
        "linux_audit is no longer in the retired block — reconsider the choice"
    )
    assert not (begin < positions["[auditd]"] < end), "auditd became legacy"


def test_the_add_on_still_produces_this_sourcetype_itself(conf):
    """rlog.sh is what makes `auditd` the live path, and ausearch -i the format."""
    script = conf["inputs"].get("script://./bin/rlog.sh", {})
    assert script.get("sourcetype") == "auditd"
    assert script.get("source") == "auditd", (
        "the source we emit is copied from the add-on's own input"
    )
    assert "ausearch -i" in (TA.parent / "bin" / "rlog.sh").read_text()


# ── the registry mirrors what the add-on grants ─────────────────────────────

def test_declared_eventtypes_and_tags_match_the_add_on(conf):
    info = get_sourcetype_info("auditd", "auditd")
    granted = set()
    for eventtype in info["eventtypes"]:
        assert eventtype in conf["eventtypes"], f"{eventtype} not in eventtypes.conf"
        stanza = conf["tags"].get(f"eventtype={eventtype}", {})
        granted |= {k for k, v in stanza.items() if v == "enabled"}

    assert set(info["tags"]) == granted, (
        f"registry says {sorted(info['tags'])}, add-on grants {sorted(granted)}"
    )


def test_no_datamodel_is_claimed_without_a_tag_that_grants_one():
    """`os unix resource file modify` grants no CIM datamodel on its own.

    Claiming one here would be wishful: Change needs `change`, which only a
    local eventtype adds. The registry records what the add-on does.
    """
    assert get_sourcetype_info("auditd", "auditd")["datamodels"] == []


def test_the_source_is_declared_because_an_eventtype_keys_on_it(conf):
    """[auditd_modify] matches `source=auditd`, not the sourcetype."""
    assert "source=auditd" in conf["eventtypes"]["auditd_modify"]["search"]
    assert get_sourcetype_info("auditd", "auditd")["hec_source"] == "auditd"


# ── the generated format is the one the stanza expects ──────────────────────

TIMESTAMP = re.compile(r"msg=audit\((\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\.\d{3}):(\d+)\)")


def test_every_line_carries_an_interpreted_timestamp(conf, lines):
    """TIME_PREFIX=audit\\( with MAX_TIMESTAMP_LOOKAHEAD=23 — the width of the
    interpreted form, not of a raw epoch."""
    assert conf["props"]["auditd"]["MAX_TIMESTAMP_LOOKAHEAD"] == "23"

    for line in lines:
        match = TIMESTAMP.search(line)
        assert match, f"no interpreted timestamp: {line[:90]}"
        assert len(match.group(1)) == 23, match.group(1)


def test_values_are_unquoted_as_ausearch_i_renders_them(lines):
    """`-i` strips the quotes; only the msg='...' envelope keeps them."""
    for line in lines:
        without_envelope = re.sub(r"msg='[^']*'", "", line)
        assert '"' not in without_envelope, f"quoted value survived: {line[:90]}"


def test_records_are_single_line(conf, lines):
    assert conf["props"]["auditd"]["LINE_BREAKER"] == "([\\r\\n]+)"
    assert all("\n" not in line for line in lines)


def _to_python_regex(pattern):
    """Splunk writes named groups PCRE-style, `(?<name>...)`; Python wants `(?P<`."""
    return re.sub(r"\(\?<(?![=!])", "(?P<", pattern)


def test_the_two_explicit_extractions_fire(conf, lines):
    """[auditd] declares only these two; everything else rides on auto-KV."""
    execve = re.compile(_to_python_regex(conf["props"]["auditd"]["EXTRACT-execve_command"]))
    matched = [line for line in lines if execve.search(line)]
    assert matched, "no EXECVE record matches the add-on's extraction"
    assert all("type=EXECVE" in line for line in matched)


def test_auto_kv_can_reach_the_fields_we_map(lines):
    """No KV_MODE is set, so key=value pairs extract on their own — but only if
    the generator actually writes them that way."""
    for field in ("hostname", "acct", "addr"):
        assert any(re.search(rf"\b{field}=\S+", line) for line in lines), field


# ── the operations the action lookup recognises ─────────────────────────────

def _known_ops():
    rows = (LOOKUPS / "nix_linux_audit_action_object_category.csv").read_text()
    return {line.split(",")[0] for line in rows.splitlines()[1:] if line.strip()}


def test_account_operations_stay_inside_the_lookup(lines):
    """An op outside the lookup yields no action and no object_category, so the
    event stays out of Change however it is tagged."""
    known = _known_ops()
    emitted = {m.group(1) for line in lines
               if (m := re.search(r"\bop=([\w:-]+)", line))}
    account_ops = {op for op in emitted if not op.startswith("PAM:")}

    assert account_ops, "no account-management operation was produced"
    assert account_ops <= known, f"unrecognised: {sorted(account_ops - known)}"


def test_authentication_carries_the_verdict_the_add_on_reads(lines):
    """EVAL-op turns op=PAM:authentication into res, which the lookup maps."""
    auth = [line for line in lines if "type=USER_AUTH" in line]
    assert auth, "no USER_AUTH record"
    for line in auth:
        assert "op=PAM:authentication" in line
        assert re.search(r"\bres=(success|failed)\b", line), line[:90]


def test_a_path_record_exists_for_the_modify_tag(lines):
    """[auditd_modify] needs a PATH record; without one the tag never appears."""
    assert any(line.startswith("type=PATH ") for line in lines)


# ── A&I ─────────────────────────────────────────────────────────────────────

def test_the_generator_can_be_pinned_to_an_entity():
    """An audit line carries a host and an account, so volet B applies."""
    from log_generators.ai_entity import AIEntityMixin
    generator = REGISTRY["auditd"]()
    assert isinstance(generator, AIEntityMixin)

    generator._ai_entity = None
    generator.generate()
    assert generator._ai_entity is None or generator._ai_entity == {}, (
        "no environment was injected, so no entity should be current"
    )
