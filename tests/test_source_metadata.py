"""The `source` metadata stamped on each event comes from the TA registry.

The Windows add-on is the reason this exists: it normalises every channel onto
one sourcetype (XmlWinEventLog) and classifies almost entirely on `source=`, so
an event without the right source is indexed but never parsed. See
references/windows-sourcetypes.md.

Two properties matter and are asserted here:
  - a TA that documents a source emits exactly that value, per channel;
  - a TA that documents none emits no `source` at all. The absence is the
    information — inventing a plausible value would silently change how Splunk
    indexes it.
"""

import json
import time

import pytest

import hec_sender
from configuration_manager import ConfigurationManager
from log_senders import MultiSourceLogGenerator, SenderManager
from network_pools import NetworkPoolManager
from syslog_destinations import SyslogDestinationsManager


class FakeResponse:
    status_code = 200
    text = "ok"


class CapturingSession:
    """Collects HEC payloads instead of reaching the network."""

    def __init__(self):
        self.payloads = []
        self.headers = {}

    def post(self, url, data=None, **kwargs):
        self.payloads.append(json.loads(data))
        return FakeResponse()

    def close(self):
        pass


@pytest.fixture
def captured_hec(monkeypatch):
    """Every HECSender built during the test writes into one shared list."""
    sessions = []
    original_init = hec_sender.HECSender.__init__

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        session = CapturingSession()
        sessions.append(session)
        self.session = session

    monkeypatch.setattr(hec_sender.HECSender, "__init__", patched_init)
    return sessions


def _manager(tmp_path, log_type, options):
    """A SenderManager holding one HEC sender for `log_type`, not yet started."""
    config_mgr = ConfigurationManager(config_file=str(tmp_path / "configurations.json"))
    config_id = config_mgr.create_configuration(
        name="lab", url="https://splunk.invalid", port=8088, token="tok"
    )

    manager = SenderManager(
        config_file=str(tmp_path / "senders_config.json"),
        config_mgr=config_mgr,
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog_destinations.json")
        ),
    )
    manager._network_pool_mgr = NetworkPoolManager(
        config_file=str(tmp_path / "network_pools.json")
    )

    sender_id = manager.create_sender(
        name=f"{log_type} sender",
        log_type=log_type,
        destination=None,
        frequency=20000,
        options=options,
        destination_type="configuration",
        configuration_id=config_id,
    )
    return manager, sender_id


def _payloads(manager, sender_id, captured_hec, seconds=0.5):
    manager.start_sender(sender_id)
    time.sleep(seconds)
    manager.stop_sender(sender_id)
    payloads = [p for session in captured_hec for p in session.payloads]
    assert payloads, "the sender produced no event at all"
    return payloads


# ── registry → wire, per channel ────────────────────────────────────────────

@pytest.mark.parametrize("render_format, prefix", [
    ("xml", "XmlWinEventLog"),
    ("classic", "WinEventLog"),
    (None, "XmlWinEventLog"),   # absent: the emitter defaults to xml
], ids=["xml", "classic", "absent"])
def test_windows_wire_metadata_follows_render_format(
    tmp_path, captured_hec, render_format, prefix
):
    """render_format picks the body shape, and the TA reads both metadata off it.

    A bare sourcetype plus the channel in `source` is what eventtypes.conf needs
    (:13 matches the bare sourcetype, :29 matches source per channel), and the
    classic/xml forms must never be mixed.
    """
    options = {"sources": ["Security", "System", "Application"],
               "use_assets_identities": False}
    if render_format is not None:
        options["render_format"] = render_format
    manager, sender_id = _manager(tmp_path, "windows", options)

    payloads = _payloads(manager, sender_id, captured_hec)

    pairs = {(p.get("sourcetype"), p.get("source")) for p in payloads}
    assert pairs == {
        (prefix, f"{prefix}:Security"),
        (prefix, f"{prefix}:System"),
        (prefix, f"{prefix}:Application"),
    }, f"unexpected sourcetype/source pairs: {sorted(pairs)}"

    # The body really is the shape that pair claims.
    body = payloads[0]["event"]
    if prefix == "XmlWinEventLog":
        assert body.lstrip().startswith("<Event"), body[:80]
    else:
        assert "Log Name:" in body[:200], body[:200]


def test_active_directory_stamps_the_security_channel(tmp_path, captured_hec):
    """AD is an umbrella TA: every category lands on the Security channel."""
    manager, sender_id = _manager(tmp_path, "active_directory", {
        "event_categories": ["account_management", "authentication"],
        "use_assets_identities": False,
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("source") for p in payloads} == {"XmlWinEventLog:Security"}
    assert {p.get("sourcetype") for p in payloads} == {"XmlWinEventLog"}


@pytest.mark.parametrize("log_type, options, expected_sourcetype", [
    ("paloalto", {"log_types": ["traffic", "threat", "system"]}, "pan:log"),
])
def test_a_ta_without_a_documented_source_emits_none(
    tmp_path, captured_hec, log_type, options, expected_sourcetype
):
    """No registry value means no `source` key — not a guessed one."""
    manager, sender_id = _manager(
        tmp_path, log_type, {**options, "use_assets_identities": False}
    )

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("sourcetype") for p in payloads} == {expected_sourcetype}
    offenders = [p["source"] for p in payloads if "source" in p]
    assert not offenders, f"{log_type} invented a source: {set(offenders)}"


# ── per-sourcetype override ─────────────────────────────────────────────────

def test_an_override_wins_over_the_registry(tmp_path, captured_hec):
    """hec_source_map replaces the registry value for that sourcetype only."""
    manager, sender_id = _manager(tmp_path, "windows", {
        "sources": ["Security", "System"],
        "render_format": "xml",
        "use_assets_identities": False,
        "hec_source_map": {"WinEventLog:Security": "WinEventLog:Security"},
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    sources = {p.get("source") for p in payloads}
    assert "WinEventLog:Security" in sources, "the override was not applied"
    assert "XmlWinEventLog:Security" not in sources, "the registry value leaked through"
    assert "XmlWinEventLog:System" in sources, "the untouched channel was altered"


def test_an_override_for_a_ta_with_no_registry_value(tmp_path, captured_hec):
    """A TA with nothing documented still honours an explicit override."""
    manager, sender_id = _manager(tmp_path, "paloalto", {
        "log_types": ["traffic"],
        "use_assets_identities": False,
        "hec_source_map": {"pan:traffic": "pan-vm-01"},
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("source") for p in payloads} == {"pan-vm-01"}


# ── the registry is the only source of truth ────────────────────────────────

def test_the_registry_is_the_only_place_the_values_live():
    """The wire values must be readable from the registry alone."""
    from ta_registry import get_sourcetype_info, get_ta

    # windows carries both forms, keyed on render_format; the plain key is absent
    # so nothing can read a format-less value by accident.
    assert "hec_default_sourcetype" not in get_ta("windows")
    assert get_ta("windows")["hec_default_sourcetype_by_render_format"] == {
        "xml": "XmlWinEventLog", "classic": "WinEventLog",
    }
    for channel in ("Security", "System", "Application"):
        info = get_sourcetype_info("windows", f"WinEventLog:{channel}")
        assert "hec_source" not in info
        assert info["hec_source_by_render_format"] == {
            "xml": f"XmlWinEventLog:{channel}", "classic": f"WinEventLog:{channel}",
        }

    # active_directory emits XML only, so its two values are fixed.
    assert get_ta("active_directory")["hec_default_sourcetype"] == "XmlWinEventLog"
    ad = get_sourcetype_info("active_directory", "WinEventLog:Security")
    assert ad["hec_source"] == "XmlWinEventLog:Security"
    assert "hec_source_by_render_format" not in ad

    # Absent, not empty: the distinction is what tells the emitter to send nothing.
    for name in ("pan:traffic", "pan:threat", "pan:system"):
        assert "hec_source" not in get_sourcetype_info("paloalto", name)


def test_no_sourcetype_in_the_registry_means_no_source():
    """_registry_source never fabricates a value."""
    assert SenderManager._registry_source("paloalto", "pan:traffic") is None
    assert SenderManager._registry_source("windows", "nope") is None
    assert (SenderManager._registry_source("windows", "WinEventLog:Security", "xml")
            == "XmlWinEventLog:Security")
    assert (SenderManager._registry_source("windows", "WinEventLog:Security", "classic")
            == "WinEventLog:Security")
    # An absent format resolves the way the emitter does, never to nothing.
    assert (SenderManager._registry_source("windows", "WinEventLog:Security")
            == "XmlWinEventLog:Security")


def test_the_two_windows_forms_are_never_mixed():
    """A classic body must not be announced with an XML source, or the reverse."""
    for render_format, prefix in (("xml", "XmlWinEventLog"), ("classic", "WinEventLog")):
        assert (SenderManager._ta_default_sourcetype("windows", render_format)
                == prefix)
        for channel in ("Security", "System", "Application"):
            source = SenderManager._registry_source(
                "windows", f"WinEventLog:{channel}", render_format)
            assert source == f"{prefix}:{channel}"
            # The sourcetype is bare and the source carries the channel.
            assert ":" not in prefix
            assert source.startswith(prefix + ":")


def test_syslog_viability_is_declared_not_inferred():
    """Windows-family TAs are flagged non-viable over syslog; others default True.

    Sysmon joins them: it is a Windows event channel, collected by the same
    forwarder, and its add-on ships no syslog path at all.
    """
    from ta_registry import get_ta, list_tas

    windows_family = ("windows", "active_directory", "sysmon")
    for ta_name in windows_family:
        assert get_ta(ta_name)["syslog_viable"] is False, ta_name
    for ta_name in list_tas():
        if ta_name in windows_family:
            continue
        assert get_ta(ta_name).get("syslog_viable", True) is True, ta_name


# ── the carrier ─────────────────────────────────────────────────────────────

def test_multi_source_generator_keeps_the_triples_aligned():
    """Each generator index maps to its own sourcetype *and* source."""
    class Stub:
        def __init__(self, line):
            self._line = line

        def generate(self):
            return self._line

    gen = MultiSourceLogGenerator(
        [Stub("a"), Stub("b")],
        ["WinEventLog:Security", "WinEventLog:System"],
        ["XmlWinEventLog:Security", "XmlWinEventLog:System"],
    )

    seen = {gen.generate_with_metadata() for _ in range(200)}
    assert seen == {
        ("a", "WinEventLog:Security", "XmlWinEventLog:Security"),
        ("b", "WinEventLog:System", "XmlWinEventLog:System"),
    }, f"misaligned triples: {sorted(seen)}"

    # The narrower accessors stay usable for callers that predate `source`.
    line, sourcetype = gen.generate_with_sourcetype()
    assert (line, sourcetype) in {("a", "WinEventLog:Security"), ("b", "WinEventLog:System")}
    assert gen.generate() in {"a", "b"}


def test_missing_metadata_lists_default_to_none():
    """A generator list with no metadata yields no sourcetype and no source."""
    class Stub:
        def generate(self):
            return "x"

    gen = MultiSourceLogGenerator([Stub()])
    assert gen.generate_with_metadata() == ("x", None, None)


def test_the_js_harness_delivery_fixture_matches_the_registry():
    """The form renders `delivery` as the API describes it, so the fixture the
    DOM tests run against must say exactly what the backend would."""
    import json
    import pathlib
    from syslog_framing import delivery_description
    from ta_registry import get_ta

    harness = (pathlib.Path(__file__).resolve().parents[1]
               / "tests-js" / "harness.mjs").read_text()
    for ta_name in ("paloalto", "windows", "ssh"):
        expected = json.dumps(delivery_description(get_ta(ta_name)), separators=(",", ":"))
        assert f"delivery: {expected}," in harness, (
            f"the JS harness no longer describes {ta_name}'s delivery formats as the API does")


def test_the_js_harness_fixture_still_matches_the_registry():
    """tests-js/ spells the wire metadata out; keep it honest against the registry.

    The harness stands in for /api/ta-registry, so its fixture is the contract
    the DOM tests assert. A drift there would let the JS suite pass against
    values the app no longer sends.
    """
    import pathlib

    from ta_registry import get_sourcetype_info, get_ta

    harness = (pathlib.Path(__file__).resolve().parents[1]
               / "tests-js" / "harness.mjs").read_text()

    for channel in ("Security", "System", "Application"):
        by_format = get_sourcetype_info(
            "windows", f"WinEventLog:{channel}")["hec_source_by_render_format"]
        for fmt, value in by_format.items():
            assert f"{fmt}: '{value}'" in harness, (
                f"the JS harness no longer carries {fmt} -> {value}"
            )

    win_fixture = harness.split("windows:")[1].split("ssh:")[0]
    by_format = get_ta("windows")["hec_default_sourcetype_by_render_format"]
    for fmt, value in by_format.items():
        assert f"{fmt}: '{value}'" in win_fixture, (
            f"the JS harness no longer carries {fmt} -> {value}"
        )
    assert "syslog_viable: false" in harness, (
        "the harness must keep windows marked non-viable over syslog"
    )


# ── multi_instance without a registry bridge ────────────────────────────────

def test_every_multi_instance_ta_can_name_its_sourcetype():
    """multi_instance and "bridged" are independent, and both paths must resolve.

    A generator that splits per category either declares the sourcetype each one
    produces, or the TA has a single sourcetype to fall through to. Neither, and
    the events leave unnamed for Splunk to guess — which is what apache and
    zscaler did until they were bridged. No add-on is in that state today; this
    keeps the next one from arriving in it.
    """
    from log_generators import REGISTRY
    from ta_registry import get_ta

    for log_type, generator in REGISTRY.items():
        config = generator.SOURCETYPE_CONFIG
        if not config.get("multi_instance"):
            continue
        sources = generator.METADATA.get("sources", [])
        bridged = bool(sources) and all(s.get("sourcetype") for s in sources)
        umbrella = SenderManager._single_registry_sourcetype(log_type)

        assert bridged or umbrella, (
            f"{log_type} splits per category, names none of them, and its TA "
            f"declares {len(get_ta(log_type)['sourcetypes'])} sourcetypes — "
            f"its events would go out unnamed"
        )


def test_a_bridged_multi_instance_ta_keeps_its_per_source_names(tmp_path, captured_hec):
    """The umbrella fallback must not flatten a TA that does name each source."""
    manager, sender_id = _manager(tmp_path, "windows", {
        "sources": ["Security", "System"],
        "render_format": "xml",
        "use_assets_identities": False,
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("source") for p in payloads} == {
        "XmlWinEventLog:Security", "XmlWinEventLog:System",
    }, "the per-channel bridge was lost to the umbrella fallback"


def test_ssh_stamps_the_monitored_path(tmp_path, captured_hec):
    """A file-monitored source: the path is the metadata, and it reaches the wire."""
    manager, sender_id = _manager(tmp_path, "ssh", {
        "event_categories": ["auth_success", "auth_failed"],
        "use_assets_identities": False,
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("sourcetype") for p in payloads} == {"linux_secure"}
    assert {p.get("source") for p in payloads} == {"/var/log/secure"}


def test_a_sender_can_override_the_monitored_path(tmp_path, captured_hec):
    """Debian writes auth.log; the per-sourcetype row in the form covers that."""
    manager, sender_id = _manager(tmp_path, "ssh", {
        "event_categories": ["auth_success"],
        "use_assets_identities": False,
        "hec_source_map": {"linux_secure": "/var/log/auth.log"},
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("source") for p in payloads} == {"/var/log/auth.log"}


def test_zscaler_splits_into_the_two_feeds_the_add_on_declares(tmp_path, captured_hec):
    """`zscaler` matched no stanza; the NSS feeds are zscalernss-<feed>.

    Each category now declares the sourcetype it produces, so the emitter splits
    them instead of putting one invented name on both.
    """
    manager, sender_id = _manager(tmp_path, "zscaler", {
        "log_types": ["web", "tunnel"],
        "use_assets_identities": False,
    })

    payloads = _payloads(manager, sender_id, captured_hec)

    assert {p.get("sourcetype") for p in payloads} == {
        "zscalernss-web", "zscalernss-tunnel",
    }
    # And each carries the body of its own feed.
    for payload in payloads:
        if payload["sourcetype"] == "zscalernss-tunnel":
            assert "Recordtype=" in payload["event"], payload["event"][:80]
        else:
            assert "urlcategory=" in payload["event"], payload["event"][:80]
