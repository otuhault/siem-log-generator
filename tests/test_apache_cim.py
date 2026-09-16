"""Apache against Splunk_TA_apache, read from disk rather than restated.

The add-on knows five access shapes and only three reach the Web datamodel:
[access_log_event] lists apache:access, :kv and :json — :combined is
deliberately not in it. So the shape that extracts perfectly reaches nothing,
and the shape that reaches Web needs a LogFormat the common log format is not.
"""

import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info, get_ta

TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_apache" / "default"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="Splunk_TA_apache not present in TAs/"
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
            out[cur].setdefault(key.strip(), value.strip())
    return out


@pytest.fixture(scope="module")
def conf():
    return {name: _stanzas(TA / f"{name}.conf")
            for name in ("props", "eventtypes", "tags", "transforms")}


def _lines(log_type, n=200):
    generator = REGISTRY["apache"](log_type=log_type)
    return [generator.generate() for _ in range(n)]


def _to_python(pattern):
    """Splunk writes named groups `(?<name>...)`; Python wants `(?P<`."""
    return re.sub(r"\(\?<(?![=!])", "(?P<", pattern)


# ── which shapes reach the Web datamodel ────────────────────────────────────

def test_combined_is_not_in_the_web_eventtype(conf):
    """The finding that shaped the mapping: it parses, and is tagged by nothing."""
    search = conf["eventtypes"]["access_log_event"]["search"]

    assert "apache:access:combined" not in search
    for sourcetype in ("apache:access", "apache:access:kv", "apache:access:json"):
        assert sourcetype in search, f"{sourcetype} left the web eventtype"


def test_the_registry_claims_web_only_where_the_add_on_grants_it():
    assert get_sourcetype_info("apache", "apache:access:kv")["datamodels"] == ["Web"]
    assert get_sourcetype_info("apache", "apache:access:combined")["datamodels"] == []
    # `error` is not a CIM datamodel tag; Web needs `web`.
    assert get_sourcetype_info("apache", "apache:error")["datamodels"] == []
    assert get_sourcetype_info("apache", "apache:error")["tags"] == ["error"]


def test_the_web_tag_really_comes_from_that_eventtype(conf):
    stanza = conf["tags"].get("eventtype=access_log_event", {})
    assert {k for k, v in stanza.items() if v == "enabled"} == {"web"}


# ── the bodies match the stanzas they are sent as ───────────────────────────

def test_the_key_value_shape_is_what_the_reroute_recognises(conf):
    """[apache_kv_events] keys on a leading `time=<digits>`."""
    assert conf["transforms"]["apache_kv_events"]["REGEX"] == r"^time=\d+"
    assert all(re.match(r"^time=\d+ ", line) for line in _lines("access"))


def test_the_key_value_shape_carries_the_fields_the_add_on_aliases(conf):
    """KV_MODE=auto_escaped extracts them, then FIELDALIAS renames them."""
    props = conf["props"]["apache:access:kv"]
    assert props["KV_MODE"] == "auto_escaped"
    assert props["FIELDALIAS-src"] == "client as src"
    assert props["FIELDALIAS-dest"] == "server as dest"

    for field in ("client", "server", "dest_port", "status",
                  "bytes_in", "bytes_out", "response_time_microseconds",
                  "uri_path", "http_user_agent"):
        assert all(re.search(rf"(?:^|\s){field}=", line) for line in _lines("access")), field


def test_the_combined_shape_still_extracts(conf):
    pattern = re.compile(_to_python(
        conf["props"]["apache:access:combined"]["EXTRACT-apache_access_combined"]))
    assert all(pattern.search(line) for line in _lines("combined"))


def test_the_error_shape_still_extracts(conf):
    for key in ("EXTRACT-message", "EXTRACT-timestamp", "EXTRACT-apache_pid",
                "EXTRACT-apache_src"):
        pattern = re.compile(_to_python(conf["props"]["apache:error"][key]))
        assert all(pattern.search(line) for line in _lines("error")), key


def test_the_common_log_format_is_no_longer_produced(conf):
    """It had no stanza: [apache:access] wants a vhost and a port it lacks.

    Keeping it would have meant a category whose every event parsed to nothing.
    """
    pattern = re.compile(_to_python(conf["props"]["apache:access"]["EXTRACT-apache_access"]))
    common = re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[[^\]]+\] "[A-Z]+ \S+ HTTP/\d\.\d" \d+ \d+$')

    for line in _lines("access"):
        assert not common.match(line), "the common log format came back"
    # And what we do emit is not what that stanza wants either — which is why it
    # is sent as :kv, not as :access.
    assert not any(pattern.search(line) for line in _lines("access"))


# ── the bridge ──────────────────────────────────────────────────────────────

def test_each_category_declares_the_sourcetype_it_produces():
    sources = REGISTRY["apache"].METADATA["sources"]
    assert {s["id"]: s.get("sourcetype") for s in sources} == {
        "access": "apache:access:kv",
        "error": "apache:error",
        "combined": "apache:access:combined",
    }


def test_a_sender_covering_every_category_emits_three_sourcetypes(tmp_path):
    from log_senders import SenderManager
    assert SenderManager._bridge_sourcetype(
        REGISTRY["apache"].METADATA["sources"], "access") == "apache:access:kv"
    assert SenderManager._bridge_sourcetype(
        REGISTRY["apache"].METADATA["sources"], "error") == "apache:error"
