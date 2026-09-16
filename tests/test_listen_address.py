"""Choosing where to serve, and refusing a taken port with something to do about it.

Werkzeug only notices a busy port after failing to bind, and says:

    Port 5002 is in use by another program. Either identify and stop that
    program, or start the server with a different port.

Neither half helps much. "Identify that program" is often impossible as
written — `lsof` shows only the current user's processes, so a port held by
another account reads as "nothing is running on 5002", which is exactly the
state people get stuck in. And "a different port" was not an option this
application offered.

So the check happens before binding, and the message names the holder when one
is visible, says why it might not be when it isn't, and gives the flag.

The address matters more than the port. This application has no authentication
and /api/configurations returns HEC tokens in clear text, so binding every
interface publishes them to whatever shares the network — which is what it did,
from the first commit, with debug=True putting an arbitrary-code console there
too. Loopback is the default now; reaching it from another machine stays
possible through --host, with a warning and without the debugger.
"""

import socket
import subprocess
from pathlib import Path

import pytest

from listen_address import (DEFAULT_HOST, DEFAULT_PORT, HOST_ENV, PORT_ENV,
                            busy_message, describe_lsof, exposure_warning,
                            is_free, is_local, lan_address, parse_host,
                            parse_port, port_holder, resolve)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def taken_port():
    """A port this process holds on the address the app would bind."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind((DEFAULT_HOST, 0))
        held.listen(1)
        yield held.getsockname()[1]


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('0.0.0.0', 0))
        return probe.getsockname()[1]


# ── which port ──────────────────────────────────────────────────────────────

def test_the_default_is_the_one_the_readme_documents():
    assert DEFAULT_PORT == 5002
    assert parse_port([], {}) == 5002


@pytest.mark.parametrize("argv", [["-p", "5005"], ["--port", "5005"], ["--port=5005"]])
def test_the_flag_wins_however_it_is_spelled(argv):
    assert parse_port(argv, {}) == 5005


def test_the_environment_is_used_when_no_flag_is_given():
    assert parse_port([], {PORT_ENV: "5010"}) == 5010
    assert parse_port(["-p", "5005"], {PORT_ENV: "5010"}) == 5005, "the flag outranks it"


def test_other_arguments_are_left_alone():
    """Flask and pytest both pass arguments of their own."""
    assert parse_port(["--port", "5005", "--debug", "-q"], {}) == 5005


@pytest.mark.parametrize("bad", ["0", "65536", "70000", "-1"])
def test_a_port_outside_the_range_is_refused_with_the_range(bad):
    with pytest.raises(SystemExit) as exit_info:
        parse_port(["-p", bad], {})
    assert "between 1 and 65535" in str(exit_info.value)


def test_an_unreadable_environment_value_says_so_rather_than_falling_back():
    """Silently serving on 5002 after being told 'ohno' would be worse."""
    with pytest.raises(SystemExit) as exit_info:
        parse_port([], {PORT_ENV: "ohno"})
    assert PORT_ENV in str(exit_info.value)


# ── is it free ──────────────────────────────────────────────────────────────

def test_a_port_nothing_holds_is_free():
    assert is_free(free_port())


def test_a_port_something_holds_is_not(taken_port):
    assert not is_free(taken_port)


def test_a_wildcard_listener_does_not_block_a_loopback_bind():
    """Surprising, and deliberate: on BSD the specific bind is allowed, and
    Werkzeug would take the port too. Probing 0.0.0.0 instead would refuse a
    port that works."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as wildcard:
        wildcard.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        wildcard.bind(('0.0.0.0', 0))
        wildcard.listen(1)
        port = wildcard.getsockname()[1]
        assert is_free(port, '127.0.0.1'), "loopback is still bindable"
        assert not is_free(port, '0.0.0.0'), "the wildcard itself is not"


def test_resolve_returns_a_free_port_and_refuses_a_taken_one(taken_port):
    port = free_port()
    assert resolve(["-p", str(port)], {}) == (DEFAULT_HOST, port)

    with pytest.raises(SystemExit) as exit_info:
        resolve(["-p", str(taken_port)], {})
    assert f"Port {taken_port} is already in use" in str(exit_info.value)


# ── where it listens ────────────────────────────────────────────────────────

def test_it_answers_only_this_machine_unless_asked_otherwise():
    """The default that matters: no authentication, HEC tokens in the API."""
    assert DEFAULT_HOST == "127.0.0.1"
    assert parse_host([], {}) == "127.0.0.1"
    assert is_local(parse_host([], {}))


@pytest.mark.parametrize("argv", [["-H", "0.0.0.0"], ["--host", "0.0.0.0"],
                                  ["--host=0.0.0.0"]])
def test_the_address_can_be_opened_deliberately(argv):
    assert parse_host(argv, {}) == "0.0.0.0"
    assert not is_local("0.0.0.0")


def test_the_environment_sets_the_address_when_no_flag_does():
    assert parse_host([], {HOST_ENV: "0.0.0.0"}) == "0.0.0.0"
    assert parse_host(["-H", "127.0.0.1"], {HOST_ENV: "0.0.0.0"}) == "127.0.0.1"


@pytest.mark.parametrize("host,local", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True),
    ("0.0.0.0", False), ("192.168.1.60", False), ("", False),
])
def test_what_counts_as_reaching_no_further_than_this_machine(host, local):
    assert is_local(host) is local


def test_host_and_port_are_read_from_the_same_command_line():
    assert resolve(["-H", "127.0.0.1", "-p", str(free_port())], {})[0] == "127.0.0.1"


def test_opening_the_address_warns_and_says_what_is_at_stake():
    warnings_seen = []
    resolve(["-H", "0.0.0.0", "-p", str(free_port())], {}, warn=warnings_seen.append)
    assert len(warnings_seen) == 1
    text = warnings_seen[0]
    assert "reachable from your whole network" in text
    assert "HEC" in text and "no authentication" in text


def test_staying_local_says_nothing():
    """A warning on the normal path is a warning nobody reads."""
    warnings_seen = []
    resolve(["-p", str(free_port())], {}, warn=warnings_seen.append)
    assert warnings_seen == []


def test_the_warning_names_an_address_someone_could_actually_type():
    text = exposure_warning("0.0.0.0", 5002, address="192.168.1.60")
    assert "http://192.168.1.60:5002" in text
    assert "0.0.0.0:5002" not in text, "nobody browses to 0.0.0.0"


def test_the_warning_still_reads_when_the_machine_is_offline():
    text = exposure_warning("0.0.0.0", 5002, address=None) if lan_address() is None \
        else exposure_warning("0.0.0.0", 5002, address="<this machine>")
    assert "reachable from your whole network" in text


def test_the_debugger_is_tied_to_the_address_not_to_debug_mode():
    """app.py must gate the console on is_local, not leave debug=True alone."""
    text = (ROOT / "log-generator" / "app.py").read_text()
    assert "use_debugger=is_local(host)" in text, \
        "the arbitrary-code console is back on whatever address is bound"


def test_the_holder_of_a_port_we_hold_ourselves_is_named(taken_port):
    holder = port_holder(taken_port)
    if holder is None:
        pytest.skip("lsof is not available here")
    assert "PID" in holder
    assert any(part in holder.lower() for part in ("python", "pytest")), holder


def test_nothing_is_reported_for_a_port_nobody_holds():
    assert port_holder(free_port()) is None


# The lsof field set differs between builds, so the parser is exercised against
# output this machine would not necessarily produce.

def test_the_first_listener_is_described_from_lsof_fields():
    assert describe_lsof("p4821\ncPython\nLalice\nn*:5002\n") == \
        "Python (PID 4821) owned by alice"


def test_only_the_first_process_is_named_when_several_hold_the_port():
    """Flask's reloader means two processes. Naming both would be noise."""
    output = "p100\ncPython\nLalice\np101\ncPython\nLalice\n"
    assert describe_lsof(output) == "Python (PID 100) owned by alice"


def test_a_build_that_omits_the_login_name_still_describes_the_process():
    assert describe_lsof("p4821\ncPython\n") == "Python (PID 4821)"


def test_a_build_that_omits_the_command_still_gives_the_pid():
    assert describe_lsof("p4821\n") == "a process (PID 4821)"


@pytest.mark.parametrize("output", ["", "\n", "cPython\nLalice\n", "garbage"])
def test_output_with_no_pid_describes_nothing_rather_than_guessing(output):
    """Without a pid there is nothing actionable, and 'PID None' helps no one."""
    assert describe_lsof(output) is None


# ── what it says ────────────────────────────────────────────────────────────

def test_the_message_names_the_holder_when_there_is_one():
    text = busy_message(5002, "Python (PID 4821) owned by alice")
    assert "Held by: Python (PID 4821) owned by alice" in text
    assert "sudo lsof" not in text, "no need to go looking — we found it"


def test_the_message_explains_an_invisible_holder_rather_than_shrugging():
    """The case that leaves people stuck: nothing shows on the port, yet it is taken."""
    text = busy_message(5002, None)
    assert "belongs to another user" in text
    assert "sudo lsof -nP -iTCP:5002 -sTCP:LISTEN" in text


def test_the_message_always_offers_both_ways_out():
    for holder in ("Python (PID 1)", None):
        text = busy_message(5002, holder)
        assert "./stop.sh" in text
        assert "./start.sh -p 5005" in text, "a concrete port, not a placeholder"


def test_the_suggested_port_moves_with_the_one_that_failed():
    assert "./start.sh -p 9003" in busy_message(9000, None)
    assert "./stop.sh -p 9000" in busy_message(9000, None), "stop needs the flag too"


# ── the launchers ───────────────────────────────────────────────────────────

def run(script, *args):
    return subprocess.run([str(ROOT / script), *args],
                          capture_output=True, text=True, cwd=ROOT, timeout=30)


@pytest.mark.parametrize("script", ["start.sh", "stop.sh"])
def test_both_scripts_document_the_flag(script):
    result = run(script, "--help")
    assert result.returncode == 0
    assert "-p, --port PORT" in result.stdout, script


@pytest.mark.parametrize("script", ["start.sh", "stop.sh"])
@pytest.mark.parametrize("args,expected", [
    (["-p", "abc"], "Not a port number"),
    (["-p", "99999"], "out of range"),
    (["-p"], "needs a port number"),
    (["--nope"], "Unknown option"),
])
def test_both_scripts_refuse_bad_input_the_same_way(script, args, expected):
    result = run(script, *args)
    assert result.returncode == 2, (script, args, result.stdout, result.stderr)
    assert expected in result.stderr, (script, args, result.stderr)


def test_stop_says_so_when_there_is_nothing_to_stop():
    result = run("stop.sh", "-p", str(free_port()))
    assert result.returncode == 0
    assert "Nothing listening" in result.stdout


def test_start_passes_the_port_and_host_through_to_the_app():
    """The flags have to survive the shell, or they would silently do nothing."""
    text = (ROOT / "start.sh").read_text()
    assert 'exec python3 app.py --port "$PORT"' in text
    assert 'exec python3 app.py --port "$PORT" --host "$HOST"' in text


def test_start_documents_the_address_and_what_opening_it_costs():
    text = (ROOT / "start.sh").read_text()
    assert "-H, --host HOST" in text
    assert "HEC tokens in clear text" in text, "the help should say why the default is local"
