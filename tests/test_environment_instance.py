"""What the UI writes to the environment reaches senders and attacks at once.

app.py and log_senders.py each built their own EnvironmentManager. The API wrote
to the first; senders and attacks read the second, loaded once at import. So an
entity or account created in the UI reached no sender and no attack until the
application restarted — and an attack at 50% drew nothing from an environment
that, on screen, plainly had entries.

The test creates the environment through the Flask API after the app is loaded,
which is exactly the order a user follows.
"""

import importlib
import re
import sys

import log_senders
from log_senders import SenderManager


def test_the_api_and_the_senders_share_one_environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager

    monkeypatch.setenv("LOG_GENERATOR_STATE_DIR", str(tmp_path))
    # A fresh instance, so nothing this test creates leaks into the session's.
    monkeypatch.setattr(log_senders, "_env_manager", EnvironmentManager())
    monkeypatch.delitem(sys.modules, "app", raising=False)
    app = importlib.import_module("app")
    try:
        assert app.env_manager is log_senders.environment_manager()

        client = app.app.test_client()
        entity = client.post("/api/entities", json={
            "name": "late", "type": "endpoint", "nt_host": "WKS-CREATED-LATER"}).get_json()
        entity_id = entity.get("entity_id") or entity.get("id")
        client.post("/api/accounts", json={
            "username": "latecomer", "type": "standard", "linked_entity": entity_id})

        plan = SenderManager.attack_plan("windows_tor_client_execution", {
            "use_assets_identities": True, "assets_identities_ratio": 100}, "configuration")
        lines = [event.render() for event in plan]
        assert all("<Computer>WKS-CREATED-LATER</Computer>" in line for line in lines), lines[0][:300]
        assert all(re.search(r"<Data Name='SubjectUserName'>latecomer</Data>", line) for line in lines)
    finally:
        sys.modules.pop("app", None)
