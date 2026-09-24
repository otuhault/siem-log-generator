"""Every sub-tab is reachable, and every id in the page is its own.

Assets & Identities spent a while showing an empty list until something was
created: it had moved from a top-level tab to a Configuration sub-tab, its
module kept listening for the old tab, and the sub-tab router carried a comment
saying the module handled it. Nothing failed — the list was just empty.

Configuration → Attacks then failed the same quiet way, for a different reason:
its container was called `attacksContainer`, and so was the senders page's
attacks table. `getElementById` returns the first in document order, which was
the senders one, so the sub-tab sat on "Loading attack types…" for good while
its renderer wrote into a table the two-second poll immediately overwrote. Two
views, one name, no error anywhere — hence the duplicate-id test below.

Read from the shipped files, so a sub-tab added without a route fails here.
"""

import collections
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "log-generator"


def test_no_element_id_is_used_twice():
    """One name, one element. Nothing in the DOM warns when two share an id."""
    html = (APP / "templates" / "index.html").read_text()
    ids = re.findall(r'\sid="([^"]+)"', html)
    assert ids, "no ids found — the markup changed"
    repeated = {name: n for name, n in collections.Counter(ids).items() if n > 1}
    assert not repeated, f"ids used more than once: {repeated}"


def test_every_configuration_subtab_has_a_loader():
    html = (APP / "templates" / "index.html").read_text()
    subtabs = re.findall(r'class="config-subtab-btn[^"]*"\s+data-subtab="([^"]+)"', html)
    assert subtabs, "no Configuration sub-tab found — the markup changed"

    app_js = (APP / "static" / "js" / "app.js").read_text()
    router = re.search(r"function loadConfigSubtab\(sub\)\s*\{(.*?)\n\}", app_js, re.S)
    assert router, "loadConfigSubtab() is gone"
    routed = set(re.findall(r"sub === '([^']+)'\)\s+\S", router.group(1)))

    assert set(subtabs) <= routed, f"sub-tabs with no loader: {sorted(set(subtabs) - routed)}"


def test_the_environment_loader_is_reachable_from_the_router():
    env_js = (APP / "static" / "js" / "modules" / "environment.js").read_text()
    assert "window.loadEnvData = loadEnvData" in env_js
    assert "data-tab === 'environment'" not in env_js and "dataset.tab === 'environment'" not in env_js, (
        "a listener for the removed top-level Environment tab is back")


def test_every_catalog_subtab_has_a_panel_to_show():
    """The Catalog navigates like Configuration: a button per panel, both ways."""
    html = (APP / "templates" / "index.html").read_text()
    buttons = re.findall(r'class="catalog-subtab-btn[^"]*"\s+data-subtab="([^"]+)"', html)
    assert buttons == ["sourcetypes", "datamodels", "attacks"], \
        f"Catalog sub-tabs changed: {buttons}"

    panels = re.findall(r'id="catalog(\w+)Tab" class="catalog-subtab-content', html)
    assert [p.lower() for p in panels] == buttons, \
        f"a Catalog sub-tab has no panel, or a panel has no button: {panels}"

    # Exactly one starts active, or the page opens blank.
    active = re.findall(r'class="catalog-subtab-content active"', html)
    assert len(active) == 1, "the Catalog must open on exactly one sub-tab"


def test_the_catalog_panels_are_the_ones_the_router_switches_to():
    """The router builds the panel id from the button — spelled here, checked there."""
    app_js = (APP / "static" / "js" / "app.js").read_text()
    assert "catalog-subtab-btn" in app_js, "the Catalog sub-tabs are not wired"
    assert "'catalog' + this.dataset.subtab.replace" in app_js, \
        "the Catalog router no longer derives its panel id from the button"


def test_configuration_no_longer_carries_the_catalog_s_views():
    """Sourcetype Mapping described the registry and Attacks duplicated the
    catalog outright; neither was configuration, and both now live there."""
    html = (APP / "templates" / "index.html").read_text()
    subtabs = re.findall(r'class="config-subtab-btn[^"]*"\s+data-subtab="([^"]+)"', html)
    assert "sourcetypes" not in subtabs and "attacks" not in subtabs, \
        f"a catalog view is back under Configuration: {subtabs}"
    for gone in ("sourcetypesContainer", "attacksTab", "logExampleCard"):
        assert gone not in html, f"{gone} outlived the view it belonged to"


def test_nothing_imports_the_modules_those_views_took_with_them():
    js = APP / "static" / "js"
    for dead in ("modules/attacks.js", "modules/sourcetype-mapping.js"):
        assert not (js / dead).exists(), f"{dead} is back"
    for path in js.rglob("*.js"):
        text = path.read_text()
        for dead in ("attacks.js", "sourcetype-mapping.js"):
            assert f"'./{dead}'" not in text and f"'./modules/{dead}'" not in text, \
                f"{path.name} still imports {dead}"


def _js_sourcetype_config():
    """The SOURCETYPE_CONFIG map from sourcetype-config.js, as {log_type: {...}}."""
    js = (APP / "static" / "js" / "modules" / "sourcetype-config.js").read_text()
    body = re.search(r"SOURCETYPE_CONFIG\s*=\s*\{(.*?)\n\};", js, re.S).group(1)
    config = {}
    for entry in re.finditer(
            r"'([^']+)':\s*\{(.*?)\}", body, re.S):
        fields = entry.group(2)
        config[entry.group(1)] = {
            "checkboxGroup": (re.search(r"checkboxGroup:\s*'([^']+)'", fields) or [None, None])[1]
            if re.search(r"checkboxGroup:\s*'([^']+)'", fields) else None,
            "formGroups": re.findall(r"'(\w+Group)'", fields),
        }
    return config


def test_every_source_that_offers_categories_has_them_in_the_form():
    """REGISTRY → sourcetype-config.js → index.html → senders.js, end to end.

    A source can be complete on the Python side, appear in the catalog, and
    still offer the user no way to pick its categories, because the checkboxes
    are markup in index.html rather than rendered from METADATA. Sysmon shipped
    that way once and PowerShell did it again in this session: nothing failed,
    the group simply was not there. Each link below is the one that was missing.
    """
    import sys
    sys.path.insert(0, str(APP))
    from log_generators import REGISTRY

    html = (APP / "templates" / "index.html").read_text()
    senders_js = (APP / "static" / "js" / "modules" / "senders.js").read_text()
    js_config = _js_sourcetype_config()

    offers_choices = {
        log_type: cls.SOURCETYPE_CONFIG for log_type, cls in REGISTRY.items()
        if len(cls.SOURCETYPE_CONFIG.get("defaults") or []) >= 1
        and not cls.SOURCETYPE_CONFIG.get("multi_instance")
    }
    missing = sorted(set(offers_choices) - set(js_config))
    assert not missing, f"no entry in sourcetype-config.js: {missing}"

    for log_type, config in offers_choices.items():
        entry = js_config[log_type]
        group = entry["checkboxGroup"]
        assert group, f"{log_type}: no checkboxGroup declared"

        values = set(re.findall(
            rf'name="{re.escape(group)}"\s+value="([^"]+)"', html))
        assert values == set(config["defaults"]), (
            f"{log_type}: the form offers {sorted(values)}, "
            f"the generator defaults to {sorted(config['defaults'])}")

        for form_group in entry["formGroups"]:
            assert f'id="{form_group}"' in html, \
                f"{log_type}: index.html has no #{form_group}"
            assert f"getElementById('{form_group}')" in senders_js, \
                f"{log_type}: #{form_group} is never hidden when another source is picked"
