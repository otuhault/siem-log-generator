/**
 * Every source's category group, driven off the real SOURCETYPE_CONFIG.
 *
 * The rest of this suite names the sources it exercises — sysmon, windows, ssh,
 * paloalto — and stands them up from a fixture in harness.mjs. That is right for
 * behaviour tests, and wrong as a guard: a source added without its checkbox
 * group fails nothing, because it is in no fixture and no test names it. Sysmon
 * shipped that way once and PowerShell repeated it.
 *
 * So these read the real module and the real markup instead. SOURCETYPE_CONFIG
 * is imported, not mirrored, and index.html is the one the app serves, so every
 * registered source is covered the moment it is registered — no list to update.
 *
 * Two honest limits, both covered elsewhere rather than here.
 *
 * These iterate SOURCETYPE_CONFIG, so they cannot notice an entry that is
 * *missing* from it — the thing being checked is also the thing driving the
 * loop. That case belongs to tests/test_ui_wiring.py, which drives off the
 * Python REGISTRY instead and fails when a registered source has no entry here.
 * Removing the powershell entry was tried both ways to confirm the split: the
 * JS suite stays green, the Python one fails.
 *
 * And `wireLogTypeListener` in harness.mjs *reproduces* app.js's #logType
 * listener rather than running it, so the second block proves the config and
 * the markup agree, not that app.js does the same thing with them. Only a
 * browser settles that.
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { createHarness, isVisible } from './harness.mjs';

describe('every source in SOURCETYPE_CONFIG has its group in the shipped markup', () => {
  let h;
  let config;
  let allIds;

  before(async () => {
    h = await createHarness({});
    config = h.sourcetypeConfig.SOURCETYPE_CONFIG;
    allIds = h.sourcetypeConfig.getAllFormGroupIds();
  });
  after(() => h.close());

  it('covers at least the sources that have shipped so far', () => {
    // A floor, not a list: it fails if the import silently yields nothing,
    // which would make every assertion below pass over an empty object.
    assert.ok(Object.keys(config).length >= 10,
      `SOURCETYPE_CONFIG yielded ${Object.keys(config).length} entries`);
  });

  it('names a form group that exists in index.html', () => {
    for (const [logType, entry] of Object.entries(config)) {
      assert.ok(entry.formGroups?.length, `${logType} declares no formGroups`);
      for (const id of entry.formGroups) {
        assert.ok(h.document.getElementById(id),
          `${logType}: index.html has no #${id}`);
        assert.ok(allIds.includes(id),
          `${logType}: #${id} is missing from getAllFormGroupIds(), so it is ` +
          'never hidden when another source is picked');
      }
    }
  });

  it('names a checkbox group with at least one checkbox behind it', () => {
    for (const [logType, entry] of Object.entries(config)) {
      assert.ok(entry.checkboxGroup, `${logType} declares no checkboxGroup`);
      const boxes = h.document.querySelectorAll(
        `input[type=checkbox][name="${entry.checkboxGroup}"]`);
      assert.ok(boxes.length > 0,
        `${logType}: no checkbox is named ${entry.checkboxGroup}, so the group ` +
        'renders empty and the source offers no choice');
    }
  });

  it('leaves no stale id behind in getAllFormGroupIds()', () => {
    for (const id of allIds) {
      assert.ok(h.document.getElementById(id),
        `getAllFormGroupIds() returns #${id}, which index.html no longer has`);
    }
  });
});

describe('picking any source shows its own group and hides the others', () => {
  let h;
  let config;

  before(async () => {
    h = await createHarness({});
    config = h.sourcetypeConfig.SOURCETYPE_CONFIG;
    // Stand every registered source up as a selectable log type, so the sweep
    // does not depend on the harness fixture naming it.
    h.state.setLogTypes(Object.fromEntries(Object.keys(config).map(
      (logType) => [logType, { name: logType, description: '', sources: [] }])));
  });
  after(() => h.close());

  it('shows the group for each one in turn', () => {
    const select = h.document.getElementById('logType');
    for (const [logType, entry] of Object.entries(config)) {
      select.value = logType;
      select.dispatchEvent(new h.window.Event('change', { bubbles: true }));

      for (const id of entry.formGroups) {
        assert.ok(isVisible(h.document, id),
          `picking ${logType} left #${id} hidden`);
      }
      const others = Object.entries(config)
        .filter(([other]) => other !== logType)
        .flatMap(([, e]) => e.formGroups)
        .filter((id) => !entry.formGroups.includes(id));
      for (const id of others) {
        assert.ok(!isVisible(h.document, id),
          `picking ${logType} left another source's #${id} on screen`);
      }
    }
  });
});
