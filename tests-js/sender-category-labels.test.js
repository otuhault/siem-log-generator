/**
 * The two lists in the sender form, for every technology the registry declares.
 *
 * Reported from the UI on FortiGate: the ticks offered under "Log category" are
 * not Splunk sourcetypes, and nothing said where each one lands. Both halves are
 * checked here for every technology rather than for the one that was reported —
 * the first version of the badge read a hand-written table and silently labelled
 * five of twelve sources, which is the failure this file exists to catch.
 *
 * Driven off the fixture registry, so a technology added to it is covered with
 * no list to update here. What the fixture cannot settle is whether the registry
 * itself names real Splunk sourcetypes; tests/test_source_metadata.py holds that
 * against the shipped add-ons.
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { REGISTRY, createHarness, isVisible, selectTechnology } from './harness.mjs';

const TECHNOLOGIES = Object.keys(REGISTRY);

describe('what the sender form offers to tick', () => {
  let h;
  let config;

  before(async () => {
    h = await createHarness({});
    config = h.sourcetypeConfig.SOURCETYPE_CONFIG;
  });
  after(() => h.close());

  for (const technology of TECHNOLOGIES) {
    const declared = () => REGISTRY[technology].sourcetypes.map((s) => s.name);

    it(`${technology}: the sourcetype ticks are the registry's sourcetypes`, async () => {
      await selectTechnology(h.document, technology);
      const offered = Array.from(
        h.document.querySelectorAll('#techSourcetypesList input[name="splunk_sourcetypes"]')
      ).map((cb) => cb.value);
      assert.deepEqual(offered.sort(), declared().sort(),
        'the selector must offer the Splunk sourcetypes, nothing else');
    });

    it(`${technology}: every category says which sourcetype it lands in`, async () => {
      await selectTechnology(h.document, technology);
      const slot = h.document.getElementById('sourcetypeCategoriesSlot');
      const ticks = `input[type="checkbox"][name="${config[technology]?.checkboxGroup}"]`;

      // Only the groups the form actually shows. Where the sourcetype selector
      // already expresses the choice — Palo Alto, Windows, one sourcetype per
      // category — the group stays hidden and there is nothing to label.
      const groups = (config[technology]?.formGroups || [])
        .filter((id) => isVisible(h.document, id))
        .map((id) => h.document.getElementById(id))
        .filter((group) => group.querySelector(ticks));
      if (!groups.length) return;

      for (const group of groups) {
        assert.equal(group.parentElement, slot,
          `#${group.id} was not moved under the sourcetypes it refines`);
        assert.ok(group.compareDocumentPosition(
          h.document.getElementById('techSourcetypesList')
        ) & h.window.Node.DOCUMENT_POSITION_PRECEDING,
          `#${group.id} reads before the sourcetype list instead of after it`);

        // Two shapes, and a technology gets exactly one of them: a line for the
        // whole group where every category lands in the same sourcetype, a
        // badge per row where they split.
        const shared = group.querySelector('.sender-cat-lands');
        const badges = Array.from(group.querySelectorAll('.sender-cat-stype'));
        assert.ok(shared || badges.length,
          `${technology}: nothing says where the categories land`);
        assert.ok(!(shared && badges.length),
          `${technology}: labelled twice — a shared line and per-row badges`);

        const named = shared
          ? [shared.querySelector('code').textContent]
          : badges.map((b) => b.textContent);
        for (const name of named) {
          assert.ok(declared().includes(name),
            `${technology} is labelled ${name}, which the registry does not ` +
            `declare: ${declared().join(', ')}`);
        }

        // Per-row labelling has to reach every row: a badge on three of eleven
        // reads as if the other eight went nowhere.
        if (!shared) {
          for (const box of group.querySelectorAll(ticks)) {
            assert.ok(box.parentElement.querySelector('.sender-cat-stype'),
              `${technology}/${box.value} carries no sourcetype badge`);
          }
        }
      }
    });
  }

  it('labels a technology whose generator never names the pairing', async () => {
    // ssh declares one sourcetype and its categories name none. The label comes
    // from the registry having a single place to put them — the case the
    // hand-written table missed for five of the twelve shipped sources.
    const [named] = REGISTRY.ssh.sourcetypes.map((s) => s.name);
    await selectTechnology(h.document, 'ssh');
    const group = h.document.getElementById(config.ssh.formGroups[0]);
    const shared = group.querySelector('.sender-cat-lands');
    assert.ok(shared, 'ssh categories say nothing about where they land');
    assert.equal(shared.querySelector('code').textContent, named);
  });

  it('says it once where every category lands in the same place', async () => {
    // Sysmon: eight events, one sourcetype. A badge per row repeats a
    // fifty-character string eight times and adds nothing to the list above.
    await selectTechnology(h.document, 'sysmon');
    const group = h.document.getElementById(config.sysmon.formGroups[0]);
    assert.equal(group.querySelectorAll('.sender-cat-stype').length, 0);
    assert.equal(group.querySelectorAll('.sender-cat-lands').length, 1);
  });

  it('does not leave a stale badge behind when the technology changes', async () => {
    await selectTechnology(h.document, 'paloalto');
    await selectTechnology(h.document, 'sysmon');
    const stale = Array.from(
      h.document.querySelectorAll('#sourcetypeCategoriesSlot .sender-cat-stype'))
      .map((b) => b.textContent)
      .filter((name) => name.startsWith('pan:'));
    assert.deepEqual(stale, [], 'Palo Alto badges survived the switch to Sysmon');
  });
});
