/**
 * A sender always keeps at least one Splunk sourcetype.
 *
 * Reported from the UI: unticking the visible FortiGate sourcetypes looked like
 * unticking them all. Two were still ticked above the fold, so the real bug was
 * the scroll height — but it exposed a second one that nothing guarded. Nothing
 * stopped the last tick from coming off, and a sender with no sourcetype has
 * nothing to send: the preview empties, the HEC rows vanish, and the form looks
 * merely unfinished instead of wrong.
 *
 * These drive off the registry fixture rather than naming technologies, so a
 * technology added to it is covered without touching this file. The floor is a
 * property of the selector, not of Palo Alto.
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import {
  REGISTRY, checkedSourcetypes, createHarness, selectTechnology, toggleSourcetype,
} from './harness.mjs';

/** Every fixture technology, so the loop cannot go stale against a hand list. */
const TECHNOLOGIES = Object.keys(REGISTRY);

describe('the sourcetype selector refuses to empty itself', () => {
  let h;

  before(async () => { h = await createHarness({}); });
  after(() => h.close());

  it('has technologies to exercise, including one with several sourcetypes', () => {
    // A floor on the fixture itself: an empty REGISTRY would make every
    // assertion below pass without checking anything.
    assert.ok(TECHNOLOGIES.length >= 2, `only ${TECHNOLOGIES.length} technologies`);
    assert.ok(TECHNOLOGIES.some((t) => REGISTRY[t].sourcetypes.length > 1),
      'no multi-sourcetype technology in the fixture — the untick path is untested');
  });

  for (const technology of TECHNOLOGIES) {
    it(`${technology}: the last sourcetype cannot be unticked`, async () => {
      await selectTechnology(h.document, technology);
      const all = REGISTRY[technology].sourcetypes.map((s) => s.name);
      assert.deepEqual(checkedSourcetypes(h.document), [...all].sort(),
        'a new sender starts with everything ticked');

      // Down to one, the way a user gets there: one click at a time.
      for (const name of all.slice(1)) await toggleSourcetype(h.document, name);
      assert.deepEqual(checkedSourcetypes(h.document), [all[0]]);

      await toggleSourcetype(h.document, all[0]);
      assert.deepEqual(checkedSourcetypes(h.document), [all[0]],
        'the last one came off');

      // And the checkbox itself is back on, not just the module's state — the
      // DOM is what the user looks at.
      const box = h.document.querySelector(
        `input[name="splunk_sourcetypes"][value="${all[0]}"]`);
      assert.equal(box.checked, true);
    });
  }

  it('says why, rather than silently ignoring the click', async () => {
    const multi = TECHNOLOGIES.find((t) => REGISTRY[t].sourcetypes.length > 1);
    await selectTechnology(h.document, multi);
    const all = REGISTRY[multi].sourcetypes.map((s) => s.name);
    for (const name of all.slice(1)) await toggleSourcetype(h.document, name);

    const before = h.document.body.textContent;
    await toggleSourcetype(h.document, all[0]);
    const added = h.document.body.textContent.slice(before.length);
    assert.match(h.document.body.textContent, /at least one sourcetype/i,
      `no notification was raised (body gained ${JSON.stringify(added)})`);
  });

  it('still lets a sourcetype come back after the refusal', async () => {
    // The guard restores `checked`; if it also left the module's set out of
    // step, the next tick would be a no-op and the form would be stuck at one.
    const multi = TECHNOLOGIES.find((t) => REGISTRY[t].sourcetypes.length > 1);
    await selectTechnology(h.document, multi);
    const all = REGISTRY[multi].sourcetypes.map((s) => s.name);
    for (const name of all.slice(1)) await toggleSourcetype(h.document, name);
    await toggleSourcetype(h.document, all[0]);          // refused
    await toggleSourcetype(h.document, all[1]);          // back on
    assert.deepEqual(checkedSourcetypes(h.document), [all[0], all[1]].sort());
  });
});
