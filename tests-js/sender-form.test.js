/**
 * Regression tests for the sender form's DOM wiring.
 *
 * Two bugs have already shipped from hydrateFromSender(); both were invisible
 * to the Python suite because they live entirely in the browser. Each test
 * below is pinned to the commit that fixed it and fails on that commit's
 * parent — see tests-js/README.md for how to verify that.
 */

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import {
  checkedCategories,
  checkedSourcetypes,
  createHarness,
  isVisible,
  selectTechnology,
  settle,
  submittedValue,
} from './harness.mjs';

/** Senders the fetch stub will serve to editSender(). */
const SENDERS = {
  'win-1': {
    id: 'win-1', name: 'Windows sender', log_type: 'windows',
    destination_type: 'file', destination: '/tmp/win.log',
    frequency: 10, enabled: false, logs_generated: 0,
    options: { sources: ['Security'] },
    attack_status: null,
  },
  'pan-1': {
    id: 'pan-1', name: 'Palo sender', log_type: 'paloalto',
    destination_type: 'file', destination: '/tmp/pan.log',
    frequency: 20, enabled: false, logs_generated: 0,
    options: { log_types: ['traffic'] },
    attack_status: null,
  },
  'pan-2': {
    id: 'pan-2', name: 'Palo sender 2', log_type: 'paloalto',
    destination_type: 'file', destination: '/tmp/pan2.log',
    frequency: 30, enabled: false, logs_generated: 0,
    options: { log_types: ['threat', 'system'] },
    attack_status: null,
  },
};

let harness;

/** Drive the real editSender() from senders.js, as the ✎ button does. */
async function editSender(id) {
  await harness.senders.editSender(id);
  await settle();
}

before(async () => {
  harness = await createHarness({ senders: SENDERS });
});

after(() => harness && harness.close());

beforeEach(() => {
  // Same call the "+ Add Sender" button makes: clears carried-over state.
  harness.senderForm.resetSenderForm();
});

describe('8b2aac5 — hidden log_type must not lag one edit behind', () => {
  it('windows then paloalto: renderFormatGroup is hidden on the second edit', async () => {
    await editSender('win-1');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), true,
      'Render Format belongs to Windows and should show there');

    await editSender('pan-1');
    assert.equal(harness.document.getElementById('logType').value, 'paloalto');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), false,
      'Render Format is Windows-only and leaked onto Palo Alto');
  });

  it('paloalto then windows: the Palo Alto group does not leak onto Windows', async () => {
    await editSender('pan-1');
    assert.equal(harness.document.getElementById('logType').value, 'paloalto');

    await editSender('win-1');
    assert.equal(harness.document.getElementById('logType').value, 'windows');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), true,
      'Render Format should be back for Windows');
    assert.equal(isVisible(harness.document, 'paloaltoLogTypesGroup'), false,
      'the Palo Alto category group leaked onto Windows');
  });
});

describe('8b2aac5 — the submitted log_type matches the sender being edited', () => {
  it('does not submit the previously edited technology', async () => {
    await editSender('win-1');
    assert.equal(submittedValue(harness.document, 'log_type'), 'windows');

    await editSender('pan-1');
    assert.equal(submittedValue(harness.document, 'log_type'), 'paloalto',
      'the form would have persisted the previous sender technology');
  });

  it('stays correct across three consecutive edits', async () => {
    for (const [id, expected] of [
      ['pan-1', 'paloalto'], ['win-1', 'windows'],
      ['pan-2', 'paloalto'], ['win-1', 'windows'],
    ]) {
      await editSender(id);
      assert.equal(submittedValue(harness.document, 'log_type'), expected,
        `editing ${id} submitted the wrong log_type`);
    }
  });
});

describe('5b3c335 — editing hydrates the form from the sender being opened', () => {
  it('fills the Technology dropdown instead of leaving the placeholder', async () => {
    await editSender('pan-1');
    assert.equal(harness.document.getElementById('techSelect').value, 'paloalto',
      'the Technology select stayed on its placeholder');
  });

  it('does not carry the previous sender sourcetypes over', async () => {
    await editSender('pan-1');
    assert.deepEqual(checkedSourcetypes(harness.document), ['pan:traffic']);

    await editSender('pan-2');
    assert.deepEqual(checkedSourcetypes(harness.document), ['pan:system', 'pan:threat'],
      'sender pan-1 sourcetypes leaked into the edit of pan-2');
  });

  it('mirrors the selection onto the generator checkboxes it submits', async () => {
    await editSender('pan-2');
    assert.deepEqual(checkedCategories(harness.document, 'paloalto_log_types'),
      ['system', 'threat'],
      'the legacy category boxes disagree with the edited sender');
  });
});

describe('creation flow — Render Format is Windows-only', () => {
  for (const [ta, expected] of [['paloalto', false], ['windows', true], ['ssh', false]]) {
    it(`${ta}: renderFormatGroup ${expected ? 'visible' : 'hidden'}`, async () => {
      await selectTechnology(harness.document, ta);
      assert.equal(isVisible(harness.document, 'renderFormatGroup'), expected);
    });
  }

  it('switching away from Windows hides it again', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), true);
    await selectTechnology(harness.document, 'ssh');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), false);
  });
});

describe('no state leaks across create → edit → create', () => {
  it('a fresh creation does not inherit the edited sender', async () => {
    await selectTechnology(harness.document, 'windows');
    await editSender('pan-1');
    assert.equal(submittedValue(harness.document, 'log_type'), 'paloalto');

    harness.senderForm.resetSenderForm();
    assert.equal(harness.document.getElementById('techSelect').value, '',
      'the Technology select kept the edited sender');
    assert.equal(submittedValue(harness.document, 'log_type'), '',
      'log_type survived the reset');
    assert.deepEqual(checkedSourcetypes(harness.document), [],
      'sourcetype ticks survived the reset');

    await selectTechnology(harness.document, 'ssh');
    assert.equal(submittedValue(harness.document, 'log_type'), 'ssh');
    assert.equal(isVisible(harness.document, 'renderFormatGroup'), false);
  });

  it('editing after a creation does not inherit the creation', async () => {
    await selectTechnology(harness.document, 'paloalto');
    assert.deepEqual(checkedSourcetypes(harness.document),
      ['pan:system', 'pan:threat', 'pan:traffic'], 'creation ticks everything');

    await editSender('pan-1');
    assert.deepEqual(checkedSourcetypes(harness.document), ['pan:traffic'],
      'the in-progress creation leaked into the edit');
  });
});

describe('an umbrella TA keeps its category group', () => {
  let h;

  before(async () => { h = await createHarness({ senders: SENDERS }); });
  after(() => h.close());

  it('shows the categories when one sourcetype covers several of them', async () => {
    // Sysmon puts five event IDs on one sourcetype, so ticking the sourcetype
    // says nothing about which you want. The group hid anyway, every category
    // came back checked, and a sender emitted all five event IDs with no way
    // to narrow it.
    await selectTechnology(h.document, 'sysmon');
    assert.deepEqual(checkedSourcetypes(h.document),
      ['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational']);
    assert.ok(isVisible(h.document, 'sysmonEventCategoriesGroup'),
      'the only control that can pick an event ID is hidden');
  });

  it('still hides it when the sourcetype selector says the same thing', async () => {
    // Windows is one sourcetype per category, so the group would be a duplicate.
    await selectTechnology(h.document, 'windows');
    assert.ok(!isVisible(h.document, 'windowsSourcesGroup'),
      'a 1:1 mapping should leave the sourcetype selector to it');
  });
});
