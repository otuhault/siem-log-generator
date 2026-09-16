/**
 * Opening the sender form gives it the page.
 *
 * The form is taller than a laptop viewport in every shape it takes — roughly
 * 650px for a sourcetype sender, 1400px for an attack, against about 780px of
 * screen. There is no arrangement in which it and the list are both usable, and
 * a reader scrolling down through it used to land back in the senders table,
 * which reads as having left the form.
 *
 * So the list goes away while the form is open. Editing used to move the form
 * into the table instead, as a row under the one being edited, which meant the
 * two-second poll had to stop rebuilding the tables entirely or it would
 * destroy the form mid-edit. The form now stays where it is and the tables
 * refresh behind it, so that exception is gone — and these tests hold both
 * halves of that.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { APP_ROOT, createHarness } from './harness.mjs';

const sender = (id, name, extra = {}) => ({
  id, name, log_type: 'paloalto', enabled: false, destination_type: 'file',
  destination: `/tmp/${id}.log`, frequency: 5, logs_generated: 1,
  created_at: '2026-09-01T10:00:00', options: { log_types: ['traffic'] }, ...extra,
});

const SENDERS = {
  a: sender('a', 'alpha'),
  b: sender('b', 'beta', { enabled: true }),
  atk: sender('atk', 'brute force', { log_type: 'ssh_bruteforce', frequency: 1,
    options: { attack_events_count: 100 } }),
};

describe('the sender form takes the page', () => {
  let h;

  const tab = () => h.document.getElementById('sendersTab');
  const card = (name) => h.document.getElementById(`${name}Card`);
  const formCard = () => h.document.getElementById('senderFormCard');
  const isFormOpen = () => tab().classList.contains('form-open');
  const settle = () => new Promise((r) => setTimeout(r, 30));

  beforeEach(async () => {
    h = await createHarness({ senders: SENDERS });
    h.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force', log_type: 'ssh' } });
    h.state.setConfigurations([]);
    h.senders.initSenderGroups();
    await h.senders.loadSenders();
  });

  afterEach(() => h.close());

  // ── the premise ───────────────────────────────────────────────────────────

  it('the stylesheet is what actually hides them, so the class means something', () => {
    // The class is inert on its own. jsdom loads no stylesheet, so the rule is
    // read where it lives: a class set with no rule behind it would pass every
    // other test here and hide nothing in a browser.
    const css = fs.readFileSync(path.join(APP_ROOT, 'static', 'css', 'style.css'), 'utf8');
    const rule = css.match(/#sendersTab\.form-open[^{]*{[^}]*}/);
    assert.ok(rule, 'no .form-open rule in style.css');
    for (const hidden of ['#sendersCard', '#attacksCard', '#addSenderBtn']) {
      assert.ok(rule[0].includes(hidden), `${hidden} is not hidden while the form is open`);
    }
    assert.match(rule[0], /display:\s*none/);
  });

  // ── opening ───────────────────────────────────────────────────────────────

  it('creating a sender hides both lists', () => {
    assert.equal(card('senders').hidden, false);
    h.senders.openSenderForm();
    assert.ok(isFormOpen());
    assert.equal(formCard().style.display, 'block');
  });

  it('editing hides them too, instead of burying the form in the table', async () => {
    await h.senders.editSender('a');
    await settle();
    assert.ok(isFormOpen());
    assert.equal(h.document.querySelectorAll('tr.sender-form-row').length, 0,
      'the form is no longer injected into the table');
    assert.ok(!formCard().closest('table'), 'the form sits outside the list');
  });

  it('starts the reader at the top of the form, not where the list left them', () => {
    h.senders.openSenderForm();
    assert.deepEqual(h.scrolled.to, [{ top: 0, behavior: 'auto' }]);
  });

  // ── the poll behind it ────────────────────────────────────────────────────

  it('the tables still refresh while the form is open', async () => {
    await h.senders.editSender('a');
    await settle();
    const before = h.document.querySelectorAll('#sendersContainer tbody tr').length;
    assert.ok(before > 0, 'the table is built, merely not shown');

    // A sender disappears while the reader is editing another one.
    const fewer = { a: SENDERS.a, atk: SENDERS.atk };
    h.window.fetch = async (url) => ({ ok: true, status: 200, json: async () =>
      (url === '/api/senders' ? Object.values(fewer) : (fewer[url.split('/').pop()] || {})) });
    globalThis.fetch = h.window.fetch;
    await h.senders.loadSenders();

    assert.equal(h.document.querySelectorAll('#sendersContainer tbody tr').length, 1,
      'the rebuild happened — it used to be suppressed for the whole edit');
    assert.ok(isFormOpen(), 'and it did not reopen the list underneath');
  });

  it('a rebuild cannot show the lists again', async () => {
    h.senders.openSenderForm();
    await h.senders.loadSenders();
    // renderGroup() owns `hidden` and sets it false whenever a group has rows,
    // which is why the form state lives on the tab and not on the cards.
    assert.equal(card('senders').hidden, false);
    assert.ok(isFormOpen(), 'the tab class survives, and the stylesheet does the hiding');
  });

  // ── closing ───────────────────────────────────────────────────────────────

  it('closing brings the lists back', () => {
    h.senders.openSenderForm();
    h.senders.closeSenderForm();
    assert.ok(!isFormOpen());
    assert.equal(formCard().style.display, 'none');
  });

  it('closing an edit returns to the row it came from', async () => {
    await h.senders.editSender('b');
    await settle();
    h.senders.closeSenderForm();

    assert.equal(h.scrolled.intoView.length, 1);
    assert.equal(h.scrolled.intoView[0].element.dataset.senderId, 'b');
    assert.deepEqual(h.scrolled.intoView[0].options, { block: 'center' });
  });

  it('closing a create scrolls nowhere, having come from no row', () => {
    h.senders.openSenderForm();
    h.senders.closeSenderForm();
    assert.deepEqual(h.scrolled.intoView, []);
  });

  it('leaves the scroll alone when the row is gone by the time we close', async () => {
    await h.senders.editSender('a');
    await settle();
    h.document.querySelector('tr[data-sender-id="a"]').remove();
    h.senders.closeSenderForm();
    assert.deepEqual(h.scrolled.intoView, [], 'no throw, and no arbitrary jump');
    assert.ok(!isFormOpen());
  });

  it('stops pointing at the edited row once it has returned there', async () => {
    // "+ Add Sender" closes the form before opening it, so a close straight
    // after an edit's close is an ordinary path, not a contrived one. The
    // second one must not scroll back to a row the reader has already left.
    await h.senders.editSender('b');
    await settle();
    h.senders.closeSenderForm();
    assert.equal(h.scrolled.intoView.length, 1);

    h.senders.closeSenderForm();
    assert.equal(h.scrolled.intoView.length, 1, 'closing again jumped to b a second time');
  });
});
