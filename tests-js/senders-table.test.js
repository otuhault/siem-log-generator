/**
 * The senders page: two groups, what each column says, and the order they list in.
 *
 * Senders and attacks are listed apart because they are read differently — a
 * sender by what it emits and how fast, an attack by where it landed. Running or
 * stopped is no longer which table a row is in, so the row says it itself: green,
 * and at the top. Each title filters its own group down to what is running.
 *
 * There is no status column. The one thing it said that nothing else does is how
 * an attack ended — a finished and a failed attack are both disabled — and that
 * stays, under the name.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { createHarness } from './harness.mjs';

const sender = (id, name, extra = {}) => ({
  id, name, log_type: 'paloalto', enabled: false, destination_type: 'file',
  destination: `/tmp/${id}.log`, frequency: 5, logs_generated: 1,
  created_at: '2026-09-01T10:00:00', options: {}, ...extra,
});

const attack = (id, name, extra = {}) => sender(id, name, {
  log_type: 'ssh_bruteforce', frequency: 1,
  options: { attack_events_count: 100, attack_duration: 60 }, ...extra,
});

const SENDERS = {
  b: sender('b', 'beta firewall', { enabled: true }),
  a: sender('a', 'Alpha windows', { log_type: 'windows' }),
  c: sender('c', 'charlie 10', { log_type: 'ssh' }),
  d: sender('d', 'charlie 9', { log_type: 'ssh', enabled: true }),
  dm: sender('dm', 'zulu datamodel', {
    options: { log_types: ['traffic'], datamodel_group: 'Network_Traffic' } }),

  run: attack('run', 'running brute force', { enabled: true, attack_status: 'Running',
    destination_type: 'configuration', configuration_id: 'cfg1' }),
  done: attack('done', 'brute force run', { attack_status: 'Done (09/14 11:45:00)',
    logs_generated: 100, destination_type: 'configuration', configuration_id: 'cfg1',
    options: { attack_events_count: 100, attack_duration: 60, hec_index: 'attack_lab' } }),
  failed: attack('failed', 'broken run', { attack_status: 'Error: connection refused',
    logs_generated: 0, destination_type: 'configuration', configuration_id: 'cfg2' }),
  idle: attack('idle', 'never started', { attack_status: 'Disabled' }),
};

describe('senders page', () => {
  let h;

  const headers = (group) => [...h.document.querySelectorAll(`#${group}Container thead th`)]
    .map((th) => th.textContent.replace(/[▲▼↕]/g, '').trim());
  const names = (group) => [...h.document.querySelectorAll(`#${group}Container tbody tr`)]
    .map((tr) => tr.dataset.senderId);
  const table = (group) => h.document.querySelector(`#${group}Container table`);
  const card = (group) => h.document.getElementById(`${group}Card`);
  const click = async (el) => { el.click(); await new Promise((r) => setTimeout(r, 0)); };
  const clickHeader = (group, key) =>
    click(h.document.querySelector(`#${group}Container .th-sort[data-sort="${key}"]`));
  const clickTitle = (group) => click(h.document.getElementById(`${group}Toggle`));

  beforeEach(async () => {
    h = await createHarness({ senders: SENDERS });
    h.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force', log_type: 'ssh' } });
    h.state.setConfigurations([{ id: 'cfg1', name: 'lab', index: 'main' },
                               { id: 'cfg2', name: 'other', index: '' }]);
    h.senders.initSenderGroups();
    await h.senders.loadSenders();
  });

  afterEach(() => h.close());

  // ── the two groups ────────────────────────────────────────────────────────

  it('lists senders and attacks apart, by what they are', () => {
    assert.deepEqual(names('senders').sort(), ['a', 'b', 'c', 'd', 'dm']);
    assert.deepEqual(names('attacks').sort(), ['done', 'failed', 'idle', 'run']);
  });

  it('hides a group that has nothing in it at all', async () => {
    const empty = await createHarness({ senders: { a: SENDERS.a } });
    empty.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force' } });
    empty.senders.initSenderGroups();
    await empty.senders.loadSenders();
    assert.equal(empty.document.getElementById('sendersCard').hidden, false);
    assert.equal(empty.document.getElementById('attacksCard').hidden, true);
    empty.close();
  });

  // ── what is running ───────────────────────────────────────────────────────

  it('marks a running row and floats it to the top of its group', () => {
    assert.deepEqual(names('senders').slice(0, 2).sort(), ['b', 'd'], 'the two running ones first');
    const running = (id) => h.document
      .querySelector(`tr[data-sender-id="${id}"]`).classList.contains('is-running');
    assert.ok(running('b') && running('d') && running('run'));
    assert.ok(!running('a') && !running('done'));
  });

  it('keeps running first whatever the table is sorted by', async () => {
    await clickHeader('senders', 'name');
    assert.deepEqual(names('senders'), ['b', 'd', 'a', 'c', 'dm'],
      'running in name order, then the rest in name order');
  });

  // ── the title filters ─────────────────────────────────────────────────────

  it('clicking a title shows only what is running, and clicking it again restores', async () => {
    await clickTitle('senders');
    assert.deepEqual(names('senders').sort(), ['b', 'd']);
    assert.deepEqual(names('attacks').sort(), ['done', 'failed', 'idle', 'run'],
      'the other group is untouched');
    assert.equal(h.document.getElementById('sendersToggle').getAttribute('aria-pressed'), 'true');
    assert.match(h.document.querySelector('#sendersToggle .group-filter').textContent, /running/i);

    await clickTitle('senders');
    assert.equal(names('senders').length, 5);
    assert.equal(h.document.getElementById('sendersToggle').getAttribute('aria-pressed'), 'false');
    assert.equal(h.document.querySelector('#sendersToggle .group-filter').textContent, '');
  });

  it('with nothing running, hides the table and says nothing in its place', async () => {
    const stopped = Object.fromEntries(
      Object.entries(SENDERS).map(([id, s]) => [id, { ...s, enabled: false }]));
    const quiet = await createHarness({ senders: stopped });
    quiet.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force' } });
    quiet.senders.initSenderGroups();
    await quiet.senders.loadSenders();
    quiet.document.getElementById('sendersToggle').click();
    await new Promise((r) => setTimeout(r, 0));

    assert.equal(quiet.document.querySelector('#sendersContainer table'), null, 'table hidden');
    assert.equal(quiet.document.getElementById('sendersContainer').textContent.trim(), '',
      'and no line of text taking its place');
    assert.equal(quiet.document.getElementById('sendersCard').hidden, false,
      'the card stays, or the title could not be clicked back');
    quiet.close();
  });

  // ── the columns ───────────────────────────────────────────────────────────

  it('has no status column in either group', () => {
    for (const group of ['senders', 'attacks']) {
      assert.ok(!headers(group).some((t) => /status/i.test(t)), headers(group).join(','));
      assert.equal(h.document.querySelectorAll(`#${group}Container .sender-status`).length, 0);
      const row = h.document.querySelector(`#${group}Container tbody tr`);
      assert.equal(row.children.length, headers(group).length, `${group}: cells do not line up`);
    }
  });

  it('lays the columns out per group, Index after Destination for a sender and before it for an attack', () => {
    assert.deepEqual(headers('senders'),
      ['Name', 'Mode', 'Destination', 'Index', 'Frequency', 'Duration', 'Actions']);
    assert.deepEqual(headers('attacks'),
      ['Name', 'Index', 'Destination', 'Frequency', 'Last Time Executed', 'Actions']);
  });

  it('names the kind of destination and nothing more, keeping which one on hover', async () => {
    const kinds = await createHarness({ senders: {
      file: sender('file', 'to a file'),
      hec: sender('hec', 'to hec', { destination_type: 'configuration',
        configuration_id: 'cfg1', options: { hec_index: 'sender_lab' } }),
      sys: sender('sys', 'to syslog', { destination_type: 'syslog',
        syslog_host: '10.0.0.9', syslog_port: 514, syslog_protocol: 'tcp' }),
    } });
    kinds.state.setAttackTypes({});
    kinds.state.setConfigurations([{ id: 'cfg1', name: 'lab', index: 'main' }]);
    kinds.senders.initSenderGroups();
    await kinds.senders.loadSenders();

    const cell = (id) => kinds.document
      .querySelector(`tr[data-sender-id="${id}"] .sender-destination`);
    assert.equal(cell('file').textContent, 'Local File');
    assert.equal(cell('hec').textContent, 'HEC');
    assert.equal(cell('sys').textContent, 'Syslog');
    // The detail is off the column but not lost.
    assert.equal(cell('file').title, '/tmp/file.log');
    assert.equal(cell('hec').title, 'lab');
    assert.equal(cell('sys').title, '10.0.0.9:514 (TCP)');

    const index = (id) => kinds.document
      .querySelector(`tr[data-sender-id="${id}"] .sender-index`).textContent;
    assert.equal(index('hec'), 'sender_lab', "the sender's own index");
    assert.equal(index('file'), '—', 'a file has no index');
    assert.equal(index('sys'), '—', 'nor a collector that decides for itself');
    kinds.close();
  });

  it('names each sender by how it was defined', () => {
    const mode = (id) => h.document.querySelector(`tr[data-sender-id="${id}"] .sender-mode`).textContent;
    assert.equal(mode('a'), 'Sourcetype');
    assert.equal(mode('dm'), 'Datamodel');
  });

  it('shows the index an attack lands in: its own, else the destination’s, else none', () => {
    const index = (id) => h.document.querySelector(`tr[data-sender-id="${id}"] .sender-index`).textContent;
    assert.equal(index('done'), 'attack_lab', "the sender's own override");
    assert.equal(index('run'), 'main', "the HEC destination's index");
    assert.equal(index('failed'), 'default', 'a destination that names none');
    assert.equal(index('idle'), '—', 'a file has no index at all');
  });

  // ── order ─────────────────────────────────────────────────────────────────

  it('sorts by name, case-insensitively and numbers as numbers', async () => {
    await clickTitle('senders');          // only the running two, to see the sort alone
    await clickHeader('senders', 'name');
    assert.deepEqual(names('senders'), ['b', 'd']);

    await clickTitle('senders');
    // "charlie 9" before "charlie 10": a plain string sort would invert them.
    assert.deepEqual(names('senders'), ['b', 'd', 'a', 'c', 'dm']);
    assert.equal(h.document.querySelector('#sendersContainer thead th').getAttribute('aria-sort'),
      'ascending');
  });

  it('keeps the order across the periodic refresh', async () => {
    await clickHeader('senders', 'name');
    await h.senders.loadSenders();        // what the 2-second poll does
    assert.deepEqual(names('senders'), ['b', 'd', 'a', 'c', 'dm']);
  });

  it('sorts attacks by index, stopped ones after the running one', async () => {
    await clickHeader('attacks', 'index');
    const th = h.document.querySelector('#attacksContainer .th-sort[data-sort="index"]').closest('th');
    assert.equal(th.getAttribute('aria-sort'), 'ascending');
    // 'run' is running so it leads; then — < attack_lab < default.
    assert.deepEqual(names('attacks'), ['run', 'idle', 'done', 'failed']);
  });

  // ── what the status column used to say ────────────────────────────────────

  it('still says how an attack ended, and nothing for one that has not run', () => {
    const outcome = (id) => h.document
      .querySelector(`tr[data-sender-id="${id}"] .sender-outcome`);
    assert.match(outcome('done').textContent, /^Done/);
    assert.ok(outcome('done').classList.contains('done'));
    assert.match(outcome('failed').textContent, /connection refused/);
    assert.ok(outcome('failed').classList.contains('error'));
    assert.equal(outcome('idle'), null);
    assert.equal(outcome('a'), null, 'a regular sender got an outcome badge');
  });
});

describe('sender duration', () => {
  let h;

  const $ = (id) => h.document.getElementById(id);
  const setRate = async (frequency, value, unit) => {
    $('frequency').value = String(frequency);
    $('senderDuration').value = String(value);
    $('senderDurationUnit').value = unit;
    $('senderDuration').dispatchEvent(new h.window.Event('input', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 0));
  };

  beforeEach(async () => {
    h = await createHarness({ senders: SENDERS });
    h.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force' } });
    h.senders.initSenderGroups();
    await h.senders.loadSenders();
  });

  afterEach(() => h.close());

  it('reads a number and a unit as one count of seconds', () => {
    const { durationSeconds } = h.senders;
    assert.equal(durationSeconds('90', 'seconds'), 90);
    assert.equal(durationSeconds('5', 'minutes'), 300);
    assert.equal(durationSeconds('2', 'hours'), 7200);
    assert.equal(durationSeconds('0', 'hours'), 0, 'zero is zero in any unit');
    assert.equal(durationSeconds('', 'minutes'), 0);
    assert.equal(durationSeconds('-5', 'minutes'), 0, 'a negative duration is no duration');
  });

  it('gives the seconds back in the largest whole unit', () => {
    const { splitDuration } = h.senders;
    assert.deepEqual(splitDuration(7200), { value: 2, unit: 'hours' });
    assert.deepEqual(splitDuration(300), { value: 5, unit: 'minutes' });
    assert.deepEqual(splitDuration(5400), { value: 90, unit: 'minutes' }, 'not 1.5 hours');
    assert.deepEqual(splitDuration(90), { value: 90, unit: 'seconds' });
    assert.deepEqual(splitDuration(0), { value: 0, unit: 'seconds' });
  });

  it('shows how many logs the two fields add up to', async () => {
    await setRate(10, 60, 'seconds');
    assert.match($('senderVolumeHint').textContent, /≈ 600 logs/);
    assert.match($('senderVolumeHint').textContent, /10 logs\/sec for 60 seconds/);

    await setRate(20, 5, 'minutes');
    assert.match($('senderVolumeHint').textContent, /≈ 6,000 logs/);
    assert.match($('senderVolumeHint').textContent, /for 5 minutes/);

    await setRate(1, 1, 'hours');
    assert.match($('senderVolumeHint').textContent, /for 1 hour\b/, 'one hour, not one hours');
  });

  it('says what zero means, instead of an estimate', async () => {
    await setRate(10, 0, 'seconds');
    assert.match($('senderVolumeHint').textContent, /Runs until you stop it/i);
    assert.doesNotMatch($('senderVolumeHint').textContent, /≈/);
  });

  it('says a duration can still be cut short by hand', async () => {
    await setRate(10, 60, 'seconds');
    assert.match($('senderVolumeHint').textContent, /stop it by hand/i);
  });

  it('sends the duration in seconds, and brings it back in its own unit', async () => {
    const withDuration = { ...SENDERS.a, id: 'dur', duration_seconds: 7200 };
    const edit = await createHarness({ senders: { dur: withDuration } });
    // jsdom has no layout, so it has no scrollIntoView; the form calls it.
    edit.window.Element.prototype.scrollIntoView = function scrollIntoView() {};
    edit.state.setAttackTypes({});
    edit.senders.initSenderGroups();
    await edit.senders.loadSenders();
    await edit.senders.editSender('dur');
    await new Promise((r) => setTimeout(r, 30));

    assert.equal(edit.document.getElementById('senderDuration').value, '2');
    assert.equal(edit.document.getElementById('senderDurationUnit').value, 'hours');
    edit.close();
  });

  // ── the table ─────────────────────────────────────────────────────────────

  it('the senders table shows Duration instead of Logs Generated and Created', () => {
    const cols = [...h.document.querySelectorAll('#sendersContainer thead th')]
      .map((th) => th.textContent.replace(/[▲▼↕]/g, '').trim());
    assert.ok(cols.includes('Duration'), cols.join(','));
    assert.ok(!cols.includes('Logs Generated') && !cols.includes('Created'), cols.join(','));
  });

  it('the attacks table says when it last ran instead', () => {
    const cols = [...h.document.querySelectorAll('#attacksContainer thead th')]
      .map((th) => th.textContent.replace(/[▲▼↕]/g, '').trim());
    assert.ok(cols.includes('Last Time Executed'), cols.join(','));
    assert.ok(!cols.includes('Logs Generated') && !cols.includes('Created'), cols.join(','));
    assert.ok(!cols.includes('Duration'), cols.join(','));
  });

  it('writes a duration in its own unit, and names the manual mode', async () => {
    const durations = await createHarness({ senders: {
      s60: { ...SENDERS.a, id: 's60', duration_seconds: 60 },
      s2h: { ...SENDERS.b, id: 's2h', enabled: false, duration_seconds: 7200 },
      s90: { ...SENDERS.c, id: 's90', duration_seconds: 90 },
      manual: { ...SENDERS.d, id: 'manual', enabled: false, duration_seconds: 0 },
    } });
    durations.state.setAttackTypes({});
    durations.senders.initSenderGroups();
    await durations.senders.loadSenders();

    const cell = (id) => durations.document
      .querySelector(`tr[data-sender-id="${id}"] .sender-duration`).textContent;
    // Stored in seconds, shown in the largest unit that divides it: the table
    // has no memory of what was typed, and 7200s reads worse than 2h.
    assert.equal(cell('s60'), '1m');
    assert.equal(cell('s2h'), '2h');
    assert.equal(cell('s90'), '90s', 'not 1.5m');
    assert.equal(cell('manual'), 'Manual');
    durations.close();
  });
});

describe('the Mode bubble', () => {
  let h;

  const LOG_TYPES = {
    paloalto: { name: 'Palo Alto', sources: [
      { id: 'traffic', name: 'Traffic', sourcetype: 'pan:traffic' },
      { id: 'threat', name: 'Threat', sourcetype: 'pan:threat' },
      { id: 'system', name: 'System', sourcetype: 'pan:system' }] },
    cisco_asa: { name: 'Cisco ASA', sources: [
      { id: 'connection', name: 'Connection Events' },
      { id: 'vpn', name: 'VPN Events' }] },
  };

  const hover = (id, type) => {
    const cell = h.document.querySelector(`tr[data-sender-id="${id}"] .sender-mode`);
    cell.dispatchEvent(new h.window.Event(type, { bubbles: false }));
    return cell;
  };
  const tip = () => h.document.querySelector('.mode-tip');
  const items = () => [...tip().querySelectorAll('li')].map((li) => li.textContent);

  const load = async (senders) => {
    h = await createHarness({ senders });
    h.state.setLogTypes(LOG_TYPES);
    h.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force' } });
    h.senders.initSenderGroups();
    await h.senders.loadSenders();
  };

  afterEach(() => h.close());

  it('lists the sourcetypes the selected categories produce', async () => {
    await load({ pa: sender('pa', 'palo', { options: { log_types: ['traffic', 'system'] } }) });
    hover('pa', 'mouseenter');
    assert.equal(tip().hidden, false);
    assert.deepEqual(items(), ['pan:traffic', 'pan:system'], 'only what was ticked, in order');
  });

  it('names the category where the generator declares no sourcetype', async () => {
    await load({ asa: sender('asa', 'asa', {
      log_type: 'cisco_asa', options: { event_categories: ['vpn'] } }) });
    hover('asa', 'mouseenter');
    assert.deepEqual(items(), ['VPN Events'],
      'no sourcetype to show, so the category rather than an invented one');
  });

  it('with nothing selected, shows every category — which is what it sends', async () => {
    await load({ pa: sender('pa', 'palo', { options: {} }) });
    hover('pa', 'mouseenter');
    assert.deepEqual(items(), ['pan:traffic', 'pan:threat', 'pan:system']);
  });

  it('shows the datamodel and the sourcetype feeding it', async () => {
    await load({ dm: sender('dm', 'zulu', { options: {
      datamodel_group: 'Network_Traffic', splunk_sourcetype: 'pan:traffic',
      log_types: ['traffic'] } }) });
    hover('dm', 'mouseenter');
    assert.equal(tip().querySelector('strong').textContent, 'Network_Traffic');
    assert.deepEqual(items(), ['pan:traffic']);
  });

  it('goes away as the pointer leaves', async () => {
    await load({ pa: sender('pa', 'palo', { options: { log_types: ['traffic'] } }) });
    hover('pa', 'mouseenter');
    assert.equal(tip().hidden, false);
    hover('pa', 'mouseleave');
    assert.equal(tip().hidden, true);
  });

  it('shows the row the pointer is on, not the one before it', async () => {
    await load({
      pa: sender('pa', 'palo', { options: { log_types: ['traffic'] } }),
      asa: sender('asa', 'asa', { log_type: 'cisco_asa', options: { event_categories: ['vpn'] } }),
    });
    hover('pa', 'mouseenter');
    assert.deepEqual(items(), ['pan:traffic']);
    hover('pa', 'mouseleave');
    hover('asa', 'mouseenter');
    assert.deepEqual(items(), ['VPN Events'], 'the bubble still held the previous row');
  });

  it('is offered on a Mode cell and never on an attack row', async () => {
    await load({
      pa: sender('pa', 'palo', { options: { log_types: ['traffic'] } }),
      atk: attack('atk', 'brute force', { destination_type: 'file' }),
    });
    assert.ok(h.document.querySelector('tr[data-sender-id="pa"] .sender-mode')
      .classList.contains('has-mode-tip'));
    assert.equal(h.document.querySelector('tr[data-sender-id="atk"] .sender-mode'), null,
      'an attack row has an Index cell, which says all there is');
  });

  it('leaves no bubble behind once the pointer has gone and the table rebuilds', async () => {
    await load({ pa: sender('pa', 'palo', { options: { log_types: ['traffic'] } }) });
    hover('pa', 'mouseenter');
    hover('pa', 'mouseleave');
    await h.senders.loadSenders();        // what the 2-second poll does
    assert.equal(tip().hidden, true);
    assert.ok(h.document.querySelector('tr[data-sender-id="pa"] .sender-mode'),
      'and the rebuild did happen');
  });
});

describe('the Mode bubble survives the refresh', () => {
  let h;

  afterEach(() => h.close());

  it('the two-second poll does not pull the bubble out from under the pointer', async () => {
    h = await createHarness({ senders: {
      pa: sender('pa', 'palo', { options: { log_types: ['traffic'] } }) } });
    h.state.setLogTypes({ paloalto: { name: 'Palo Alto', sources: [
      { id: 'traffic', name: 'Traffic', sourcetype: 'pan:traffic' }] } });
    h.state.setAttackTypes({});
    h.senders.initSenderGroups();
    await h.senders.loadSenders();

    const cell = h.document.querySelector('tr[data-sender-id="pa"] .sender-mode');
    cell.dispatchEvent(new h.window.Event('mouseenter'));
    assert.equal(h.document.querySelector('.mode-tip').hidden, false);

    await h.senders.loadSenders();
    assert.equal(h.document.querySelector('.mode-tip').hidden, false,
      'the refresh hid the bubble the pointer is still on');
    assert.equal(h.document.querySelector('tr[data-sender-id="pa"] .sender-mode'), cell,
      'and it must be the same cell, or the pointer is over a new one that never got mouseenter');

    cell.dispatchEvent(new h.window.Event('mouseleave'));
    await h.senders.loadSenders();
    assert.equal(h.document.querySelector('tr[data-sender-id="pa"] .sender-mode') !== cell, true,
      'once the pointer is away the table rebuilds as usual');
  });
});

describe('when an attack last ran', () => {
  let h;

  const load = async (senders) => {
    h = await createHarness({ senders });
    h.state.setAttackTypes({ ssh_bruteforce: { name: 'SSH Brute Force' } });
    h.senders.initSenderGroups();
    await h.senders.loadSenders();
  };
  const cell = (id) => h.document.querySelector(`tr[data-sender-id="${id}"] .sender-last-run`);

  afterEach(() => h.close());

  it('shows the date and the time, since an attack runs more than once a day', async () => {
    await load({ a: attack('a', 'ran today', { last_run_at: '2026-09-16T14:05:00' }) });
    assert.equal(cell('a').textContent, '2026/09/16 14:05');
    assert.ok(!cell('a').classList.contains('is-never'));
  });

  it('says Never for one that has not run', async () => {
    await load({ a: attack('a', 'never started') });
    assert.equal(cell('a').textContent, 'Never');
    assert.ok(cell('a').classList.contains('is-never'));
  });

  it('says Never rather than a broken date for an unreadable value', async () => {
    await load({ a: attack('a', 'odd', { last_run_at: 'not a date' }) });
    assert.equal(cell('a').textContent, 'Never');
  });

  it('an attack saved before this existed simply reads as never run', async () => {
    // No last_run_at at all, but a status that says it finished: the badge
    // under the name still carries that, so nothing is lost.
    await load({ a: attack('a', 'older run', { attack_status: 'Done (09/14 11:45:00)' }) });
    assert.equal(cell('a').textContent, 'Never');
    assert.match(h.document.querySelector('tr[data-sender-id="a"] .sender-outcome').textContent,
      /^Done/);
  });
});
