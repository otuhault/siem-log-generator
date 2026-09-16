/**
 * Attack Configuration for an attack that declares its data sources.
 *
 * The order is the user's: sourcetypes, environment, number of events, noise,
 * duration. A sourcetype row gets a checkbox only when there are several to
 * choose between, and its name becomes a format picker only when there are
 * several formats. The last selected sourcetype cannot be unticked, and the HEC
 * sourcetype and source overrides are hidden because the rows force them.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { createHarness, settle } from './harness.mjs';

const WINDOWS_SECURITY = {
  log_type: 'windows', sourcetype: 'WinEventLog:Security',
  label: 'Windows Security · process creation (4688)', technology: 'Windows',
  formats: [
    { value: 'xml', sourcetype: 'XmlWinEventLog', source: 'XmlWinEventLog:Security' },
    { value: 'classic', sourcetype: 'WinEventLog', source: 'WinEventLog:Security' },
  ],
  // As the API describes Windows: a default, and no choice on any destination.
  delivery: {"default":"uf","offered":{"file":[],"syslog":[],"configuration":[]}},
};

const TOR = {
  name: 'Windows TOR Client Execution', log_type: 'windows', field_behaviors: { user: 'fixed', dest: 'fixed' },
  data_sources: [WINDOWS_SECURITY], noise: true,
  defaults: { events: 5, noise_events: 20, duration: 1 },
};

const TWO_FIREWALLS = {
  name: 'Port scan', log_type: 'paloalto', field_behaviors: {}, noise: false, defaults: {},
  data_sources: [
    { log_type: 'paloalto', sourcetype: 'pan:traffic', label: 'Palo Alto traffic',
      formats: [{ value: 'xml', sourcetype: 'pan:log', source: null }] },
    { log_type: 'fortigate', sourcetype: 'fortigate_traffic', label: 'FortiGate traffic',
      formats: [{ value: 'xml', sourcetype: 'fortigate_traffic', source: null }] },
  ],
};

const IMPACT = [
  { field: 'user', sources: ['standard account · username'], count: 3, available: true },
  { field: 'dest', sources: ['endpoint · nt_host'], count: 0, available: false },
];

function fetchWithImpact(base) {
  return async (url, options) => {
    if (String(url).startsWith('/api/environment/attack-impact/')) {
      return { ok: true, status: 200, json: async () => IMPACT };
    }
    return base(url, options);
  };
}

describe('attack configuration', () => {
  let h;
  let $;

  beforeEach(async () => {
    h = await createHarness();
    const base = globalThis.fetch;
    globalThis.fetch = fetchWithImpact(base);
    h.attackConfig.initAttackConfig();
    $ = (id) => h.document.getElementById(id);
  });

  afterEach(() => {
    h.attackConfig.hideAttackConfig();
    h.close();
  });

  it('lays the blocks out in the order asked for', () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    const ids = ['attackSourcesGroup', 'attackEnvironmentGroup', 'attackEventsCount',
                 'attackNoiseGroup', 'attackDuration'];
    const positions = ids.map((id) => [...h.document.querySelectorAll('#attackOptionsGroup *')].indexOf($(id)));
    assert.deepEqual([...positions].sort((a, b) => a - b), positions, `order: ${positions}`);
  });

  it('one sourcetype: no checkbox, and its name is a format picker', () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    const rows = h.document.querySelectorAll('.attack-source-row');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].querySelector('.attack-source-check'), null);
    const options = [...rows[0].querySelectorAll('.attack-source-format option')].map((o) => o.textContent);
    assert.deepEqual(options, ['XmlWinEventLog', 'WinEventLog']);
  });

  it('switching the format shows the source it will force', () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    const row = h.document.querySelector('.attack-source-row');
    assert.equal(row.querySelector('.attack-source-wire code').textContent, 'XmlWinEventLog:Security');
    const select = row.querySelector('.attack-source-format');
    select.value = 'classic';
    select.dispatchEvent(new h.window.Event('change'));
    assert.equal(row.querySelector('.attack-source-wire code').textContent, 'WinEventLog:Security');
  });

  it('several sourcetypes get checkboxes, and the last one cannot be unticked', () => {
    h.attackConfig.showAttackConfig('scan', TWO_FIREWALLS);
    const checks = [...h.document.querySelectorAll('.attack-source-check')];
    assert.equal(checks.length, 2);
    assert.ok(checks.every((c) => c.checked && !c.disabled));

    checks[0].checked = false;
    checks[0].dispatchEvent(new h.window.Event('change'));
    assert.ok(checks[1].disabled, 'the only one left must be locked');

    const sent = h.attackConfig.collectAttackOptions().attack_sources;
    assert.deepEqual(sent, [{ log_type: 'fortigate', sourcetype: 'fortigate_traffic', render_format: 'xml' }]);
  });

  it('applies the attack defaults: 5 events, 20 benign events, one second', () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    assert.equal($('attackEventsCount').value, '5');
    assert.equal($('attackNoiseCount').value, '20');
    assert.equal($('attackDuration').value, '1');
    assert.equal($('attackDuration').min, '0', '0 stays available for an instant burst');
  });

  it('noise shows its count only when switched on, and is sent only then', () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    assert.equal($('attackNoiseCountGroup').hidden, true);
    assert.equal(h.attackConfig.collectAttackOptions().attack_noise, false);
    assert.equal('attack_noise_count' in h.attackConfig.collectAttackOptions(), false);

    $('attackNoise').checked = true;
    $('attackNoise').dispatchEvent(new h.window.Event('change'));
    assert.equal($('attackNoiseCountGroup').hidden, false);
    const options = h.attackConfig.collectAttackOptions();
    assert.equal(options.attack_noise, true);
    assert.equal(options.attack_noise_count, 20);
  });

  it('the environment shows the slider and the detection fields it feeds', async () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    assert.equal($('attackAiRatioGroup').hidden, true);

    $('attackUseEnvironment').checked = true;
    $('attackUseEnvironment').dispatchEvent(new h.window.Event('change'));
    await settle();

    assert.equal($('attackAiRatioGroup').hidden, false);
    const rows = [...h.document.querySelectorAll('#attackAiFieldRows .ai-impact-row')];
    assert.deepEqual(rows.map((r) => r.querySelector('.ai-cim-field').textContent), ['user', 'dest']);
    assert.ok(rows[1].classList.contains('fallback'), 'an empty pool must read as a fallback');

    const options = h.attackConfig.collectAttackOptions();
    assert.equal(options.use_assets_identities, true);
    assert.equal(options.assets_identities_ratio, 100);
  });

  it('forces sourcetype and source: the HEC overrides are hidden while selected', () => {
    const form = $('createSenderForm');
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    assert.ok(form.classList.contains('attack-sourced'));
    h.attackConfig.hideAttackConfig();
    assert.ok(!form.classList.contains('attack-sourced'));
  });

  it('a legacy attack shows none of it', () => {
    const shown = h.attackConfig.showAttackConfig('ssh_bruteforce', { data_sources: [] });
    assert.equal(shown, false);
    assert.equal($('attackSourcesGroup').hidden, true);
    assert.equal($('attackNoiseGroup').hidden, true);
    assert.equal($('attackDuration').min, '1');
  });

  it('an edited attack comes back as it was saved', async () => {
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    h.attackConfig.hydrateAttackConfig({
      attack_sources: [{ log_type: 'windows', sourcetype: 'WinEventLog:Security', render_format: 'classic' }],
      attack_events_count: 12, attack_duration: 30,
      attack_noise: true, attack_noise_count: 7,
      use_assets_identities: true, assets_identities_ratio: 40,
    });
    await settle();
    assert.equal(h.document.querySelector('.attack-source-format').value, 'classic');
    assert.equal($('attackEventsCount').value, '12');
    assert.equal($('attackDuration').value, '30');
    assert.equal($('attackNoiseCount').value, '7');
    assert.equal($('attackNoise').checked, true);
    assert.equal($('attackAiRatio').value, '40');

    const options = h.attackConfig.collectAttackOptions();
    assert.equal(options.attack_sources[0].render_format, 'classic');
    assert.equal(options.assets_identities_ratio, 40);
  });
});

describe('attack delivery format', () => {
  let h;
  let $;

  // A source collected over syslog, described the way the API describes ssh.
  const SSH_SOURCE = {
    log_type: 'ssh', sourcetype: 'linux_secure', label: 'SSH authentication',
    formats: [{ value: 'xml', sourcetype: 'linux_secure', source: '/var/log/secure' }],
    delivery: { default: 'uf', offered: { file: ['uf', 'syslog'], syslog: ['uf', 'syslog'], configuration: [] } },
  };
  const SSH_ATTACK = { name: 'SSH attack', data_sources: [SSH_SOURCE], noise: false, defaults: {} };

  const choose = (value) => {
    const radio = h.document.querySelector(`input[name="destination_type"][value="${value}"]`);
    radio.checked = true;
    radio.dispatchEvent(new h.window.Event('change', { bubbles: true }));
  };

  beforeEach(async () => {
    h = await createHarness();
    h.attackConfig.initAttackConfig();
    $ = (sel) => h.document.querySelector(sel);
  });

  afterEach(() => {
    h.attackConfig.hideAttackConfig();
    h.close();
  });

  it('appears on a Local File and disappears on HEC', () => {
    choose('file');
    h.attackConfig.showAttackConfig('ssh_attack', SSH_ATTACK);
    assert.equal($('.attack-source-delivery').hidden, false);
    assert.equal($('.attack-source-delivery').value, 'uf');

    choose('configuration');
    assert.equal($('.attack-source-delivery').hidden, true);
    assert.equal('delivery_format' in h.attackConfig.collectAttackOptions().attack_sources[0], false,
      'a hidden choice must not be sent');
  });

  it('is sent per source when shown, and restored on edit', () => {
    choose('file');
    h.attackConfig.showAttackConfig('ssh_attack', SSH_ATTACK);
    $('.attack-source-delivery').value = 'syslog';
    assert.equal(h.attackConfig.collectAttackOptions().attack_sources[0].delivery_format, 'syslog');

    h.attackConfig.showAttackConfig('ssh_attack', SSH_ATTACK);
    h.attackConfig.hydrateAttackConfig({
      attack_sources: [{ log_type: 'ssh', sourcetype: 'linux_secure', delivery_format: 'syslog' }] });
    assert.equal($('.attack-source-delivery').value, 'syslog');
  });

  it('a Windows source has formats but no delivery format', () => {
    choose('file');
    h.attackConfig.showAttackConfig('windows_tor_client_execution', TOR);
    assert.equal($('.attack-source-delivery'), null);
    assert.ok($('.attack-source-format'), 'XmlWinEventLog / WinEventLog stays the choice');
  });
});

describe('port scan configuration', () => {
  let h;
  let $;

  // As the API describes a source of an attack over several sourcetypes: one
  // shape everywhere, so no delivery format on any destination.
  const firewall = (log_type, sourcetype, wire) => ({
    log_type, sourcetype, label: sourcetype,
    formats: [{ value: 'default', sourcetype: wire, source: null }],
    delivery: { default: 'uf', offered: { file: [], syslog: [], configuration: [] } },
  });

  // As the API describes paloalto_horizontal_port_scan.
  const PORT_SCAN = {
    name: 'Internal Horizontal Port Scan', log_type: 'paloalto', field_behaviors: { dest_port: 'fixed' },
    data_sources: [firewall('paloalto', 'pan:traffic', 'pan:log'),
                   firewall('fortigate', 'fortigate_traffic', 'fortigate_traffic'),
                   firewall('cisco_asa', 'cisco:asa', 'cisco:asa')],
    noise: true, destinations: ['file', 'configuration'],
    destinations_note: 'This attack spans several sourcetypes, so it is sent to a Local File or HEC only.'
                       + ' A file receives the events exactly as HEC sends them.',
    defaults: { events: 250, noise_events: 300, duration: 60 },
    count_label: 'Number of Distinct Dest IPs', count_hint: 'One probe per destination.',
    identity_fields: [{ field: 'src_ip', mode: 'single', label: 'Source IP' },
                      { field: 'dest_ip', mode: 'distinct', label: 'Destination IPs' }],
  };

  const radio = (value) => h.document.querySelector(`input[name="destination_type"][value="${value}"]`);
  const change = (el, type = 'change') => el.dispatchEvent(new h.window.Event(type, { bubbles: true }));

  beforeEach(async () => {
    h = await createHarness();
    const base = globalThis.fetch;
    globalThis.fetch = fetchWithImpact(base);
    h.attackConfig.initAttackConfig();
    $ = (id) => h.document.getElementById(id);
  });

  afterEach(() => {
    h.attackConfig.hideAttackConfig();
    h.close();
  });

  it('every sourcetype starts ticked, with no source line for a firewall', () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    const checks = [...h.document.querySelectorAll('.attack-source-check')];
    assert.equal(checks.length, 3);
    assert.ok(checks.every((c) => c.checked));
    assert.equal(h.document.querySelector('.attack-source-wire'), null);
  });

  it('goes to HEC or a file, never syslog, and every destination comes back afterwards', () => {
    radio('file').checked = true;
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    assert.equal(radio('file').checked, true, 'a file stays a file');
    assert.equal(radio('file').disabled, false);
    assert.equal(radio('configuration').disabled, false);
    assert.equal(radio('syslog').disabled, true);
    assert.match($('attackDestinationNote').textContent, /Local File or HEC only\. A file receives the events exactly as HEC sends them/);
    assert.equal(h.document.querySelector('.attack-source-delivery'), null, 'no delivery format on a file');
    assert.equal('delivery_format' in h.attackConfig.collectAttackOptions().attack_sources[0], false);

    h.attackConfig.hideAttackConfig();
    radio('syslog').checked = true;
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    assert.equal(radio('syslog').checked, false, 'syslog cannot stay selected');
    assert.ok(radio('file').checked || radio('configuration').checked);

    h.attackConfig.hideAttackConfig();
    assert.equal(radio('file').disabled, false);
    assert.equal(radio('syslog').disabled, false);
    assert.equal($('attackDestinationNote').hidden, true);
  });

  it('counts distinct destinations, with its own defaults', () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    assert.equal($('attackEventsLabel').textContent, 'Number of Distinct Dest IPs:');
    assert.equal($('attackEventsCount').value, '250');
    assert.equal($('attackNoiseCount').value, '300');
    assert.equal($('attackDuration').value, '60');

    h.attackConfig.hideAttackConfig();
    assert.equal($('attackEventsLabel').textContent, 'Number of Events:');
  });

  it('shows the rate: (events + noise) / duration, the sourcetypes only sharing it', () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    assert.match($('attackRate').textContent, /^≈ 4\.17 events\/s — 250 \/ 60 s, split over 3 sourcetypes$/);

    $('attackNoise').checked = true;
    change($('attackNoise'));
    assert.match($('attackRate').textContent, /^≈ 9\.17 events\/s — 250 \+ 300 \/ 60 s, split over 3 sourcetypes$/);

    // Unticking a sourcetype shares the same total between fewer of them.
    const check = h.document.querySelector('.attack-source-check');
    check.checked = false;
    change(check);
    assert.match($('attackRate').textContent, /^≈ 9\.17 events\/s — 250 \+ 300 \/ 60 s, split over 2 sourcetypes$/);

    $('attackDuration').value = '0';
    change($('attackDuration'), 'input');
    assert.match($('attackRate').textContent, /^550 events at once/);
  });

  it('the source is Random by default; Custom types an address or keeps the placeholder', () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    const order = [...h.document.querySelectorAll('.attack-identity-row')].map((r) => r.dataset.field);
    assert.deepEqual(order, ['src_ip', 'dest_ip'], 'the scanner first, then what it sweeps');
    assert.equal($('attackUseEnvironmentLabel').hidden, true, 'no ratio slider for a scan');
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity,
      { src_ip: { mode: 'random' }, dest_ip: { environment: false } });

    const select = $('attackIdentity_src_ip');
    const input = h.document.querySelector('.attack-identity-value');
    assert.equal(input.hidden, true);
    select.value = 'custom';
    change(select);
    assert.equal(input.hidden, false);
    assert.match(input.placeholder, /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+/);
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.src_ip,
      { mode: 'custom', value: input.placeholder });

    input.value = '10.9.8.7';
    assert.equal(h.attackConfig.collectAttackOptions().attack_identity.src_ip.value, '10.9.8.7');
    assert.equal(h.attackConfig.collectAttackOptions().use_assets_identities, false);
  });

  it('the environment, for the source or the destinations, lists the fields it feeds', async () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    assert.equal($('attackAiFields').hidden, true);

    $('attackIdentity_dest_ip').checked = true;
    change($('attackIdentity_dest_ip'));
    await settle();
    assert.equal($('attackAiFields').hidden, false);
    let options = h.attackConfig.collectAttackOptions();
    assert.deepEqual(options.attack_identity.dest_ip, { environment: true });
    assert.equal(options.use_assets_identities, true);

    $('attackIdentity_dest_ip').checked = false;
    change($('attackIdentity_dest_ip'));
    assert.equal($('attackAiFields').hidden, true);

    $('attackIdentity_src_ip').value = 'environment';
    change($('attackIdentity_src_ip'));
    assert.equal($('attackAiFields').hidden, false);
    options = h.attackConfig.collectAttackOptions();
    assert.deepEqual(options.attack_identity.src_ip, { mode: 'environment' });
  });

  it('an edited scan comes back as saved, including one saved with a typed source IP', () => {
    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    h.attackConfig.hydrateAttackConfig({
      attack_sources: [{ log_type: 'cisco_asa', sourcetype: 'cisco:asa', render_format: 'default' }],
      attack_identity: { src_ip: { mode: 'custom', value: '192.168.3.3' }, dest_ip: { environment: true } },
      use_assets_identities: true, attack_events_count: 400,
    });
    assert.equal(h.document.querySelector('.attack-identity-value').value, '192.168.3.3');
    assert.equal($('attackIdentity_dest_ip').checked, true);
    assert.equal(h.document.querySelectorAll('.attack-source-check:checked').length, 1);
    assert.match($('attackRate').textContent, /^≈ 6\.67 events\/s — 400 \/ 60 s/);

    h.attackConfig.showAttackConfig('paloalto_horizontal_port_scan', PORT_SCAN);
    h.attackConfig.hydrateAttackConfig({ target_src_ip: '10.1.1.1' });
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.src_ip,
      { mode: 'custom', value: '10.1.1.1' });
  });
});

describe('vertical port scan configuration', () => {
  let h;
  let $;

  const firewall = (log_type, sourcetype, wire) => ({
    log_type, sourcetype, label: sourcetype,
    formats: [{ value: 'default', sourcetype: wire, source: null }],
    delivery: { default: 'uf', offered: { file: [], syslog: [], configuration: [] } },
  });

  const VERTICAL = {
    name: 'Internal Vertical Port Scan', log_type: 'paloalto', field_behaviors: {},
    data_sources: [firewall('paloalto', 'pan:traffic', 'pan:log'),
                   firewall('fortigate', 'fortigate_traffic', 'fortigate_traffic'),
                   firewall('cisco_asa', 'cisco:asa', 'cisco:asa')],
    noise: true, destinations: ['file', 'configuration'],
    destinations_note: 'This attack spans several sourcetypes, so it is sent to a Local File or HEC only.'
                       + ' A file receives the events exactly as HEC sends them.',
    defaults: { events: 500, noise_events: 200, duration: 60 },
    count_label: 'Total Destination Ports', count_hint: 'One probe per port.',
    extra_counts: [{ key: 'privileged_ports', label: 'Privileged Ports (< 1024)', default: 20,
                     hint: 'How many below 1024.' }],
    identity_fields: [{ field: 'src_ip', mode: 'asset', label: 'Source IP' },
                      { field: 'dest_ip', mode: 'asset', label: 'Destination IP' }],
  };

  const ASSETS = [{ id: 'a1', name: 'wks-01', ip: '10.50.1.10' },
                  { id: 'a2', name: 'crown-jewel', ip: '10.60.2.10' },
                  { id: 'a3', name: 'no-ip-host', ip: '' }];

  function fetchWithAssets(base) {
    return async (url, options) => {
      if (String(url) === '/api/entities') return { ok: true, status: 200, json: async () => ASSETS };
      if (String(url).startsWith('/api/environment/attack-impact/')) return { ok: true, status: 200, json: async () => IMPACT };
      return base(url, options);
    };
  }

  const change = (el, type = 'change') => el.dispatchEvent(new h.window.Event(type, { bubbles: true }));

  beforeEach(async () => {
    h = await createHarness();
    globalThis.fetch = fetchWithAssets(globalThis.fetch);
    h.attackConfig.initAttackConfig();
    $ = (id) => h.document.getElementById(id);
  });

  afterEach(() => {
    h.attackConfig.hideAttackConfig();
    h.close();
  });

  it('has a total-ports count and a privileged-ports input', () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    assert.equal($('attackEventsLabel').textContent, 'Total Destination Ports:');
    assert.equal($('attackEventsCount').value, '500');
    const extra = h.document.querySelector('.attack-extra-count');
    assert.equal(extra.dataset.key, 'privileged_ports');
    assert.equal(extra.value, '20');
    assert.equal(h.attackConfig.collectAttackOptions().privileged_ports, 20);

    h.attackConfig.hideAttackConfig();
    assert.equal($('attackExtraCounts').hidden, true);
    assert.equal($('attackExtraCounts').innerHTML, '');
  });

  it('offers Random / A&I / Custom for both the source and the destination', () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    const rows = [...h.document.querySelectorAll('.attack-identity-row')];
    assert.deepEqual(rows.map((r) => r.dataset.field), ['src_ip', 'dest_ip']);
    rows.forEach((r) => {
      const opts = [...r.querySelectorAll('.attack-identity-mode option')].map((o) => o.value);
      assert.deepEqual(opts, ['random', 'ai', 'custom']);
    });
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity,
      { src_ip: { mode: 'random' }, dest_ip: { mode: 'random' } });
  });

  it('A&I shows an asset picker of name and IP, and sends the chosen IP', async () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    const row = h.document.querySelector('.attack-identity-row[data-field=src_ip]');
    const mode = row.querySelector('.attack-identity-mode');
    const picker = row.querySelector('.attack-identity-asset');
    assert.equal(picker.hidden, true);

    mode.value = 'ai';
    change(mode);
    await settle();
    assert.equal(picker.hidden, false);
    const labels = [...picker.querySelectorAll('option')].map((o) => o.textContent);
    assert.deepEqual(labels, ['wks-01 — 10.50.1.10', 'crown-jewel — 10.60.2.10'],
      'only assets with an IP, shown as name — IP');

    picker.value = '10.60.2.10';
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.src_ip,
      { mode: 'ai', value: '10.60.2.10' });
    assert.equal(h.attackConfig.collectAttackOptions().use_assets_identities, true);
    assert.equal($('attackAiFields').hidden, false, 'the environment fields panel opens');
  });

  it('Custom types an address; Random sends no value and no environment', async () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    const row = h.document.querySelector('.attack-identity-row[data-field=dest_ip]');
    const mode = row.querySelector('.attack-identity-mode');
    mode.value = 'custom';
    change(mode);
    const input = row.querySelector('.attack-identity-value');
    assert.equal(input.hidden, false);
    input.value = '192.168.9.9';
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.dest_ip,
      { mode: 'custom', value: '192.168.9.9' });
    assert.equal(h.attackConfig.collectAttackOptions().use_assets_identities, false);
  });

  it('shows the rate as a total, shared over the three sourcetypes', () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    $('attackNoise').checked = true;
    change($('attackNoise'));
    assert.match($('attackRate').textContent, /^≈ 11\.7 events\/s — 500 \+ 200 \/ 60 s, split over 3 sourcetypes$/);
  });

  it('an edited scan comes back as saved, asset picked by its IP', async () => {
    h.attackConfig.showAttackConfig('paloalto_vertical_port_scan', VERTICAL);
    h.attackConfig.hydrateAttackConfig({
      attack_sources: [{ log_type: 'cisco_asa', sourcetype: 'cisco:asa', render_format: 'default' }],
      attack_identity: { src_ip: { mode: 'ai', value: '10.50.1.10' },
                         dest_ip: { mode: 'custom', value: '192.168.3.3' } },
      privileged_ports: 30, attack_events_count: 600, use_assets_identities: true,
    });
    await settle();
    assert.equal($('attackEventsCount').value, '600');
    assert.equal(h.document.querySelector('.attack-extra-count').value, '30');
    const src = h.document.querySelector('.attack-identity-row[data-field=src_ip]');
    assert.equal(src.querySelector('.attack-identity-mode').value, 'ai');
    assert.equal(src.querySelector('.attack-identity-asset').value, '10.50.1.10');
    const dest = h.document.querySelector('.attack-identity-row[data-field=dest_ip]');
    assert.equal(dest.querySelector('.attack-identity-value').value, '192.168.3.3');
    const opts = h.attackConfig.collectAttackOptions();
    assert.equal(opts.privileged_ports, 30);
    assert.equal(opts.attack_identity.src_ip.value, '10.50.1.10');
  });
});

describe('AD SID history attack configuration', () => {
  let h;
  let $;

  // As the API describes windows_ad_sid_history_addition.
  const SID_HISTORY = {
    name: 'Windows AD Privileged Account SID History Addition', log_type: 'windows',
    field_behaviors: {}, noise: true, destinations: ['file', 'configuration'],
    destinations_note: 'Windows is not collected over syslog, so it is sent to a Local File or HEC only.',
    datamodel: null,
    data_sources: [{
      log_type: 'windows', sourcetype: 'WinEventLog:Security',
      label: 'Windows Security · account changed (4738, 4742)',
      formats: [{ value: 'xml', sourcetype: 'XmlWinEventLog', source: 'XmlWinEventLog:Security' },
                { value: 'classic', sourcetype: 'WinEventLog', source: 'WinEventLog:Security' }],
      delivery: { default: 'uf', offered: { file: [], syslog: [], configuration: [] } },
    }],
    defaults: { events: 1, noise_events: 20, duration: 30 },
    count_label: 'Number of Events', count_hint: 'Each event triggers on its own.',
    identity_fields: [
      { field: 'host', mode: 'asset', label: 'Host', picker: 'assets',
        picker_value: 'nt_host', kind: 'hostname', hint: 'Follows the destination.' },
      { field: 'src_user', mode: 'asset', label: 'Source User', picker: 'identities',
        picker_value: 'username', kind: 'username', hint: 'The account making the change.' },
      { field: 'dest', mode: 'asset', label: 'Destination', picker: 'assets',
        picker_value: 'nt_host', kind: 'hostname', hint: 'The domain controller.' },
      { field: 'sid_history', mode: 'text', label: 'Privileged SID planted', kind: 'sid',
        default: 'S-1-5-21-1004336348-1177238915-682003330-512',
        hint: 'Already have your Assets & Identities in Enterprise Security? Use one of yours.' },
    ],
    warning: {
      text: 'the detection ends in a lookup against your Enterprise Security identities, '
            + 'and fires for none of them unless one carries a SID in `identity` and '
            + '`privileged` in `category`. Add that row to an active identities lookup, '
            + 'copying the SID below:',
      code: 'S-1-5-21-1004336348-1177238915-682003330-512',
    },
  };

  const ASSETS = [{ id: 'a1', name: 'dc-lab', ip: '10.1.1.1', nt_host: 'DC-LAB-01' },
                  { id: 'a2', name: 'no-hostname', ip: '10.1.1.2', nt_host: '' }];
  const IDENTITIES = [{ id: 'u1', username: 'adm.lab' }, { id: 'u2', username: 'jsmith' }];

  function fetchWithEnvironment(base) {
    return async (url, options) => {
      if (String(url) === '/api/entities') return { ok: true, status: 200, json: async () => ASSETS };
      if (String(url) === '/api/accounts') return { ok: true, status: 200, json: async () => IDENTITIES };
      if (String(url).startsWith('/api/environment/attack-impact/')) return { ok: true, status: 200, json: async () => IMPACT };
      return base(url, options);
    };
  }

  const change = (el, type = 'change') => el.dispatchEvent(new h.window.Event(type, { bubbles: true }));
  const row = (field) => h.document.querySelector(`.attack-identity-row[data-field=${field}]`);

  beforeEach(async () => {
    h = await createHarness();
    globalThis.fetch = fetchWithEnvironment(globalThis.fetch);
    h.attackConfig.initAttackConfig();
    $ = (id) => h.document.getElementById(id);
  });

  afterEach(() => {
    h.attackConfig.hideAttackConfig();
    h.close();
  });

  it('applies its defaults: one event, twenty benign, thirty seconds', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    assert.equal($('attackEventsCount').value, '1');
    assert.equal($('attackNoiseCount').value, '20');
    assert.equal($('attackDuration').value, '30');
    assert.equal(h.document.querySelector('.attack-extra-count'), null, 'no threshold here');
    assert.equal($('attackRate').textContent, '≈ 0.03 events/s — 1 / 30 s');
  });

  it('keeps XML as the default format, with classic still offered', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const format = h.document.querySelector('.attack-source-format');
    assert.deepEqual([...format.options].map((o) => o.textContent), ['XmlWinEventLog', 'WinEventLog']);
    assert.equal(format.value, 'xml');
    assert.equal(h.attackConfig.collectAttackOptions().attack_sources[0].render_format, 'xml');
  });

  it('goes to a file or HEC, never syslog', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const radio = (v) => h.document.querySelector(`input[name="destination_type"][value="${v}"]`);
    assert.equal(radio('syslog').disabled, true);
    assert.equal(radio('file').disabled, false);
    assert.equal(radio('configuration').disabled, false);
  });

  it('picks the host and destination from the assets, by host name', async () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const mode = row('dest').querySelector('.attack-identity-mode');
    mode.value = 'ai';
    change(mode);
    await settle();
    const picker = row('dest').querySelector('.attack-identity-asset');
    assert.deepEqual([...picker.options].map((o) => o.textContent), ['dc-lab — DC-LAB-01'],
      'only assets that have a host name, shown as name — host');
    assert.equal(h.attackConfig.collectAttackOptions().attack_identity.dest.value, 'DC-LAB-01');
  });

  it('picks the source user from the identities, by username', async () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const mode = row('src_user').querySelector('.attack-identity-mode');
    mode.value = 'ai';
    change(mode);
    await settle();
    const picker = row('src_user').querySelector('.attack-identity-asset');
    assert.deepEqual([...picker.options].map((o) => o.textContent), ['adm.lab', 'jsmith']);
    picker.value = 'jsmith';
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.src_user,
      { mode: 'ai', value: 'jsmith' });
  });

  it('warns with the steps and the SID to copy, and hides it again afterwards', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const warning = $('attackWarning');
    assert.equal(warning.hidden, false);
    assert.match(warning.textContent, /^Before you run this — /);
    assert.match(warning.textContent, /add that row to an active identities lookup/i);
    const code = warning.querySelector('code.attack-warning-code');
    assert.equal(code.textContent, 'S-1-5-21-1004336348-1177238915-682003330-512',
      'the SID is there to be copied');

    h.attackConfig.hideAttackConfig();
    assert.equal(warning.hidden, true);
    assert.equal(warning.textContent, '');
  });

  it('offers the same SID as a pre-filled input, which the attack sends', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    const input = row('sid_history').querySelector('.attack-identity-value');
    const shown = $('attackWarning').querySelector('code').textContent;
    assert.equal(input.value, shown, 'copy it from the warning, send exactly it');
    assert.equal(row('sid_history').querySelector('.attack-identity-mode'), null,
      'no Random / A&I choice: a fixed value is the point');
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.sid_history,
      { value: shown });

    input.value = 'S-1-5-21-9-9-9-519';
    assert.deepEqual(h.attackConfig.collectAttackOptions().attack_identity.sid_history,
      { value: 'S-1-5-21-9-9-9-519' }, 'their own SID wins');
  });

  it('shows no warning on an attack that has none', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    h.attackConfig.showAttackConfig('scan', { ...SID_HISTORY, warning: undefined });
    assert.equal($('attackWarning').hidden, true);
    assert.equal($('attackWarning').textContent, '');
  });

  it('gives each field a placeholder of its own kind', () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    assert.match(row('host').querySelector('.attack-identity-value').placeholder, /^DC0\d$/);
    assert.match(row('src_user').querySelector('.attack-identity-value').placeholder, /^[\w.]+$/);
    assert.equal(row('host').querySelector('.attack-identity-value').getAttribute('pattern'), null,
      'a host name is not an IP address');
  });

  it('hides the HEC Host override, because the attack names the machine itself', () => {
    const form = $('createSenderForm');
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    assert.ok(form.classList.contains('attack-owns-host'));
    assert.equal(h.attackConfig.attackOwnsHost(), true);

    h.attackConfig.hideAttackConfig();
    assert.ok(!form.classList.contains('attack-owns-host'));
    assert.equal(h.attackConfig.attackOwnsHost(), false);
  });

  it('an edited attack comes back as saved', async () => {
    h.attackConfig.showAttackConfig('windows_ad_sid_history_addition', SID_HISTORY);
    h.attackConfig.hydrateAttackConfig({
      attack_identity: { host: { mode: 'random' },
                         dest: { mode: 'ai', value: 'DC-LAB-01' },
                         src_user: { mode: 'custom', value: 'svc_adsync' } },
      attack_events_count: 4, attack_noise: true, attack_noise_count: 9,
    });
    await settle();
    assert.equal(row('dest').querySelector('.attack-identity-asset').value, 'DC-LAB-01');
    assert.equal(row('src_user').querySelector('.attack-identity-value').value, 'svc_adsync');

    const options = h.attackConfig.collectAttackOptions();
    assert.equal(options.attack_identity.host.mode, 'random');
    assert.equal(options.attack_identity.dest.value, 'DC-LAB-01');
    assert.equal(options.attack_noise_count, 9);
  });
});
