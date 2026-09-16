/**
 * The Catalog renders three views from one fetch.
 *
 * Sourcetypes absorbed what Configuration → Sourcetype Mapping used to show in
 * its own tab: the two read the same registry and said the same things, so the
 * mapping now opens from the sourcetype it describes. Data Models is the same
 * data inverted. Attacks is what Configuration → Attacks duplicated outright.
 *
 * catalog.js is a renderer — every value comes from /api/catalog, and
 * tests/test_catalog.py holds the payload against the registries. What is
 * tested here is that the page shows what it was given and invents nothing.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { createHarness } from './harness.mjs';

const CATALOG = {
  sources: [
    {
      key: 'paloalto', name: 'Palo Alto', vendor: 'Palo Alto Networks',
      add_on: 'Splunk_TA_paloalto', add_on_url: 'https://splunkbase.example/pan',
      add_on_version: '8.1.1', description: 'PAN-OS logs',
      sc4s_url: 'https://sc4s.example/pan',
      datamodels: ['Network_Traffic'], categories: [], attacks: [],
      sourcetypes: [
        {
          name: 'pan:traffic', wire: 'pan:log', description: 'Firewall traffic',
          datamodels: ['Network_Traffic'],
          eventtypes: ['pan_traffic'], tags: ['network', 'communicate'],
          datamodel_conditions: [{ when: 'always', eventtype: 'pan_traffic',
            tags: ['network', 'communicate'], datamodels: ['Network_Traffic'] }],
          fields: [
            { raw_field: 'src_ip', cim_field: 'src', datamodels: ['Network_Traffic'],
              ai_source: { type: 'entity', entity_type: 'endpoint', entity_field: 'ip' },
              csv_position: 8, extracted_from: '', description: 'Source address' },
            { raw_field: 'rule', cim_field: 'rule', datamodels: ['Network_Traffic'],
              ai_source: { type: 'random' }, csv_position: null,
              extracted_from: '', description: '' },
          ],
          entity_types: ['endpoint'], account_types: ['standard'],
        },
        // A second sourcetype on the same source, so a count of sourcetypes
        // cannot be mistaken for a count of sources.
        { name: 'pan:threat', wire: 'pan:log', description: 'Threat log',
          datamodels: ['Intrusion_Detection'], eventtypes: ['pan_threat'], tags: ['ids'],
          datamodel_conditions: [{ when: 'always', eventtype: 'pan_threat',
            tags: ['ids', 'attack'], datamodels: ['Intrusion_Detection'] }],
          fields: [], entity_types: [], account_types: [] },
      ],
    },
    {
      key: 'ssh', name: 'SSH (Linux)', vendor: 'OpenSSH', add_on: 'Splunk_TA_nix',
      add_on_url: '', add_on_version: '', description: 'auth log', sc4s_url: null,
      datamodels: [], categories: [], attacks: [],
      sourcetypes: [
        { name: 'linux_secure', wire: 'linux_secure', description: '', datamodels: [],
          eventtypes: [], tags: [], datamodel_conditions: [], fields: [],
          entity_types: [], account_types: [] },
      ],
    },
  ],
  datamodels: [
    { name: 'Network_Traffic', sources: ['Palo Alto'],
      sourcetypes: [{ name: 'pan:traffic', source: 'Palo Alto', source_key: 'paloalto' }],
      attacks: ['Internal Horizontal Port Scan'] },
    { name: 'Endpoint', sources: ['Windows'],
      sourcetypes: [{ name: 'WinEventLog:Security', source: 'Windows', source_key: 'windows' }],
      attacks: [] },
  ],
  attacks: [
    { key: 'scan', name: 'Internal Horizontal Port Scan', description: 'many hosts, one port',
      category: 'Network', source: 'paloalto', source_name: 'Palo Alto',
      datamodel: 'Network_Traffic', research_url: 'https://research.example/scan',
      sample: '<14>Jan 1 ... TRAFFIC' },
  ],
};

describe('the catalog', () => {
  let h;

  const fetchImpl = async (url) => ({
    ok: true, status: 200,
    json: async () => (url === '/api/catalog' ? CATALOG : {}),
  });

  const $ = (sel) => h.document.querySelector(sel);
  const all = (sel) => [...h.document.querySelectorAll(sel)];
  const text = (sel) => ($(sel)?.textContent || '').replace(/\s+/g, ' ').trim();

  beforeEach(async () => {
    h = await createHarness({ fetchImpl });
    const catalog = await import('../log-generator/static/js/modules/catalog.js');
    catalog.resetCatalogCache();   // the module is a singleton, as in the browser
    await catalog.loadCatalog();
  });

  afterEach(() => h.close());

  // ── the three panels ──────────────────────────────────────────────────────

  it('fills all three panels, and counts what is in them', () => {
    assert.equal(all('#catalogSources .catalog-source').length, 2);
    assert.equal(all('#catalogDatamodels .catalog-source').length, 2);
    assert.equal(all('#catalogAttacks tbody tr').length, 1);

    assert.equal(text('#catalogSourceCount'), '2');
    assert.equal(text('#catalogSourcetypeCount'), '3', 'sourcetypes, not sources');
    assert.equal(text('#catalogDatamodelCount'), '2');
    assert.equal(text('#catalogAttackCount'), '1');
  });

  it('opens on Sourcetypes, with one panel active', () => {
    const active = all('.catalog-subtab-content.active');
    assert.equal(active.length, 1);
    assert.equal(active[0].id, 'catalogSourcetypesTab');
  });

  // ── a sourcetype, and what it opens onto ──────────────────────────────────

  it('a sourcetype row starts closed and opens onto its mapping', () => {
    const row = $('.catalog-st-row');
    const detail = h.document.getElementById(row.getAttribute('aria-controls'));

    assert.equal(row.getAttribute('aria-expanded'), 'false');
    assert.equal(detail.hidden, true, 'the mapping is not shown until asked for');

    row.click();
    assert.equal(row.getAttribute('aria-expanded'), 'true');
    assert.equal(detail.hidden, false);

    row.click();
    assert.equal(detail.hidden, true, 'and it closes again');
  });

  it('the mapping is the registry\'s, rendered', () => {
    const row = $('.catalog-st-row');
    row.click();
    const detail = h.document.getElementById(row.getAttribute('aria-controls'));
    const shown = detail.textContent.replace(/\s+/g, ' ');

    assert.match(shown, /Datamodel matching rules/);
    assert.match(shown, /pan_traffic/, 'the eventtype that grants the datamodel');
    assert.match(shown, /src_ip/);
    assert.match(shown, /endpoint\.ip/, 'where the value comes from');
    assert.match(shown, /CSV #8/);
    assert.match(shown, /Assets used/);
  });

  it('says plainly when a sourcetype has no mapping recorded', () => {
    const rows = all('.catalog-st-row');
    rows[2].click();   // linux_secure: no rules, no fields
    const detail = h.document.getElementById(rows[2].getAttribute('aria-controls'));
    assert.match(detail.textContent, /No field mapping recorded/);
  });

  it('a field with no environment source reads as random, not as blank', () => {
    $('.catalog-st-row').click();
    const detail = h.document.getElementById($('.catalog-st-row').getAttribute('aria-controls'));
    const ruleRow = [...detail.querySelectorAll('tbody tr')]
      .find((tr) => tr.textContent.includes('rule'));
    assert.match(ruleRow.textContent, /random/);
  });

  it('names the wire sourcetype only where it differs from the final one', () => {
    const [pan, ssh] = all('#catalogSources .catalog-source');
    assert.match(pan.textContent, /sent as pan:log/, 'pan:traffic goes out as pan:log');
    assert.equal(ssh.querySelector('.catalog-wire'), null,
      'linux_secure goes out under its own name — saying so twice is noise');
  });

  // ── data models ───────────────────────────────────────────────────────────

  it('lists each datamodel with the sourcetypes that reach it', () => {
    const first = all('#catalogDatamodels .catalog-source')[0];
    assert.match(first.textContent, /Network_Traffic/);
    assert.match(first.textContent.replace(/\s+/g, ' '), /1 sourcetype from 1 source/);
    assert.match(first.querySelector('tbody').textContent, /pan:traffic/);
    assert.match(first.querySelector('tbody').textContent, /Palo Alto/);
  });

  it('names the attacks a datamodel carries, and stays silent when it has none', () => {
    const [traffic, endpoint] = all('#catalogDatamodels .catalog-source');
    assert.match(traffic.textContent, /Attacks detected through it/);
    assert.match(traffic.textContent, /Internal Horizontal Port Scan/);
    assert.ok(!endpoint.textContent.includes('Attacks detected through it'),
      'a datamodel with no attack says nothing rather than "none"');
  });

  // ── attacks ───────────────────────────────────────────────────────────────

  it('lists an attack with its source, datamodel and detection link', () => {
    const row = $('#catalogAttacks tbody tr');
    assert.match(row.textContent, /Internal Horizontal Port Scan/);
    assert.match(row.textContent, /Palo Alto/);
    assert.match(row.textContent, /Network_Traffic/);
    assert.equal(row.querySelector('a').href, 'https://research.example/scan');
  });

  // ── the renderer invents nothing ──────────────────────────────────────────

  it('badges SC4S only on the source that carries the link', () => {
    const [pan, ssh] = all('#catalogSources .catalog-source');
    assert.equal(pan.querySelector('.catalog-sc4s').href, 'https://sc4s.example/pan');
    assert.equal(ssh.querySelector('.catalog-sc4s'), null);
  });

  it('shows an add-on version only where there is one', () => {
    const [pan, ssh] = all('#catalogSources .catalog-source');
    assert.equal(pan.querySelector('.catalog-addon-version').textContent, 'v8.1.1');
    assert.equal(ssh.querySelector('.catalog-addon-version'), null);
  });

  it('marks a sourcetype its add-on maps to nothing', () => {
    const ssh = all('#catalogSources .catalog-source')[1];
    assert.match(ssh.querySelector('tbody').textContent, /no datamodel/);
  });
});
