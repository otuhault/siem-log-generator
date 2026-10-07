/**
 * The Read Me tab's data source and add-on tables.
 *
 * They are the only part of the tab that is not prose: rendered from
 * /api/catalog, add-on grouping included, so the tab lists what this build
 * generates and the same add-ons the repository README names. These tests feed
 * a catalog payload and read the DOM back.
 */

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import { createHarness } from './harness.mjs';

const CATALOG = {
  sources: [
    { name: 'Active Directory', add_on: 'Splunk Add-on for Microsoft Windows',
      sourcetypes: [{ name: 'WinEventLog:Security' }] },
    { name: 'Palo Alto', add_on: 'Splunk Add-on for Palo Alto Networks',
      sourcetypes: [{ name: 'pan:traffic' }, { name: 'pan:threat' }] },
    { name: 'Windows', add_on: 'Splunk Add-on for Microsoft Windows',
      sourcetypes: [{ name: 'WinEventLog:Security' }, { name: 'WinEventLog:System' }] },
  ],
  add_ons: [
    { name: 'Splunk Add-on for Microsoft Windows', url: 'https://splunkbase.splunk.com/app/742',
      package: 'Splunk_TA_windows', version: '11.0.2', used_by: ['Active Directory', 'Windows'] },
    { name: 'Splunk Add-on for Palo Alto Networks', url: 'https://splunkbase.splunk.com/app/7523',
      package: 'Splunk_TA_paloalto_networks', version: '4.0.0', used_by: ['Palo Alto'] },
  ],
  attacks: [], datamodels: [],
};

let reply = () => ({ ok: true, status: 200, json: async () => CATALOG });

describe('the Read Me tab lists the data sources and the add-ons they need', () => {
  let h;

  before(async () => {
    h = await createHarness({
      fetchImpl: async (url) => {
        if (url === '/api/catalog') return reply();
        return { ok: true, status: 200, json: async () => ({}) };
      },
    });
  });
  beforeEach(() => {
    // The catalog is cached module-wide; each test asks for its own payload.
    h.catalog.resetCatalogCache();
    reply = () => ({ ok: true, status: 200, json: async () => CATALOG });
  });
  after(() => h.close());

  const rows = (id) => [...h.document.querySelectorAll(`#${id} tr`)]
    .map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent.trim()));

  it('has a contents entry pointing at its section', () => {
    const link = h.document.querySelector('.readme-toc a[href="#readme-data-sources"]');
    assert.ok(link, 'the Read Me contents does not list the section');
    assert.ok(h.document.getElementById('readme-data-sources'));
  });

  it('renders one row per source, with its sourcetypes and add-on', async () => {
    await h.readme.loadReadmeSources();
    assert.deepEqual(rows('readmeSourcesRows'), [
      ['Active Directory', 'WinEventLog:Security', 'Splunk Add-on for Microsoft Windows'],
      ['Palo Alto', 'pan:traffic, pan:threat', 'Splunk Add-on for Palo Alto Networks'],
      ['Windows', 'WinEventLog:Security, WinEventLog:System', 'Splunk Add-on for Microsoft Windows'],
    ]);
  });

  it('lists each add-on once, with every source that needs it', async () => {
    await h.readme.loadReadmeSources();
    const addOns = rows('readmeAddOnsRows');
    assert.equal(addOns.length, 2, 'Windows and Active Directory share one add-on');
    assert.deepEqual(addOns[0],
      ['Splunk Add-on for Microsoft Windows', 'Splunk_TA_windows', '11.0.2',
       'Active Directory, Windows']);
  });

  it('links each add-on to its Splunkbase page, in a new tab', async () => {
    await h.readme.loadReadmeSources();
    const links = [...h.document.querySelectorAll('#readmeAddOnsRows a')];
    assert.deepEqual(links.map((a) => a.getAttribute('href')),
      ['https://splunkbase.splunk.com/app/742', 'https://splunkbase.splunk.com/app/7523']);
    for (const a of links) assert.equal(a.getAttribute('target'), '_blank');
  });

  it('says so when the list cannot be loaded, rather than showing nothing', async () => {
    reply = () => { throw new Error('offline'); };
    await h.readme.loadReadmeSources();
    assert.match(h.document.getElementById('readmeSourcesRows').textContent,
      /Could not load/);
  });
});
