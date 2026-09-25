/**
 * jsdom harness for the sender form.
 *
 * Loads templates/index.html and the ES modules from static/js/ exactly as the
 * browser does — no copies, no shims inside application code. The only things
 * provided here are the browser globals jsdom does not expose to Node and a
 * fetch stub standing in for the Flask API.
 *
 * APP_ROOT selects which tree to load, so the same suite can be pointed at a
 * historical checkout to prove a regression test actually catches its bug.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { JSDOM } from 'jsdom';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const APP_ROOT = process.env.APP_ROOT
  ? path.resolve(process.env.APP_ROOT)
  : path.resolve(HERE, '..', 'log-generator');

/**
 * Registry fixture: shape mirrors /api/ta-registry, content kept minimal.
 *
 * The wire metadata below (hec_default_sourcetype, hec_source, syslog_viable) is
 * the contract the form is tested against, so it is spelled out here rather than
 * imported. tests/test_source_metadata.py asserts it still matches ta_registry.py,
 * which stays the single source of truth for the running app.
 */
export const REGISTRY = {
  paloalto: {
    name: 'paloalto', full_name: 'Splunk Add-on for Palo Alto Networks',
    display_name: 'Palo Alto', vendor: 'Palo Alto Networks',
    hec_default_sourcetype: 'pan:log',
    syslog_viable: true,   // frames itself, so no syslog_framing and no option
    delivery: {"default":"syslog","offered":{"file":["uf","syslog"],"syslog":[],"configuration":[]}},
    sourcetypes: [
      { name: 'pan:traffic', description: '', datamodels: ['Network_Traffic'],
        datamodel_conditions: [], fields: [] },
      { name: 'pan:threat', description: '', datamodels: ['Intrusion_Detection'],
        datamodel_conditions: [], fields: [] },
      { name: 'pan:system', description: '', datamodels: ['Authentication'],
        datamodel_conditions: [], fields: [] },
    ],
  },
  windows: {
    name: 'windows', full_name: 'Splunk Add-on for Microsoft Windows',
    display_name: 'Windows', vendor: 'Microsoft',
    hec_default_sourcetype_by_render_format: { xml: 'XmlWinEventLog', classic: 'WinEventLog' },
    syslog_viable: false,
    delivery: {"default":"uf","offered":{"file":[],"syslog":[],"configuration":[]}},
    sourcetypes: [
      { name: 'WinEventLog:Security', description: '', datamodels: ['Authentication'],
        hec_source_by_render_format: {
          xml: 'XmlWinEventLog:Security', classic: 'WinEventLog:Security' },
        datamodel_conditions: [], fields: [] },
      { name: 'WinEventLog:System', description: '', datamodels: ['Change'],
        hec_source_by_render_format: {
          xml: 'XmlWinEventLog:System', classic: 'WinEventLog:System' },
        datamodel_conditions: [], fields: [] },
      { name: 'WinEventLog:Application', description: '', datamodels: ['Updates'],
        hec_source_by_render_format: {
          xml: 'XmlWinEventLog:Application', classic: 'WinEventLog:Application' },
        datamodel_conditions: [], fields: [] },
    ],
  },
  // An umbrella TA: five categories, one sourcetype. The sourcetype selector
  // cannot express which of them you want, so the category group has to stay.
  sysmon: {
    name: 'sysmon', full_name: 'Splunk Add-on for Sysmon', display_name: 'Sysmon',
    vendor: 'Microsoft',
    hec_default_sourcetype: 'XmlWinEventLog',
    syslog_viable: false,
    delivery: {"default":"uf","offered":{"file":[],"syslog":[],"configuration":[]}},
    sourcetypes: [
      { name: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', description: '',
        datamodels: ['Endpoint'], hec_source: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        datamodel_conditions: [], fields: [] },
    ],
  },
  ssh: {
    name: 'ssh', full_name: 'SSH (syslog-based)', display_name: 'SSH (Linux)',
    vendor: 'OpenSSH / Linux',
    syslog_viable: true,
    syslog_framing: { facility: 'authpriv', severity: 'info', tag: 'sshd' },
    delivery: {"default":"uf","offered":{"file":["uf","syslog"],"syslog":["uf","syslog"],"configuration":[]}},
    sourcetypes: [
      { name: 'linux_secure', description: '', datamodels: ['Authentication'],
        hec_source: '/var/log/secure',
        datamodel_conditions: [], fields: [] },
    ],
  },
};

/** METADATA.sources as /api/log-types returns it (the registry↔generator bridge). */
const LOG_TYPES = {
  paloalto: { name: 'Palo Alto Firewall', description: 'PAN-OS logs', sources: [
    { id: 'traffic', name: 'Traffic', sourcetype: 'pan:traffic' },
    { id: 'threat', name: 'Threat', sourcetype: 'pan:threat' },
    { id: 'system', name: 'System', sourcetype: 'pan:system' },
  ]},
  windows: { name: 'Windows Event Log', description: 'Windows logs', sources: [
    { id: 'Security', name: 'Security', sourcetype: 'WinEventLog:Security' },
    { id: 'Application', name: 'Application', sourcetype: 'WinEventLog:Application' },
    { id: 'System', name: 'System', sourcetype: 'WinEventLog:System' },
  ]},
  sysmon: { name: 'Sysmon', description: 'Sysmon events', sources: [
    { id: 'process_creation', name: 'Process creation',
      sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' },
    { id: 'file_create', name: 'File created',
      sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' },
    { id: 'registry_set', name: 'Registry value set',
      sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' },
    { id: 'registry_key', name: 'Registry key added or deleted',
      sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' },
    { id: 'registry_rename', name: 'Registry object renamed',
      sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' },
  ]},
  ssh: { name: 'SSH Auth Log', description: 'auth.log', sources: [
    { id: 'auth_success', name: 'Success' },
    { id: 'auth_failed', name: 'Failed' },
  ]},
};

function makeFetch(senders) {
  return async (url) => {
    const reply = (body) => ({ ok: true, status: 200, json: async () => body });

    if (url === '/api/ta-registry') {
      return reply({ tas: Object.values(REGISTRY).map(
        ({ name, full_name, display_name, vendor }) => ({ name, full_name, display_name, vendor })) });
    }
    const ta = url.match(/^\/api\/ta-registry\/([^/]+)$/);
    if (ta) return reply(REGISTRY[decodeURIComponent(ta[1])] || {});

    if (url === '/api/log-types') return reply(LOG_TYPES);
    if (url === '/api/attack-types') return reply({});
    if (url === '/api/network-pools') return reply({ categories: {} });
    if (url === '/api/environment/counts') return reply({});
    if (url === '/api/configurations') return reply([]);
    if (url === '/api/simulations') return reply([]);
    if (url === '/api/syslog-destinations') return reply([]);
    if (url === '/api/senders') return reply(Object.values(senders));

    const one = url.match(/^\/api\/senders\/([^/?]+)$/);
    if (one) return reply(senders[decodeURIComponent(one[1])] || { error: 'not found' });

    if (url.startsWith('/api/environment/impact/')) return reply([]);
    return reply({});
  };
}

/**
 * Install a fresh DOM (and the browser globals) for one test.
 *
 * The application modules are a singleton graph, exactly as they are in the
 * browser: senders.js imports sender-form.js by its literal path, so handing
 * the test a cache-busted copy would give the two files different module
 * state. Instead each test gets a new document and re-runs initSenderForm(),
 * then clears the carried-over state through the module's own
 * resetSenderForm() — the same call the "+ Add Sender" button makes.
 */
export async function createHarness({ senders = {}, fetchImpl } = {}) {
  const html = fs.readFileSync(path.join(APP_ROOT, 'templates', 'index.html'), 'utf8');
  const dom = new JSDOM(html, { url: 'http://localhost:5002/', runScripts: 'outside-only' });
  const { window } = dom;

  installGlobals(window, fetchImpl || makeFetch(senders));
  const scrolled = installScrolling(window);

  const mods = await loadAppModules();
  mods.state.setLogTypes(LOG_TYPES);
  mods.state.setAttackTypes({});

  wireLogTypeListener(window.document, mods);
  await mods.senderForm.initSenderForm();
  mods.senderForm.resetSenderForm();

  return {
    dom,
    window,
    document: window.document,
    scrolled,
    ...mods,
    close: () => window.close(),
  };
}

/**
 * A harness with the simulation tab initialised and its grid populated.
 *
 * Same DOM and same modules as createHarness — the simulation form reads the
 * shipped index.html like every other tab — with initSimulation() wired and one
 * loadSimulations() done, so the per-source rows exist to be driven.
 */
export async function createSimulationHarness(options = {}) {
  const harness = await createHarness(options);
  harness.simulation.initSimulation();
  await harness.simulation.loadSimulations();
  return harness;
}

/** Pick the simulation destination, the way clicking the radio does. */
export function selectSimDestination(document, value) {
  const radio = document.querySelector(
    `input[name="sim_destination_type"][value="${value}"]`);
  radio.checked = true;
  radio.dispatchEvent(new globalThis.Event('change', { bubbles: true }));
}

/** Type a volume into one source row and let the row react. */
export function setSimVolume(document, logType, value) {
  const input = document.querySelector(
    `.sim-volume-input[data-log-type="${logType}"]`);
  input.value = String(value);
  input.dispatchEvent(new globalThis.Event('input', { bubbles: true }));
  return input;
}

/** The per-source index rows that are actually on screen, as {logType: {value, placeholder}}. */
export function simIndexRows(document) {
  const out = {};
  document.querySelectorAll('.sim-index-row').forEach((row) => {
    if (row.style.display === 'none') return;
    const input = row.querySelector('.sim-index-input');
    out[row.dataset.logType] = { value: input.value, placeholder: input.placeholder };
  });
  return out;
}

let _installed = null;

/**
 * The scrolling jsdom does not implement, recorded rather than performed.
 *
 * jsdom has no layout, so `scrollIntoView` is simply absent and `scrollTo` is a
 * stub that complains. Both are real browser API the page is entitled to call,
 * so the harness supplies them — and keeps what they were asked to do, which is
 * the only way a test can see where the page sent the reader.
 */
function installScrolling(window) {
  const calls = { to: [], intoView: [] };
  window.scrollTo = (...args) => { calls.to.push(args[0]); };
  window.HTMLElement.prototype.scrollIntoView = function (options) {
    calls.intoView.push({ element: this, options });
  };
  return calls;
}

function installGlobals(window, fetchImpl) {
  const values = {
    window, document: window.document, Event: window.Event,
    HTMLElement: window.HTMLElement, FormData: window.FormData,
    Node: window.Node,
    CSS: window.CSS && window.CSS.escape
      ? window.CSS
      : { escape: (s) => String(s).replace(/[^\w-]/g, (c) => '\\' + c) },
    fetch: fetchImpl,
    confirm: () => true,
    alert: () => {},
  };
  for (const [key, value] of Object.entries(values)) {
    // Some globals (navigator, ...) are getter-only in recent Node; defineProperty
    // keeps the harness working whichever kind the runtime exposes.
    try {
      globalThis[key] = value;
    } catch {
      Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
    }
  }
  _installed = values;
}

let _modules = null;

/** Load the application ES modules once, straight from static/js/. */
async function loadAppModules() {
  if (_modules) return _modules;
  const load = (rel) =>
    import(pathToFileURL(path.join(APP_ROOT, 'static', 'js', rel)).href);
  _modules = {
    state: await load('modules/state.js'),
    senderForm: await load('modules/sender-form.js'),
    senders: await load('modules/senders.js'),
    simulation: await load('modules/simulation.js'),
    attackConfig: await load('modules/attack-config.js'),
    sourcetypeConfig: await load('modules/sourcetype-config.js'),
  };
  return _modules;
}

/** Reproduces app.js's #logType listener: which per-technology groups show. */
function wireLogTypeListener(document, { state, sourcetypeConfig }) {
  const { SOURCETYPE_CONFIG, getAllFormGroupIds } = sourcetypeConfig;
  document.getElementById('logType').addEventListener('change', (event) => {
    const selected = event.target.value;
    const hideAll = () => getAllFormGroupIds().forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    if (selected && state.state.attackTypes[selected]) {
      hideAll();
    } else if (selected && state.state.logTypes[selected]) {
      document.getElementById('frequencyGroup').style.display = 'block';
      document.getElementById('useAssetsIdentitiesGroup').style.display = 'block';
      hideAll();
      const config = SOURCETYPE_CONFIG[selected];
      if (config) config.formGroups.forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'block';
      });
    } else {
      hideAll();
    }
  });
}

/** Is a form group actually shown? */
export function isVisible(document, id) {
  const el = document.getElementById(id);
  if (!el) return false;
  return el.style.display !== 'none';
}

/** The value the form would really POST/PUT for a given field. */
export function submittedValue(document, field) {
  const form = document.getElementById('createSenderForm');
  return new globalThis.FormData(form).get(field);
}

/** Which Splunk sourcetypes are ticked in the Phase 4a selector. */
export function checkedSourcetypes(document) {
  return Array.from(
    document.querySelectorAll('input[name="splunk_sourcetypes"]:checked')
  ).map((cb) => cb.value).sort();
}

/** Which generator categories are ticked in a legacy per-TA checkbox group. */
export function checkedCategories(document, groupName) {
  return Array.from(
    document.querySelectorAll(`input[name="${groupName}"]:checked`)
  ).map((cb) => cb.value).sort();
}

/** The per-sourcetype `source` rows, as {sourcetype: value}. */
export function sourceRows(document) {
  const out = {};
  document.querySelectorAll('#hecSourceMapRows input.hec-source-input')
    .forEach((input) => { out[input.dataset.sourcetype] = input.value; });
  return out;
}

/** The per-sourcetype `sourcetype` rows, as {sourcetype: value}. */
export function sourcetypeRows(document) {
  const out = {};
  document.querySelectorAll('#hecSourcetypeMapRows input.hec-st-input')
    .forEach((input) => { out[input.dataset.sourcetype] = input.value; });
  return out;
}

/** Type into one `source` row, the way a user does. */
export function typeSource(document, sourcetype, value) {
  const input = document.querySelector(
    `#hecSourceMapRows input.hec-source-input[data-sourcetype="${sourcetype}"]`);
  if (!input) throw new Error(`no source row for ${sourcetype}`);
  input.value = value;
  input.dispatchEvent(new globalThis.Event('input'));
}

/** Tick / untick one Splunk sourcetype checkbox and let the re-render settle. */
export async function toggleSourcetype(document, name) {
  const cb = document.querySelector(
    `input[name="splunk_sourcetypes"][value="${name}"]`);
  if (!cb) throw new Error(`no checkbox for ${name}`);
  cb.checked = !cb.checked;
  cb.dispatchEvent(new globalThis.Event('change'));
  await settle();
}

/** Pick a destination type radio, the way a user does. */
export function selectDestinationType(document, value) {
  const radio = document.querySelector(
    `input[name="destination_type"][value="${value}"]`);
  radio.checked = true;
  radio.dispatchEvent(new globalThis.Event('change'));
}

/** Pick a render format, the way a user does. */
export function selectRenderFormat(document, value) {
  const select = document.getElementById('renderFormat');
  select.value = value;
  select.dispatchEvent(new globalThis.Event('change'));
}

/** Pick a technology the way a user does, and wait for the async render. */
export async function selectTechnology(document, taName) {
  const select = document.getElementById('techSelect');
  select.value = taName;
  select.dispatchEvent(new globalThis.Event('change'));
  await settle();
}

/** Let queued microtasks and the module's own awaits settle. */
export const settle = () => new Promise((resolve) => setTimeout(resolve, 25));
