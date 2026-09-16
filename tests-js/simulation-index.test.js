/**
 * The per-source HEC index rows in the simulation form.
 *
 * The rule they encode: a source row names an index only when the simulation
 * has somewhere to send one. Over syslog the collector decides, so the row must
 * not even offer the choice — and a row left blank has to keep following the
 * simulation-wide field rather than freeze the value it happened to show.
 */

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import {
  createSimulationHarness,
  selectSimDestination,
  setSimVolume,
  simIndexRows,
} from './harness.mjs';

describe('simulation per-source index', () => {
  let harness;
  let document;

  beforeEach(async () => {
    harness = await createSimulationHarness();
    document = harness.document;
    selectSimDestination(document, 'configuration');
    document.getElementById('simHecIndex').value = 'main_idx';
    document.getElementById('simHecIndex')
      .dispatchEvent(new harness.window.Event('input', { bubbles: true }));
  });

  after(() => harness && harness.close());

  it('shows a row only once that source has a volume', () => {
    assert.deepEqual(simIndexRows(document), {});

    setSimVolume(document, 'ssh', 1);
    assert.deepEqual(Object.keys(simIndexRows(document)), ['ssh']);
  });

  it('carries the HEC index as a placeholder, not as a value', () => {
    setSimVolume(document, 'ssh', 1);
    // A value would freeze the index at whatever it said when the row appeared;
    // a placeholder lets the row keep following the field above it.
    assert.deepEqual(simIndexRows(document).ssh,
      { value: '', placeholder: 'main_idx' });
  });

  it('follows the HEC index when it changes afterwards', () => {
    setSimVolume(document, 'ssh', 1);
    const field = document.getElementById('simHecIndex');
    field.value = 'other_idx';
    field.dispatchEvent(new harness.window.Event('input', { bubbles: true }));

    assert.equal(simIndexRows(document).ssh.placeholder, 'other_idx');
  });

  it('hides every row over syslog, where the collector assigns the index', () => {
    setSimVolume(document, 'ssh', 1);
    assert.deepEqual(Object.keys(simIndexRows(document)), ['ssh']);

    selectSimDestination(document, 'syslog');
    assert.deepEqual(simIndexRows(document), {});

    selectSimDestination(document, 'configuration');
    assert.deepEqual(Object.keys(simIndexRows(document)), ['ssh']);
  });

  it('sends the row index only where the row named one', async () => {
    setSimVolume(document, 'ssh', 1);
    setSimVolume(document, 'windows', 1);
    document.querySelector('.sim-index-input[data-log-type="ssh"]').value = 'linux_idx';

    const sent = await submitSimulation(harness);
    const byType = Object.fromEntries(
      sent.sourcetypes.map((s) => [s.log_type, s.hec_index]));

    assert.equal(byType.ssh, 'linux_idx');
    assert.equal(byType.windows, null);   // the server fills it from hec_index
    assert.equal(sent.hec_index, 'main_idx');
  });

  it('sends no row index over syslog', async () => {
    setSimVolume(document, 'ssh', 1);
    document.querySelector('.sim-index-input[data-log-type="ssh"]').value = 'linux_idx';
    selectSimDestination(document, 'syslog');
    document.getElementById('simSyslogHost').value = 'sc4s';

    const sent = await submitSimulation(harness);
    assert.equal(sent.sourcetypes[0].hec_index, null);
  });
});

/** Submit the form and return the payload it POSTed. */
async function submitSimulation(harness) {
  const { document, window } = harness;
  document.getElementById('simName').value = 'sim';
  document.getElementById('simDurationValue').value = '60';
  document.getElementById('simDurationUnit').value = '1';
  document.getElementById('simConfigurationSelect').innerHTML =
    '<option value="c1" selected>c1</option>';

  let payload = null;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url === '/api/simulations' && options && options.method === 'POST') {
      payload = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => ({ success: true }) };
    }
    return realFetch(url, options);
  };
  try {
    document.getElementById('createSimulationForm')
      .dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(payload, 'the form did not POST a simulation');
  return payload;
}
