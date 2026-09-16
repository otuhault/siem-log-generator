/**
 * The per-sourcetype `source` rows in the sender form.
 *
 * Every value shown comes from /api/ta-registry — the form holds no copy of it.
 * The tests below check that, that only edited values are handed back for
 * persistence, and that the rows do not leak between two senders (the same trap
 * hydrateFromSender() fell into twice, fixed in 8b2aac5).
 */

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import {
  createHarness,
  isVisible,
  selectDestinationType,
  selectRenderFormat,
  selectTechnology,
  settle,
  sourceRows,
  sourcetypeRows,
  toggleSourcetype,
  typeSource,
} from './harness.mjs';

const SENDERS = {
  'win-sec': {
    id: 'win-sec', name: 'Windows Security', log_type: 'windows',
    destination_type: 'file', destination: '/tmp/win.log',
    frequency: 10, enabled: false, logs_generated: 0,
    options: { sources: ['Security'] },
    attack_status: null,
  },
  'win-custom': {
    id: 'win-custom', name: 'Windows overridden', log_type: 'windows',
    destination_type: 'file', destination: '/tmp/win2.log',
    frequency: 10, enabled: false, logs_generated: 0,
    options: {
      sources: ['Security', 'System'],
      hec_source_map: { 'WinEventLog:Security': 'WinEventLog:Security' },
    },
    attack_status: null,
  },
  'win-classic': {
    id: 'win-classic', name: 'Windows classic', log_type: 'windows',
    destination_type: 'file', destination: '/tmp/win3.log',
    frequency: 10, enabled: false, logs_generated: 0,
    options: { sources: ['Security', 'System'], render_format: 'classic' },
    attack_status: null,
  },
  'pan-1': {
    id: 'pan-1', name: 'Palo sender', log_type: 'paloalto',
    destination_type: 'file', destination: '/tmp/pan.log',
    frequency: 20, enabled: false, logs_generated: 0,
    options: { log_types: ['traffic'] },
    attack_status: null,
  },
};

let harness;

async function editSender(id) {
  await harness.senders.editSender(id);
  await settle();
}

before(async () => {
  harness = await createHarness({ senders: SENDERS });
});

after(() => harness && harness.close());

beforeEach(() => harness.senderForm.resetSenderForm());

describe('source rows are prefilled from the registry', () => {
  it('windows gets one row per selected sourcetype', async () => {
    await selectTechnology(harness.document, 'windows');

    assert.equal(isVisible(harness.document, 'hecSourceMapGroup'), true,
      'the per-sourcetype source block stayed hidden');
    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Application': 'XmlWinEventLog:Application',
      'WinEventLog:Security': 'XmlWinEventLog:Security',
      'WinEventLog:System': 'XmlWinEventLog:System',
    });
  });

  it('the single free-text Source field gives way to the rows', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.equal(isVisible(harness.document, 'hecSourceSingleGroup'), false);
  });

  it('unticking a sourcetype drops its row', async () => {
    await selectTechnology(harness.document, 'windows');
    await toggleSourcetype(harness.document, 'WinEventLog:System');

    assert.deepEqual(Object.keys(sourceRows(harness.document)).sort(),
      ['WinEventLog:Application', 'WinEventLog:Security']);
  });

  it('a TA that documents no source gets no rows at all', async () => {
    await selectTechnology(harness.document, 'paloalto');

    assert.equal(isVisible(harness.document, 'hecSourceMapGroup'), false,
      'a source block appeared for a TA with nothing documented');
    assert.deepEqual(sourceRows(harness.document), {});
    assert.equal(isVisible(harness.document, 'hecSourceSingleGroup'), true,
      'the single Source field should stay available as the fallback');
  });

  it('every value shown comes from the API, not from the module', async () => {
    // ssh's source is a file path, nothing like the Windows channel names, and
    // the module has no way to derive one from the other. Showing it proves the
    // row is filled from /api/ta-registry rather than from a local table.
    await selectTechnology(harness.document, 'ssh');
    assert.deepEqual(sourceRows(harness.document), {
      'linux_secure': '/var/log/secure',
    });
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {},
      'showing the registry default must not persist it');
  });
});

describe('only edited values are persisted', () => {
  it('an untouched form hands back nothing', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {},
      'the registry defaults were persisted as if the user had typed them');
  });

  it('an edited row is handed back, the others are not', async () => {
    await selectTechnology(harness.document, 'windows');
    typeSource(harness.document, 'WinEventLog:Security', 'WinEventLog:Security');

    assert.deepEqual(harness.senderForm.getHecSourceMap(), {
      'WinEventLog:Security': 'WinEventLog:Security',
    });
  });

  it('clearing a row falls back to the registry rather than emitting empty', async () => {
    await selectTechnology(harness.document, 'windows');
    typeSource(harness.document, 'WinEventLog:System', '   ');

    assert.deepEqual(harness.senderForm.getHecSourceMap(), {},
      'a blank row must not be persisted as an empty source');
  });
});

describe('edit flow', () => {
  it('restores a persisted override and leaves the rest on the registry', async () => {
    await editSender('win-custom');

    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Security': 'WinEventLog:Security',
      'WinEventLog:System': 'XmlWinEventLog:System',
    });
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {
      'WinEventLog:Security': 'WinEventLog:Security',
    });
  });

  it('does not leak one sender’s override into the next', async () => {
    await editSender('win-custom');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {
      'WinEventLog:Security': 'WinEventLog:Security',
    }, 'premise: the first sender carries an override');

    await editSender('win-sec');
    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Security': 'XmlWinEventLog:Security',
    }, 'the previous sender’s override leaked into this one');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {});
  });

  it('switching to a TA with no documented source clears the rows', async () => {
    await editSender('win-custom');
    assert.notDeepEqual(sourceRows(harness.document), {}, 'premise: rows exist');

    await editSender('pan-1');
    assert.deepEqual(sourceRows(harness.document), {},
      'windows rows survived a move to Palo Alto');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {});
  });

  it('a reset clears the rows', async () => {
    await editSender('win-custom');
    harness.senderForm.resetSenderForm();

    assert.deepEqual(sourceRows(harness.document), {});
    assert.equal(isVisible(harness.document, 'hecSourceMapGroup'), false);
  });
});

describe('warnings', () => {
  it('classic render format warns, XML does not', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.equal(isVisible(harness.document, 'renderFormatWarning'), false,
      'XML is the parsed format, it must not warn');

    selectRenderFormat(harness.document, 'classic');
    assert.equal(isVisible(harness.document, 'renderFormatWarning'), true);

    selectRenderFormat(harness.document, 'xml');
    assert.equal(isVisible(harness.document, 'renderFormatWarning'), false);
  });

  it('the classic option itself is left in place', async () => {
    await selectTechnology(harness.document, 'windows');
    selectRenderFormat(harness.document, 'classic');

    const select = harness.document.getElementById('renderFormat');
    assert.equal(select.disabled, false, 'the option must stay usable');
    assert.equal(select.value, 'classic', 'the choice must be honoured');
    assert.deepEqual(Array.from(select.options).map((o) => o.value), ['xml', 'classic']);
  });

  it('the classic warning is hidden for a TA that has no render format', async () => {
    await selectTechnology(harness.document, 'windows');
    selectRenderFormat(harness.document, 'classic');
    assert.equal(isVisible(harness.document, 'renderFormatWarning'), true);

    await selectTechnology(harness.document, 'paloalto');
    assert.equal(isVisible(harness.document, 'renderFormatWarning'), false,
      'the warning followed a technology that has no render format at all');
  });

  it('syslog warns for windows and stays quiet for palo alto', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), false,
      'the default destination is a file, nothing to warn about');

    selectDestinationType(harness.document, 'syslog');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), true);

    selectDestinationType(harness.document, 'configuration');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), false,
      'HEC carries the source metadata, so it must not warn');

    await selectTechnology(harness.document, 'paloalto');
    selectDestinationType(harness.document, 'syslog');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), false,
      'Palo Alto is collected over syslog — warning it is wrong');
  });

  it('the syslog warning follows an edited windows sender', async () => {
    await selectTechnology(harness.document, 'paloalto');
    selectDestinationType(harness.document, 'syslog');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), false);

    await editSender('win-sec');
    selectDestinationType(harness.document, 'syslog');
    assert.equal(isVisible(harness.document, 'syslogViabilityWarning'), true);
  });
});

describe('render_format drives both wire values', () => {
  it('xml shows the XML pair, classic shows the classic pair', async () => {
    await selectTechnology(harness.document, 'windows');

    assert.deepEqual(sourcetypeRows(harness.document), {
      'WinEventLog:Application': 'XmlWinEventLog',
      'WinEventLog:Security': 'XmlWinEventLog',
      'WinEventLog:System': 'XmlWinEventLog',
    }, 'xml must announce the bare XmlWinEventLog sourcetype');
    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Application': 'XmlWinEventLog:Application',
      'WinEventLog:Security': 'XmlWinEventLog:Security',
      'WinEventLog:System': 'XmlWinEventLog:System',
    });

    selectRenderFormat(harness.document, 'classic');

    assert.deepEqual(sourcetypeRows(harness.document), {
      'WinEventLog:Application': 'WinEventLog',
      'WinEventLog:Security': 'WinEventLog',
      'WinEventLog:System': 'WinEventLog',
    }, 'switching to classic must switch the sourcetype too');
    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Application': 'WinEventLog:Application',
      'WinEventLog:Security': 'WinEventLog:Security',
      'WinEventLog:System': 'WinEventLog:System',
    }, 'the two forms must never be mixed');
  });

  it('the two forms are never mixed, in either direction', async () => {
    await selectTechnology(harness.document, 'windows');
    for (const [format, prefix] of [['classic', 'WinEventLog'], ['xml', 'XmlWinEventLog']]) {
      selectRenderFormat(harness.document, format);
      const sts = sourcetypeRows(harness.document);
      const srcs = sourceRows(harness.document);
      for (const name of Object.keys(sts)) {
        assert.equal(sts[name], prefix, `${format}: sourcetype must be bare ${prefix}`);
        assert.ok(srcs[name].startsWith(`${prefix}:`),
          `${format}: source ${srcs[name]} does not match sourcetype ${prefix}`);
      }
    }
  });

  it('an untouched windows form persists neither map', async () => {
    await selectTechnology(harness.document, 'windows');
    assert.deepEqual(harness.senderForm.getHecSourcetypeMap(), {},
      'the registry default was frozen into the sender as a user override');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {});

    selectRenderFormat(harness.document, 'classic');
    assert.deepEqual(harness.senderForm.getHecSourcetypeMap(), {},
      'switching format must not look like a user edit either');
    assert.deepEqual(harness.senderForm.getHecSourceMap(), {});
  });

  it('palo alto no longer freezes pan:log as an override', async () => {
    await selectTechnology(harness.document, 'paloalto');

    assert.deepEqual(sourcetypeRows(harness.document), {
      'pan:system': 'pan:log',
      'pan:threat': 'pan:log',
      'pan:traffic': 'pan:log',
    }, 'the rows must still show the value that will be sent');
    assert.deepEqual(harness.senderForm.getHecSourcetypeMap(), {},
      'showing the registry default must not persist it');
  });

  it('a real edit is still persisted', async () => {
    await selectTechnology(harness.document, 'windows');
    const input = harness.document.querySelector(
      '#hecSourcetypeMapRows input.hec-st-input[data-sourcetype="WinEventLog:Security"]');
    input.value = 'XmlWinEventLog:Security';

    assert.deepEqual(harness.senderForm.getHecSourcetypeMap(), {
      'WinEventLog:Security': 'XmlWinEventLog:Security',
    });
  });
});

describe('what the form shows is what the sender will send', () => {
  it('editing a classic sender shows the classic pair, not the previous format', async () => {
    // Build the exact trap: edit an xml sender, then a classic one. senders.js
    // restores #renderFormat only after hydrateFromSender(), so the rows used to
    // be rendered from the previously edited sender's format.
    await editSender('win-sec');
    assert.deepEqual(sourcetypeRows(harness.document), {
      'WinEventLog:Security': 'XmlWinEventLog',
    }, 'premise: the first sender is xml');

    await editSender('win-classic');
    assert.equal(harness.document.getElementById('renderFormat').value, 'classic',
      'the form must show the edited sender’s own format');
    assert.deepEqual(sourcetypeRows(harness.document), {
      'WinEventLog:Security': 'WinEventLog',
      'WinEventLog:System': 'WinEventLog',
    }, 'the previous sender’s format leaked into the rows');
    assert.deepEqual(sourceRows(harness.document), {
      'WinEventLog:Security': 'WinEventLog:Security',
      'WinEventLog:System': 'WinEventLog:System',
    });
  });

  it('going back to an xml sender restores the xml pair', async () => {
    await editSender('win-classic');
    assert.equal(harness.document.getElementById('renderFormat').value, 'classic');

    await editSender('win-sec');
    assert.equal(harness.document.getElementById('renderFormat').value, 'xml');
    assert.deepEqual(sourcetypeRows(harness.document), {
      'WinEventLog:Security': 'XmlWinEventLog',
    });
  });

  it('a reset puts the format back to xml', async () => {
    await editSender('win-classic');
    harness.senderForm.resetSenderForm();
    assert.equal(harness.document.getElementById('renderFormat').value, 'xml',
      'a new sender would inherit the last edited format');
  });

  it('the single fields hide exactly when the rows take over', async () => {
    // senders.js reads a single field only while its group is visible, so this
    // visibility is the whole mechanism that stops a leftover value — such as the
    // 'apache:access' found on a paloalto sender — from being persisted unseen.
    await selectTechnology(harness.document, 'windows');
    assert.equal(isVisible(harness.document, 'hecSourcetypeSingleGroup'), false,
      'windows has sourcetype rows, so the single field must be hidden');
    assert.equal(isVisible(harness.document, 'hecSourceSingleGroup'), false,
      'windows has source rows, so the single field must be hidden');

    await selectTechnology(harness.document, 'paloalto');
    assert.equal(isVisible(harness.document, 'hecSourcetypeSingleGroup'), false,
      'paloalto has sourcetype rows too');
    assert.equal(isVisible(harness.document, 'hecSourceSingleGroup'), true,
      'paloalto documents no source, so the single field stays the way in');

    harness.senderForm.resetSenderForm();
    assert.equal(isVisible(harness.document, 'hecSourcetypeSingleGroup'), true,
      'with nothing selected both single fields come back');
    assert.equal(isVisible(harness.document, 'hecSourceSingleGroup'), true);
  });
});

describe('delivery format', () => {
  const visible = () => isVisible(harness.document, 'deliveryFormatGroup');
  const select = () => harness.document.getElementById('deliveryFormat');

  it('a Local File offers both shapes for any source collected over syslog', async () => {
    selectDestinationType(harness.document, 'file');

    await selectTechnology(harness.document, 'ssh');
    assert.equal(visible(), true, 'ssh: a raw file or a capture of the framed wire');
    assert.equal(select().value, 'uf', 'ssh has no priority of its own');

    await selectTechnology(harness.document, 'paloalto');
    assert.equal(visible(), true, 'Palo Alto too — with or without its priority');
    assert.equal(select().value, 'syslog', 'Palo Alto writes its own priority, so that is its default');

    await selectTechnology(harness.document, 'windows');
    assert.equal(visible(), false, 'Windows is not collected over syslog at all');
  });

  it('HEC never offers it: the collector endpoint receives the event itself', async () => {
    selectDestinationType(harness.document, 'configuration');
    for (const tech of ['ssh', 'paloalto', 'windows']) {
      await selectTechnology(harness.document, tech);
      assert.equal(visible(), false, `${tech} on HEC`);
    }
  });

  it('a syslog destination offers it only where there is a choice to make', async () => {
    selectDestinationType(harness.document, 'syslog');
    await selectTechnology(harness.document, 'ssh');
    assert.equal(visible(), true);
    await selectTechnology(harness.document, 'paloalto');
    assert.equal(visible(), false, 'a self-framing source is always framed for a collector');
  });

  it('follows the destination without losing a choice already made', async () => {
    selectDestinationType(harness.document, 'file');
    await selectTechnology(harness.document, 'ssh');
    select().value = 'syslog';
    select().dispatchEvent(new harness.window.Event('change'));

    selectDestinationType(harness.document, 'configuration');
    assert.equal(visible(), false);
    selectDestinationType(harness.document, 'file');
    assert.equal(visible(), true);
    assert.equal(select().value, 'syslog', 'switching destination must not reset the choice');
  });

  it('a new source brings its own default back', async () => {
    selectDestinationType(harness.document, 'file');
    await selectTechnology(harness.document, 'ssh');
    select().value = 'syslog';
    select().dispatchEvent(new harness.window.Event('change'));

    await selectTechnology(harness.document, 'paloalto');
    assert.equal(select().value, 'syslog');
    await selectTechnology(harness.document, 'ssh');
    assert.equal(select().value, 'uf', "ssh's default, not Palo Alto's or the last pick");
  });

  it('a reset hides it again', async () => {
    await selectTechnology(harness.document, 'ssh');
    harness.senderForm.resetSenderForm();
    assert.equal(visible(), false);
  });
});
