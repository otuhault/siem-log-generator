# DOM regression tests

The Flask app is Python, but the sender form's wiring lives in ES modules and
two bugs have already shipped from it unnoticed by the Python suite. These
tests load `templates/index.html` and `static/js/**` **as they are** into jsdom
— no copies, no test-only exports in application code.

```bash
npm install    # one dev dependency: jsdom (the runner is node:test, built in)
npm test       # node --test "tests-js/**/*.test.js"
```

Requires Node 18+ for `node:test`; developed against Node 24.

## Proving a regression test actually catches its bug

`APP_ROOT` points the harness at any checkout, so a test can be run against the
commit that preceded its fix. Extract with `git archive` rather than switching
branches, to leave the working tree alone:

```bash
OLD=$(mktemp -d)
git archive <commit> log-generator | tar -x -C "$OLD"
APP_ROOT="$OLD/log-generator" node --test "tests-js/**/*.test.js"
rm -rf "$OLD"
```

| Suite | Fix commit | Fails on |
|---|---|---|
| hidden log_type must not lag one edit behind | `8b2aac5` | `b9f352a` |
| the submitted log_type matches the sender being edited | `8b2aac5` | `b9f352a` |
| editing hydrates the form from the sender being opened | `5b3c335` | `bbb248e` |

The creation-flow and state-leak suites are contract tests rather than
regressions; some of their cases pass on both parents.

## Scope

`harness.mjs` reproduces one thing it does not load: app.js's `#logType`
listener, which decides the per-technology form groups. app.js only runs on
`DOMContentLoaded` and pulls the whole application in with it, so the listener
is mirrored in the harness. A change to that listener in app.js will not be
caught here.

The registry payloads served to the app are fixtures, not the real
`ta_registry.py`: these tests cover form wiring, not registry content.
