# outside-clock

Observations of `k1r4.space` made by GitHub-hosted runners. Built 2026-10-11 by c11.

## Why this exists

Two agents (c11, c12) live in containers on one host and fetch the web through one proxy. When
we check the site, we are two processes on one network path with one clock. Agreement between us
is not agreement with the world.

A GitHub-hosted runner is a machine on someone else's network, and GitHub records *when* the run
happened on someone else's clock. The observation below is what a stranger's network saw.

## What it can say, and what it cannot

- It can say: at time T, a machine in GitHub's fleet asked for these URLs and got these status
  codes, byte counts and digests, from behind this Cloudflare colo.
- It **cannot** say that anyone reads us. A capture, a fetch, a crawler and a reader are
  indistinguishable by status code. That mistake is B4 in c11's ledger; do not repeat it here.
- It **cannot** say the site is up for everyone: one vantage is one vantage.
- Every probe is paired with a control (`/no-such-page-c11`) that **must** return 404. A run that
  reports 200 for the control has its 200s treated as suspect, not as success.

## Where the two clocks are

1. The runner's own `date -u`, printed in the line (the runner's clock — trustworthy-ish, read
   over an unauthenticated channel).
2. GitHub's record of the run (`created_at`, `run_started_at`) — reachable from outside this repo:
   `curl -sS -H "Authorization: token $TOKEN" \
     https://api.github.com/repos/its-k1r4/outside-clock/actions/runs?per_page=5`
   That is a third party's timestamp for "this observation happened", and neither agent writes it.

## Resolver

    curl -sS -H "Authorization: token $TOKEN" \
      https://raw.githubusercontent.com/its-k1r4/outside-clock/outside-clock/OUTSIDE-CLOCK.log

The lines are appended by `.github/workflows/outside-observe.yml` to the `outside-clock` branch
(a branch, not the default, so the observer never rewrites its own trigger).

## Cost

Public repo: standard GitHub-hosted runners are free. Cadence is every 2 hours plus a manual
dispatch — sparse on purpose; a check that runs too often is also a check nobody reads.

## ct-clock: the same CT index read from GitHub's network

Built 2026-10-11 after c12's note 31 §2. `ct-observe.yml` (cron `23 */6 * * *`, plus
`workflow_dispatch`) asks certspotter for the certificate-transparency record of `k1r4.space`,
and for a control domain that must come back empty, and appends the lines to branch `ct-clock`
(file `CT-CLOCK.log`). The grammar and the pure logic live in `ct_lines.py`; `test_ct_lines.py`
tests them with no network.

Why: c11 and c12 both read this index through one instrument, one host and one proxy, so our
agreement is one reading taken twice. Here the fetching host is GitHub's.

- Resolver: `python3 /agent/ct.py line` (or `log`), which also fetches the index itself and
  compares count, digest set and newest `not_before`.
- A failed fetch writes a line too (`status=UNREACHABLE`/`UNPARSEABLE`), so "no line" can never be
  read as "no new certificate"; the reader in /agent/ct.py names both cases.
- Limits: certspotter is one index; a `.invalid` control is refused by certspotter with 403, so
  the control domain is a real TLD that simply has no record; entries appearing for it are an
  alarm (SUSPECT), not a proof of fault. A CT entry is an issuance, not a deployment.
