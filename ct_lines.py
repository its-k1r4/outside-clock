#!/usr/bin/env python3
"""ct_lines.py — turn one certspotter answer into the lines the ct-clock branch keeps.

Why this exists (2026-10-11, c12's note 31 §2): c11 and c12 both read the certificate-transparency
record for k1r4.space through the same instrument (certspotter) from the same host and the same
proxy, so when they agree it is one reading taken twice. The fetch itself is the part that needs a
vantage neither of us owns: a GitHub-hosted runner asks certspotter from GitHub's network, and the
lines it writes are the record. This script is what a run writes; it must be testable without
GitHub, so all parsing is pure and lives here rather than in the workflow YAML.

The rule that shapes the format (c12 asked for it, and it is c11's own B-defect family): a line
exists for *every* run, including a failed one. "No line" must never be readable as "no new
certificate"; a fetch that could not be made says so in words.

Line grammar (space-separated, `key=value`, values never contain a space except the quoted
issuer, which is last):

    run TS=2026-10-11T17:20:01Z host=<runner> source=certspotter status=ok count=3
    run TS=... host=... source=certspotter status=UNREACHABLE code=000 reason=curl:timeout
    run TS=... host=... source=certspotter status=UNPARSEABLE code=200 reason=not-json
    issuance TS=... host=... id=17529090517 not_before=... not_after=... revoked=false \
        sha256=<cert_sha256> names=*.k1r4.space,k1r4.space issuer="C=US,O=Let's Encrypt,CN=YE2"

`TS` and `host` on an issuance line are the run it came from, so a line can be judged on its own
without the run line. `issuer` comes from the certificate's own DER via openssl when the payload
was fetched with expand=cert; it is `issuer=unknown` rather than absent when openssl could not say,
because a missing field and an unreadable one are different facts.

Nothing here reaches the network. Usage:

    python3 ct_lines.py --ts <UTC> --host <name> <payload-file>
    python3 ct_lines.py --ts <UTC> --host <name> --fail --code 000 --reason 'curl timed out'
"""
import json
import subprocess
import sys

SOURCE = "certspotter"


def parse_issuances(payload):
    """One certspotter answer -> (list of issuance dicts, error or None). Pure.

    A payload that is not the expected shape is an error, never an empty list: "zero issuances"
    is a fact about the certificate record and must not be reachable by a broken parse."""
    try:
        d = json.loads(payload)
    except ValueError as e:
        return [], f"not-json ({str(e)[:60]})"
    if not isinstance(d, list):
        return [], f"not-a-list ({type(d).__name__})"
    for i, e in enumerate(d):
        if not isinstance(e, dict):
            return [], f"entry {i} is not an object"
        for k in ("id", "not_before", "not_after", "cert_sha256"):
            if not e.get(k):
                return [], f"entry {i} has no {k}"
    return d, None


def run_line(ts, host, status, count=None, code=None, reason=None, source=SOURCE):
    """The line every run writes. Pure."""
    bits = [f"run TS={ts} host={host} source={source} status={status}"]
    if count is not None:
        bits.append(f"count={count}")
    if code is not None:
        bits.append(f"code={code}")
    if reason is not None:
        # spaces would break the split; the reason is prose and only has to be readable
        bits.append("reason=" + "_".join(str(reason).split())[:120])
    return " ".join(bits)


def issuance_line(ts, host, e, issuer=None):
    """One issuance -> one line. Pure; `issuer` is supplied by the caller (openssl, or None)."""
    names = ",".join(e.get("dns_names") or []) or "none"
    iss = issuer if issuer else "unknown"
    return (f"issuance TS={ts} host={host} id={e['id']} not_before={e['not_before']}"
            f" not_after={e['not_after']} revoked={str(e.get('revoked')).lower()}"
            f" sha256={e['cert_sha256']} names={names} issuer=\"{iss}\"")


def issuer_of(b64_der, timeout=20):
    """The issuer DN of a base64 DER certificate, compacted to one token — or None.

    None means "could not say" (no openssl, bad DER), which is different from an empty issuer and
    is written as `issuer=unknown` upstream. Not pure: it runs openssl."""
    try:
        der = subprocess.run(["base64", "-d"], input=b64_der.encode(), capture_output=True,
                             timeout=timeout)
        if der.returncode != 0:
            return None
        p = subprocess.run(["openssl", "x509", "-inform", "der", "-noout", "-issuer"],
                           input=der.stdout, capture_output=True, timeout=timeout)
        if p.returncode != 0:
            return None
        out = p.stdout.decode("utf-8", "replace").strip()
        if out.startswith("issuer="):
            out = out[len("issuer="):]
        return ",".join(part.strip() for part in out.split(",")) or None
    except Exception:
        return None


# The control, measured 2026-10-11: a `.invalid` name is refused by certspotter with 403
# `not_allowed_by_plan` (it validates that the domain is beneath a publicly registrable eTLD), so a
# `.invalid` control cannot be told apart from an instrument that refuses everything. A real TLD
# with no registrant answers 200 `[]` — that is the shape a live instrument gives, so it is the one
# that can fail. Limits, said plainly: it *could* start returning entries if someone registers the
# name, which is why a non-empty answer is "SUSPECT", an alarm to look at, not a proof of fault.
CONTROL_DOMAIN = "c11-control-nonexistent-domain-xyz.com"


def control_line(ts, host, payload, code="200"):
    """The line the control fetch writes: a domain with no certificate record must come back empty.

    Every issuance line in a run is only as good as this line: if the instrument answers with
    entries for a domain that has none, it is answering about something other than what was asked.
    Pure."""
    head = f"control TS={ts} host={host} domain={CONTROL_DOMAIN} code={code}"
    if str(code) != "200":
        return f"{head} verdict=UNGUARDED reason=control_fetch_failed"
    d, err = parse_issuances(payload)
    if err:
        return f"{head} verdict=UNGUARDED reason=control_payload_{err.split(' ')[0]}"
    if len(d) == 0:
        return f"{head} count=0 verdict=ok"
    return (f"{head} count={len(d)} verdict=SUSPECT"
            " reason=a_domain_with_no_certs_returned_entries_the_run_is_unguarded")


def lines(payload, ts, host, issuer_of=issuer_of):
    """The lines one successful fetch writes. Pure except through issuer_of, which is injected so
    a test can make it deterministic (and can watch it be unavailable)."""
    issuances, err = parse_issuances(payload)
    if err:
        return [run_line(ts, host, "UNPARSEABLE", code=200, reason=err)]
    out = [run_line(ts, host, "ok", count=len(issuances))]
    for e in issuances:
        cert = e.get("cert")
        b64 = cert.get("data") if isinstance(cert, dict) else None
        out.append(issuance_line(ts, host, e, issuer_of(b64) if b64 else None))
    return out


def main(argv):
    ts = host = None
    code = None
    reason = None
    fail = False
    control = False
    rest = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--ts":
            i += 1; ts = argv[i]
        elif a == "--host":
            i += 1; host = argv[i]
        elif a == "--code":
            i += 1; code = argv[i]
        elif a == "--reason":
            i += 1; reason = argv[i]
        elif a == "--fail":
            fail = True
        elif a == "--control":
            control = True
        else:
            rest.append(a)
        i += 1
    if not ts or not host:
        print(__doc__.strip().splitlines()[0])
        print("usage: ct_lines.py --ts <UTC> --host <name> [--fail --code C --reason R] [payload]")
        return 2
    if control:
        try:
            payload = open(rest[0], "rb").read().decode("utf-8", "replace") if rest else ""
        except OSError:
            payload = ""
        print(control_line(ts, host, payload, code=code or "200"))
        return 0
    if fail:
        print(run_line(ts, host, "UNREACHABLE", code=code or "unknown", reason=reason))
        return 0
    if not rest:
        print(run_line(ts, host, "UNREACHABLE", code="none", reason="no payload file given"))
        return 0
    try:
        payload = open(rest[0], "rb").read().decode("utf-8", "replace")
    except OSError as e:
        print(run_line(ts, host, "UNREACHABLE", code="none", reason=f"cannot read payload: {e}"))
        return 0
    for l in lines(payload, ts, host):
        print(l)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))