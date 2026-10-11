#!/usr/bin/env python3
"""Tests for ct_lines.py — the grammar of the ct-clock log. No network, no GitHub.

Run: python3 test_ct_lines.py

Why: every line in CT-CLOCK.log is written by this repo's own code from a stranger's fetch, and
nothing else will ever check it. The failure that matters most is the quiet one — a broken parse
that yields an empty list, which downstream would read as "no new certificate" (that is the shape
of c11's B-defect family and of c12's note 32 §1). So the cases below spend most of their effort on
making sure "zero issuances" is reachable only through a *valid* payload.
"""
import sys

sys.path.insert(0, "/data/repos/outside-clock")
import ct_lines  # noqa: E402

fails = []


def check(name, cond, detail=""):
    if not cond:
        fails.append(name)
    print(("ok   " if cond else "FAIL ") + name + (f"  {detail}" if detail and not cond else ""))


ISSUANCE = {
    "id": "17529090517",
    "tbs_sha256": "5019a8c7",
    "cert_sha256": "6586ab6a0d2e38cb1ac55a7a8c75fc5055e45f12c3b1d9d0133ef0c679fcf486",
    "dns_names": ["*.k1r4.space", "k1r4.space"],
    "not_before": "2026-10-01T00:00:00Z",
    "not_after": "2026-12-30T03:50:35Z",
    "revoked": False,
}
import json  # noqa: E402

GOOD = json.dumps([ISSUANCE])

# --- parse: zero issuances must not be reachable by a broken parse -------------------------------

d, err = ct_lines.parse_issuances(GOOD)
check("a well-formed payload parses", err is None and len(d) == 1, f"{d} {err}")
d, err = ct_lines.parse_issuances("[]")
check("an empty list is a fact, not an error", err is None and d == [])
for name, bad in (("garbage", "not json at all"), ("an object", '{"id": "1"}'),
                  ("an entry that is not an object", '[1,2]'),
                  ("an entry with no cert_sha256", '[{"id":"1","not_before":"x","not_after":"y"}]'),
                  ("an entry with no id", '[{"cert_sha256":"a","not_before":"x","not_after":"y"}]')):
    d, err = ct_lines.parse_issuances(bad)
    check(f"{name} is an error and not an empty reading", err is not None and d == [], f"{d} {err}")

# --- line shapes ---------------------------------------------------------------------------------

ok = ct_lines.run_line("T", "h", "ok", count=3)
check("a run line carries status and count", "status=ok" in ok and "count=3" in ok, ok)
un = ct_lines.run_line("T", "h", "UNREACHABLE", code="000", reason="curl: (28) timed out")
check("a failed run line says UNREACHABLE and keeps the reason on one token",
      "status=UNREACHABLE" in un and " " not in un.split("reason=")[1].split("=")[0] and
      "curl:_(28)_timed_out" in un, un)
check("every non-issuance line is space-separated key=value with no quoting",
      all("=" in t for t in ok.split()[1:]) and '"' not in ok, ok)

line = ct_lines.issuance_line("T", "h", ISSUANCE, issuer="C=US,O=Let's Encrypt,CN=YE2")
for field in ("id=17529090517", "not_before=2026-10-01T00:00:00Z", "not_after=2026-12-30T03:50:35Z",
              "revoked=false", "sha256=6586ab6a", "names=*.k1r4.space,k1r4.space"):
    check(f"an issuance line carries {field.split('=')[0]}", field in line, line)
check("the issuer is the last field and is quoted, because it contains spaces",
      line.endswith('issuer="C=US,O=Let\'s Encrypt,CN=YE2"'), line)
check("an unreadable issuer is written unknown, not omitted",
      'issuer="unknown"' in ct_lines.issuance_line("T", "h", ISSUANCE, issuer=None))

# --- the control, which is what makes a run's lines usable at all ---------------------------------

c = ct_lines.control_line("T", "h", "[]", code="200")
check("an empty control reading is ok", "count=0 verdict=ok" in c, c)
c = ct_lines.control_line("T", "h", GOOD, code="200")
check("a control that returns entries is SUSPECT and says the run is unguarded",
      "verdict=SUSPECT" in c, c)
c = ct_lines.control_line("T", "h", "", code="403")
check("a control that cannot be fetched is UNGUARDED, not missing",
      "verdict=UNGUARDED" in c and "code=403" in c, c)
c = ct_lines.control_line("T", "h", "not json", code="200")
check("a control payload that cannot be parsed is UNGUARDED too", "UNGUARDED" in c, c)

# --- lines(): the whole run, and the injected issuer_of -------------------------------------------

made = ct_lines.lines(GOOD, "T", "h", issuer_of=lambda b64: "ISSUER")
check("a run writes one run line and one line per issuance",
      len(made) == 2 and made[0].startswith("run ") and made[1].startswith("issuance "), str(made))
made = ct_lines.lines("nonsense", "T", "h", issuer_of=lambda b64: "ISSUER")
check("a run whose payload is unparseable writes UNPARSEABLE rather than nothing",
      len(made) == 1 and "status=UNPARSEABLE" in made[0], str(made))
made = ct_lines.lines(json.dumps([ISSUANCE]), "T", "h", issuer_of=lambda b64: None)
check("no expand=cert means issuer=unknown, on a line that still exists",
      len(made) == 2 and 'issuer="unknown"' in made[1], str(made))
check("the control domain is a real registrable name, not a .invalid (a 403 cannot fail honestly)",
      not ct_lines.CONTROL_DOMAIN.endswith(".invalid"), ct_lines.CONTROL_DOMAIN)

print(f"\n{len(fails)} failed" if fails else "\nall passed")
sys.exit(1 if fails else 0)