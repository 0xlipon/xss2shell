#!/usr/bin/env python3
"""
XSS2Shell (CVE-2026-64638) mass scanner  v1.1.0
================================================

Accuracy-focused, DETECTION-ONLY scanner. v1.1 grounds every verdict in
*behavioral evidence* instead of version strings alone, mirroring the
vendor checker's approach. Key principle of v1.1:

    A version string says what patch level the code SHOULD be.
    Only the login-page sanitizer behavior says whether the bug FIRES.
    When they disagree, behavior wins (managed-host silent backports and
    login-hardening plugins make version-only verdicts false-positive-prone).

Evidence collected per host (all benign; only --active sends one POST):
  1. homepage           -> WP fingerprint + version candidates
  2. /wp-login.php      -> reachability, REAL login form present,
                           user-profile.js gadget enqueued (needed by the
                           published chain to auto-fire), core asset ?ver=
  3. /feed/, /readme.html (only if no version yet) -> version candidates
  4. REST JSONP smoke test (harmless GET on public index with _jsonp=cb)
                           -> is the _jsonp pathway (used by the chain) open
  5. --active probe     -> one failed login with marker username
                           "< area id=<MARKER> href=/x2s>"; the returned HTML
                           is classified:  BYPASS  (real <area> element
                           survived strip_tags/KSES) | ESCAPED | STRIPPED

Decision matrix (see decide()):

  version=patched-branch ..................... patched
  version=insecure, probe=BYPASS              confirmed_vulnerable
  version=insecure, probe not run ...........  vulnerable   (run --active)
  version=insecure, probe=ESCAPED/STRIPPED .. mitigated     (was FP in v1.0)
  version=insecure, probe blocked by WAF ....  inconclusive (waf)
  version=hidden,  probe=BYPASS + gadget ....  confirmed_vulnerable
  version=hidden,  probe=BYPASS no gadget ...  likely_vulnerable
  version=hidden,  probe=ESCAPED/STRIPPED ..  likely_patched
  login page absent (renamed/removed) .......  inconclusive / patched-by-version
  Cloudflare/WAF challenge or block .........  inconclusive

Statuses:
    confirmed_vulnerable | vulnerable | likely_vulnerable | mitigated |
    likely_patched | patched | not_wordpress | unreachable |
    inconclusive | error

Usage:
    python3 xss2shell_mass.py -i domains.txt -o results
    python3 xss2shell_mass.py -i subs.txt  -o out --active --workers 80
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import os
import random
import re
import string
import sys
import threading
import time
from urllib.parse import urlparse

import requests

VERSION = "1.1.0"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 "
      "XSS2Shell-Scanner/{}".format(VERSION))

STABLE_CHECK_URL = "https://api.wordpress.org/core/stable-check/1.0/"
CACHE_FILE = ".wp_stable_check_cache.json"
CACHE_TTL = 24 * 3600

# --------------------------------------------------------------------------- #
# Regexes
# --------------------------------------------------------------------------- #
RE_META_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]*>', re.I)
RE_META_CONTENT = re.compile(
    r'content=["\']\s*WordPress\s+([0-9]+(?:\.[0-9]+){0,2})', re.I)
RE_FEED_GEN = re.compile(
    r'<generator>https?://wordpress\.org/\?v=([0-9]+(?:\.[0-9]+){0,2})</generator>', re.I)
RE_README = re.compile(r'>\s*Version\s+([0-9]+(?:\.[0-9]+){0,2})\s*<', re.I)
RE_VER_PARAM = re.compile(
    r'/wp-(?:includes|admin)/[^"\'\s<>]+\?ver=([0-9]+(?:\.[0-9]+){0,2})', re.I)
RE_WP_HINT = re.compile(r'wp-content/|wp-includes/|wp-json', re.I)
RE_ERROR_BODY = re.compile(r'<area\b[^>]*id=["\']?{}', re.I)

# Bundled third-party libs under wp-includes/wp-admin carry their OWN versions.
LIB_VERSION_EXCLUDE = {"3.7.1", "3.7.0", "3.6.4", "3.6.0", "3.5.1"}

cvd = threading.local()


# --------------------------------------------------------------------------- #
# Stable-check cache
# --------------------------------------------------------------------------- #
class StableCheck:
    def __init__(self):
        self.map: dict[str, str] | None = None
        self.err: str | None = None
        self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE) as fh:
                    blob = json.load(fh)
                if time.time() - blob.get("ts", 0) < CACHE_TTL:
                    self.map = blob["map"]
        except Exception:
            pass

    def ensure(self, timeout=10):
        if self.map is not None:
            return
        try:
            r = requests.get(STABLE_CHECK_URL, timeout=timeout,
                             headers={"User-Agent": UA})
            r.raise_for_status()
            self.map = r.json()
            with open(CACHE_FILE, "w") as fh:
                json.dump({"ts": time.time(), "map": self.map}, fh)
        except Exception as e:
            self.err = f"stable-check unavailable: {e}"

    @staticmethod
    def _vkey(v: str):
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return None

    def status_of(self, version: str) -> str:
        """-> 'latest' | 'outdated' | 'insecure' | 'unknown'
        API semantics: latest=newest release; outdated=newest release of a
        maintained branch (HAS all security backports incl. this CVE);
        insecure=anything older (missing backports)."""
        if self.map is None:
            return "unknown"
        if version in self.map:
            return self.map[version]
        vk = self._vkey(version)
        if vk is None:
            return "unknown"
        branch = ".".join(version.split(".")[:2])
        keys = [k for k in self.map
                if self._vkey(k) and ".".join(k.split(".")[:2]) == branch]
        if keys:
            newest = max(keys, key=self._vkey)
            return "outdated" if vk >= self._vkey(newest) else "insecure"
        gmax = max((k for k in self.map if self._vkey(k)), key=self._vkey)
        return "latest" if vk >= self._vkey(gmax) else "unknown"


STABLE = StableCheck()


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def normalize_host(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        line = "http://" + line
    p = urlparse(line)
    host = (p.netloc or p.path.split("/")[0]).strip().lower()
    return host or None


def get_session() -> requests.Session:
    if not hasattr(cvd, "s"):
        cvd.s = requests.Session()
        cvd.s.headers.update({"User-Agent": UA})
    return cvd.s


def fetch(url: str, timeout: int, method: str = "GET", **kw):
    try:
        return get_session().request(method, url, timeout=timeout, **kw), None
    except requests.exceptions.SSLError as e:
        return None, f"ssl_error: {type(e).__name__}"
    except requests.exceptions.TooManyRedirects:
        return None, "too_many_redirects"
    except requests.exceptions.ConnectionError as e:
        return None, f"conn_error: {type(e).__name__}"
    except requests.exceptions.Timeout:
        return None, "timeout"
    except Exception as e:
        return None, f"error: {type(e).__name__}"


def is_waf_block(resp: requests.Response) -> bool:
    """Cloudflare challenge/block or generic WAF 403."""
    if resp.status_code not in (403, 406, 429, 503):
        return False
    hdrs = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
    body = (resp.text or "")[:3000].lower()
    if "cf-ray" in hdrs or "cloudflare" in hdrs.get("server", ""):
        return True
    if any(s in body for s in ("attention required! | cloudflare",
                               "cf-error-code", "you have been blocked",
                               "just a moment", "cloudflare ray id",
                               "generated by cloudfront",
                               "the request could not be satisfied")):
        return True
    if "cloudfront" in hdrs.get("x-cache", "") or \
            "cloudfront" in hdrs.get("via", ""):
        return True
    return bool(hdrs.get("cf-mitigated"))


def cf_challenge(html: str) -> bool:
    h = html[:2000].lower()
    return ("just a moment" in h or "cf-browser-verification" in h)


# --------------------------------------------------------------------------- #
# Analysis helpers (pure functions - unit tested)
# --------------------------------------------------------------------------- #
def version_candidates(html: str, src_label: str) -> list[tuple[str, str]]:
    out = []
    for m in RE_META_GEN.finditer(html):
        c = RE_META_CONTENT.search(m.group(0))
        if c:
            out.append((c.group(1), src_label + ":meta"))
            break
    assets = [v for v in RE_VER_PARAM.findall(html)
              if v not in LIB_VERSION_EXCLUDE]
    if assets:
        out.append((max(set(assets), key=assets.count), src_label + ":asset"))
    m = RE_README.search(html)
    if m:
        out.append((m.group(1), src_label + ":readme"))
    return out


def pick_version(cands: list[tuple[str, str]]) -> tuple[str | None, str]:
    """Choose the NEWEST version across sources; stale fingerprints (cached
    meta, old readme.html) are a known false-positive source."""
    if not cands:
        return None, ""
    def key(c):
        try:
            return tuple(int(x) for x in c[0].split("."))
        except ValueError:
            return (0,)
    best = max(cands, key=key)
    versions = {v for v, _ in cands}
    note = best[1]
    if len(versions) > 1:
        note += " [fingerprints disagree: " + ",".join(sorted(versions)) + \
                " -> using newest; stale cached fingerprints possible]"
    return best[0], note


def has_login_form(html: str) -> bool:
    return 'name="log"' in html and 'wp-submit' in html


def gadget_present(html: str) -> bool:
    """user-profile.js must be enqueued on wp-login.php for the published
    chain to auto-fire (line 620 auto-click + delegated #color-picker)."""
    return bool(re.search(r'user-profile(\.min)?\.js', html, re.I))


def classify_reflection(html: str, marker: str) -> str:
    """-> 'bypass' | 'escaped' | 'stripped' | 'closed'
    Decisive test for the strip_tags/KSES parser disagreement:
      bypass   - a real <area> element with our marker survived
      escaped  - marker present but entity-escaped (hardened/escaped message)
      stripped - default WP error shown, marker tags removed (acevomod case)
      closed   - error message replaced by login-hardening (e.g. "Invalid
                 login details.") - NO reflection channel exists at all"""
    if re.search(r'<area\b[^>]*\bid=["\']?' + re.escape(marker), html, re.I):
        return "bypass"
    if marker in html:                       # present but not as an element
        return "escaped"
    if re.search(r'is not registered on this site|invalid_username', html, re.I):
        return "stripped"
    return "closed"


def decide(vstat: str | None, version: str, login_ok: bool,
           probe: dict | None, gadget: bool | None,
           jsonp_ok: bool | None) -> tuple[str, str]:
    """Pure decision matrix. Returns (status, evidence_note).

    vstat:   'latest'|'outdated'|'insecure'|'unknown'|None
    login_ok: wp-login.php reachable with a real login form
    probe:   None (not run) or {'result': 'bypass'|'escaped'|'stripped'|
                                'blocked'|'error', 'detail': str}
    """
    vtag = f"v{version}" if version else "v?"

    if not login_ok:
        if vstat in ("latest", "outdated"):
            return "patched", f"{vtag} has backports; wp-login.php absent anyway"
        if vstat == "insecure":
            return ("inconclusive",
                    f"{vtag} insecure per wordpress.org BUT wp-login.php is "
                    "renamed/removed (chain precondition missing) - manual check")
        return "inconclusive", "wp-login.php absent (renamed/removed)"

    # --- version known to be patched: done, probe not needed --------------
    if vstat in ("latest", "outdated"):
        if probe and probe["result"] == "bypass":
            return ("inconclusive",
                    f"ANOMALY: {vtag} is a backported branch tip yet probe "
                    "marker SURVIVED - possible incomplete patch; report to vendor")
        return "patched", f"{vtag} has CVE-2026-64638 backport ({vstat})"

    note_bits = []
    if jsonp_ok is True:
        note_bits.append("REST JSONP open")
    elif jsonp_ok is False:
        note_bits.append("REST JSONP unreachable")
    note = "; ".join(note_bits)

    # --- probe decisive path ------------------------------------------------
    if probe is None:
        if vstat == "insecure":
            return "vulnerable", \
                f"{vtag} insecure per wordpress.org ({note}); behavior " \
                "untested (run --active to confirm)".rstrip("; ")
        return ("inconclusive",
                f"{vtag} version unrecognized/hidden; run --active for probe")

    pr = probe["result"]
    if pr == "blocked":
        return ("inconclusive",
                f"{vtag}; probe blocked by WAF ({probe['detail']})")
    if pr == "error":
        return ("inconclusive", f"{vtag}; probe error ({probe['detail']})")

    if pr == "bypass":
        if gadget is False:
            return ("likely_vulnerable",
                    f"{vtag}; marker survived sanitizers BUT user-profile.js "
                    f"is not enqueued on the login page - the published "
                    f"auto-fire gadget is missing; {note}")
        if vstat == "insecure":
            return ("confirmed_vulnerable",
                    f"version insecure AND probe marker survived as <area> "
                    f"element (strip_tags/KSES mismatch confirmed); "
                    f"gadget present; {note}")
        return ("confirmed_vulnerable",
                f"version hidden; probe marker survived as <area> element; "
                f"gadget present; {note}")

    # escaped / stripped / closed -> the published chain cannot fire
    if pr == "closed":
        if vstat == "insecure":
            return ("mitigated",
                    f"{vtag} insecure per wordpress.org BUT the login error "
                    "message is replaced by a hardening plugin/host "
                    "(no username reflection at all) - the published chain "
                    "has no injection point")
        return ("inconclusive",
                f"{vtag}; custom login error handling (no username "
                "reflection channel) - sanitizer behavior not testable")

    if vstat == "insecure":
        return ("mitigated",
                f"{vtag} insecure per wordpress.org BUT probe marker was "
                f"{pr} (managed-host silent backport or login hardening) - "
                "chain cannot fire as published")
    return "likely_patched", f"probe marker {pr} (no bypass); {note}"


# --------------------------------------------------------------------------- #
# Per-host scan
# --------------------------------------------------------------------------- #
def scan_host(host: str, timeout: int, active: bool) -> dict:
    rec = {"host": host, "url": "", "status": "error", "wp_version": "",
           "branch_status": "", "evidence": "", "http": 0,
           "ms": 0, "error": ""}
    t0 = time.time()
    try:
        base, resp, err = None, None, None
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            resp, err = fetch(base + "/", timeout)
            if resp is not None:
                break
        if resp is None:
            rec.update(status="unreachable", error=err or "")
            return rec

        rec["http"] = resp.status_code
        rec["url"] = base
        html = resp.text or ""
        if cf_challenge(html):
            rec.update(status="inconclusive", evidence="cloudflare challenge on homepage")
            return rec

        cands: list[tuple[str, str]] = version_candidates(html, "home")
        is_wp = bool(RE_WP_HINT.search(html)) or bool(cands)

        if not is_wp:  # last WP-proof: REST index namespaces
            r3, _ = fetch(base + "/wp-json/", timeout)
            if r3 is not None and r3.status_code == 200 \
                    and '"namespaces"' in r3.text and '"wp/v2"' in r3.text:
                is_wp = True
        if not is_wp:
            rec.update(status="not_wordpress")
            return rec

        # --- login page: reachability, real form, gadget, asset versions ---
        login_url = None
        login_html = ""
        login_ok = False
        gadget = None
        for path in ("/wp-login.php", "/login/"):
            r, _ = fetch(base + path, timeout)
            if r is None:
                continue
            if r.status_code == 200 and (r.text or ""):
                body = r.text
                if has_login_form(body):
                    login_url, login_html, login_ok = base + path, body, True
                    gadget = gadget_present(body)
                    cands += version_candidates(body, "login")
                    break
                if "wp-login" in body or "log in" in body.lower():
                    # some login-ish page without the stock form (SSO gate etc.)
                    login_url, login_html = base + path, body
                    cands += version_candidates(body, "login")

        # --- version candidates from feed/readme only if still unknown ----
        if not cands:
            for path, label in (("/feed/", "feed"), ("/readme.html", "readme")):
                r2, _ = fetch(base + path, timeout)
                if r2 is None or r2.status_code != 200 or not r2.text:
                    continue
                if label == "feed":
                    m = RE_FEED_GEN.search(r2.text)
                    if m:
                        cands.append((m.group(1), "feed:generator"))
                else:
                    m = RE_README.search(r2.text)
                    if m:
                        cands.append((m.group(1), "readme"))
                if cands:
                    break

        version, vnote = pick_version(cands)
        rec["wp_version"] = version or ""
        vstat = STABLE.status_of(version) if version else None
        rec["branch_status"] = vstat or ""

        # --- REST JSONP smoke test (harmless GET; chain precondition) ----
        jsonp_ok = None
        if is_wp:
            cb = "x2spv" + "".join(random.choices(string.ascii_lowercase, k=6))
            rj, _ = fetch(base + f"/?rest_route=/&_method=GET&_jsonp={cb}&_envelope=1",
                          timeout)
            if rj is not None:
                ctype = rj.headers.get("Content-Type", "")
                body_j = (rj.text or "")[:200]
                jsonp_ok = ("javascript" in ctype.lower()
                            and rj.status_code == 200
                            and body_j.lstrip().startswith("/**/" + cb + "("))

        # --- optional active probe (decisive behavioral test) --------------
        probe = None
        if active and login_ok and vstat not in ("latest", "outdated"):
            probe = run_probe(login_url, timeout)
        rec["http"] = rec["http"]

        status, note = decide(vstat, version, login_ok, probe, gadget, jsonp_ok)
        rec["status"] = status
        ev = []
        if vnote:
            ev.append(vnote)
        ev.append(f"login:{'ok' if login_ok else 'absent'}")
        if gadget is not None:
            ev.append(f"gadget:{'yes' if gadget else 'no'}")
        if jsonp_ok is not None:
            ev.append(f"jsonp:{'yes' if jsonp_ok else 'no'}")
        if probe:
            ev.append(f"probe:{probe['result']}")
        ev.append(note)
        rec["evidence"] = "; ".join(x for x in ev if x)
        return rec
    finally:
        rec["ms"] = int((time.time() - t0) * 1000)


def run_probe(login_url: str, timeout: int) -> dict:
    """One failed-login POST with the marker username; classifies reflection."""
    marker = "x2s" + "".join(random.choices(string.ascii_lowercase, k=8))
    probe_user = f"< area id={marker} href=/x2s>"
    sess = get_session()
    sess.cookies.set("wordpress_test_cookie", "WP Cookie check")
    data = {"log": probe_user, "pwd": "x2s-invalid", "wp-submit": "Log In",
            "redirect_to": "", "testcookie": "1"}
    r, err = fetch(login_url, timeout, method="POST", data=data)
    if r is None:
        return {"result": "error", "detail": err}
    if is_waf_block(r) or r.status_code in (403, 406, 429):
        return {"result": "blocked",
                "detail": f"http {r.status_code} (WAF/rate-limit)"}
    html = r.text or ""
    if not has_login_form(html) and marker not in html:
        # custom login flow that doesn't reflect at all
        return {"result": "error", "detail": "unexpected login flow (SSO/custom)"}
    return {"result": classify_reflection(html, marker), "detail": ""}


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
COLOR = {
    "confirmed_vulnerable": "\033[1;31m",
    "vulnerable": "\033[1;31m",
    "likely_vulnerable": "\033[31m",
    "mitigated": "\033[35m",
    "likely_patched": "\033[32m", "patched": "\033[32m",
    "not_wordpress": "\033[90m", "unreachable": "\033[90m",
    "inconclusive": "\033[33m", "error": "\033[33m",
}
RESET = "\033[0m"

# Mapping into the pwn.ai checker's public vocabulary. Its VULNERABLE verdict
# is defined by "the login page reflects usernames without proper HTML
# encoding" - i.e. our reflection-bypass signal alone (the checker does not
# evaluate gadget/JSONP preconditions, hence likely_vulnerable also maps to
# its "vulnerable"). mitigated/likely_patched mean the reflection does not
# fire, which the checker reports as NOT VULNERABLE -> "patched".
CHECKER_MAP = {
    "confirmed_vulnerable": "vulnerable",
    "vulnerable":           "vulnerable",
    "likely_vulnerable":    "vulnerable",
    "mitigated":            "patched",
    "likely_patched":       "patched",
    "patched":              "patched",
    "not_wordpress":        "not_wordpress",
    "unreachable":          "unreachable",
    "inconclusive":         "inconclusive",
    "error":                "error",
}
SEV = {"confirmed_vulnerable": 0, "vulnerable": 1, "likely_vulnerable": 2}


def main():
    ap = argparse.ArgumentParser(
        description="XSS2Shell (CVE-2026-64638) mass scanner v1.1 "
                    "(detection only, behavior-first)")
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", default="xss2shell_results")
    ap.add_argument("--active", action="store_true",
                    help="enable the one-request wp-login.php marker probe "
                         "(authorized assets only)")
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    with open(args.input) as fh:
        hosts = sorted({h for h in (normalize_host(l) for l in fh) if h})
    if not hosts:
        sys.exit("no hosts parsed from input file")

    print(f"[*] {len(hosts)} hosts | workers={args.workers} "
          f"timeout={args.timeout}s active={args.active}")
    print("[*] fetching WordPress stable-check data ...")
    STABLE.ensure()
    if STABLE.map is None:
        print(f"[!] {STABLE.err} -> version status will be 'unknown'")

    results, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(scan_host, h, args.timeout, args.active): h
                for h in hosts}
        for fut in cf.as_completed(futs):
            rec = fut.result()
            results.append(rec)
            done += 1
            st = rec["status"]
            if not args.quiet or st in SEV:
                print(COLOR.get(st, "")
                      + f"[{done}/{len(hosts)}] {rec['host']:<40} {st}"
                        f"{' ' * max(1, 22 - len(st))}"
                        f"{rec['wp_version'] or '-':<9} "
                        f"{rec['evidence'][:72]}"
                      + RESET)

    print("\n=== SUMMARY ===")
    agg = {}
    for r in results:
        agg[r["status"]] = agg.get(r["status"], 0) + 1
    for st, n in sorted(agg.items(), key=lambda kv: -kv[1]):
        print(f"{COLOR.get(st, '')}{st:>22}: {n}{RESET}")

    fields = ["host", "url", "status", "checker_status", "wp_version",
              "branch_status", "evidence", "http", "ms", "error"]
    csv_path, json_path = args.output + ".csv", args.output + ".json"
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in sorted(results, key=lambda r: (SEV.get(r["status"], 9),
                                                r["host"])):
            row = dict(r)
            row["checker_status"] = CHECKER_MAP.get(r["status"], "")
            w.writerow(row)
    with open(json_path, "w") as fh:
        json.dump([{**r, "checker_status":
                       CHECKER_MAP.get(r["status"], "")} for r in results],
                  fh, indent=2)
    print(f"\n[+] wrote {csv_path} and {json_path}")
    print("[i] 'checker_status' column = verdict in the pwn.ai checker's exact "
          "vocabulary (its VULNERABLE means 'login page reflects usernames "
          "without proper HTML encoding' = our bypass signal)")


if __name__ == "__main__":
    main()