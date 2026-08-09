<p align="center">
  <img src="https://img.shields.io/badge/CVE-2026--64638-critical?style=for-the-badge&logo=wordpress&logoColor=white&color=dc143c" alt="CVE-2026-64638">
  <img src="https://img.shields.io/badge/CVSS-8.9-high?style=for-the-badge&color=crimson" alt="CVSS 8.9">
  <img src="https://img.shields.io/badge/discovered_by-pwn.ai-7fd1ff?style=for-the-badge" alt="pwn.ai">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/github/license/jakestone/xss2shell?style=for-the-badge" alt="License">
</p>

<h1 align="center">🔥 XSS2Shell — CVE-2026-64638 Scanner &amp; PoC Toolkit</h1>

<p align="center">
  <b>Behavior-first mass scanner and evidence-grade PoC generator for the WordPress
  pre-auth XSS-to-RCE chain affecting 500M+ websites.</b><br>
  <i>Detection only. No weaponization. Built for bug bounty programs and blue teams.</i>
</p>

<h4>Official Checker: https://pwn.ai/xss2shell-checker.html</h4>

<p align="center">
  <a href="#-what-is-cve-2026-64638">What is this?</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-shodan-dorks">Shodan Dorks</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-decision-matrix">Decision Matrix</a> •
  <a href="#-detection-signatures">Detection</a> •
  <a href="#-faq">FAQ</a>
</p>

---

## 🔎 Shodan Dorks

Hunt for potentially vulnerable WordPress instances across the internet before scanning:

### Core WordPress Discovery

```
http.component:"wordpress" -http.title:"Just a moment"
```

Finds WordPress sites while excluding Cloudflare "I'm Under Attack" mode / bot-protection pages that will block or challenge automated requests.

### Narrow to Login Pages

```
http.component:"wordpress" http.title:"Log In"
```

Returns only WordPress login pages — the exact attack surface for CVE-2026-64638.

### Version-Specific Hunting

```
http.component:"wordpress" "wp-content" "?ver=7.0" -"?ver=7.0.3"
```

Flags WordPress 7.0.x instances without the 7.0.3 patch by asset version fingerprinting.

### Widen the Surface

```
http.component:"wordpress" http.html:"wp-login.php"
```

Catches sites where wp-login.php is reachable but may not be the current page — broader coverage.

### Cloudflare Exclusions (Combined)

```
http.component:"wordpress" -http.title:"Just a moment" -http.title:"Attention Required" -org:"Cloudflare"
```

Aggressive filter that strips out most Cloudflare-fronted targets. Use when scanning at scale with `--active` — Cloudflare will rate-limit or block the probe request.

> **Tip:** Export Shodan results with `shodan download` and pipe the hostnames directly into `xss2shell_mass.py -i`.

---

## 🚨 What Is CVE-2026-64638?

On August 7, 2026, **pwn.ai disclosed CVE-2026-64638 (XSS2Shell)** — a critical pre-authentication cross-site scripting vulnerability in WordPress Core that chains all the way to **remote code execution** on the server. [citation:pwn.ai blog]

The bug exploits a parser disagreement between PHP's `strip_tags()` and WordPress's `wp_kses_post()`:

- **`strip_tags()`** uses `<` immediately followed by a letter to identify HTML tags. `< area id=...>` (with a space) is treated as **text** — it survives.
- **`wp_kses_post()`** (KSES) recognizes `< area` as a valid `<area>` element — and `<area>` is **allowlisted** in KSES. [citation:pwn.ai blog]

One failed login with a specially crafted username `< area id=ajaxurl href=/?rest_route=/&_method=GET&_jsonp=alert>...` bypasses both sanitizers, gets rendered as live DOM on the login page, hijacks WordPress's own `user-profile.js` script via DOM clobbering, and fires `alert()` in the WordPress origin — **zero clicks, zero authentication, zero cookies required**. [citation:pwn.ai blog]

Escalated to a logged-in administrator? The same primitive steals Application Passwords via Same Origin Method Execution (SOME), uploads a malicious plugin, and executes PHP as `www-data`. [citation:pwn.ai blog] [citation:hadrian.io blog]

> **Affected:** WordPress 6.4 through 7.0.2 — patched in 7.0.3 with backports to 4.7+.  
> **Impact:** ~500 million websites at time of disclosure. [citation:pwn.ai blog]

### 📰 Key Resources

| Resource | Link |
|---|---|
| **Original Disclosure (pwn.ai)** | [pwn.ai/blog/xss2shell](https://pwn.ai/blog/xss2shell) |
| **Hadrian Technical Analysis** | [hadrian.io/blog/wordpress-xss2shell](https://hadrian.io/blog/wordpress-xss2shell-unauthenticated-login-screen-xss-to-php-code-execution-cve-2026-64638) |
| **WordPress Advisory (GHSA)** | [GHSA-52p2-r8wf-jcrf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf) |
| **SOME Attack Research (2022)** | [pwn.ai/blog/bypass-csp-using-wordpress](https://pwn.ai/blog/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution) |
| **WordPress 7.0.3 Release** | [wordpress.org/news/2026/08/wordpress-7-0-3-release](https://wordpress.org/news/2026/08/wordpress-7-0-3-release/) |

---

## ⚡ What This Toolkit Does

This is a **detection-only** toolkit. It does not weaponize the vulnerability — it gives security researchers, bug bounty hunters, and blue teams everything needed to:

1. **Mass-scan** hundreds of WordPress hosts in minutes with behavioral-first accuracy
2. **Generate evidence-grade PoC pages** to prove the XSS fires (alert() only)
3. **Classify findings** with precise confidence levels — no false positives from version-matching

### 🔑 Why Behavior-First?

> "A version string says what patch level the code *should* be.  
> Only the login-page sanitizer behavior says whether the bug *fires*."

Managed hosts silently backport security patches without bumping version strings. Login-hardening plugins replace the error message entirely, killing the reflection channel even on insecure versions. **Version-only scanners produce false positives and false negatives.** This scanner sends a single benign probe and classifies the *actual sanitizer behavior*.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/jakestone/xss2shell.git
cd xss2shell
pip install -r requirements.txt
```

### 5-Minute Scan

```bash
# Passive — no probes sent to target, version + endpoint fingerprinting only
python3 xss2shell_mass.py -i domains.txt -o results

# Active — sends ONE benign failed-login per host (authorized assets only!)
python3 xss2shell_mass.py -i domains.txt -o results --active --workers 80
```

### Generate Evidence PoCs

```bash
# Single target
python3 make_poc.py --target https://blog.example.com

# Batch from scanner output
python3 make_poc.py --from-results results.csv -o pocs/
```

Open the generated `.poc.html` in your browser while recording video → if `alert()` fires, you've captured pre-auth XSS evidence.

---

## 📖 Usage

### Mass Scanner (`xss2shell_mass.py`)

```
usage: xss2shell_mass.py [-h] -i INPUT [-o OUTPUT]
                         [--active] [--workers WORKERS]
                         [--timeout TIMEOUT] [--quiet]
```

| Flag | Description |
|---|---|
| `-i, --input` | File with one host per line (bare domain or full URL) |
| `-o, --output` | Base path for output files (generates `.csv` + `.json`) |
| `--active` | Enable behavioral probe — one failed login per host |
| `--workers` | Thread pool size (default: 50, max ~200 for good connections) |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--quiet` | Only print `confirmed_vulnerable`, `vulnerable`, and `likely_vulnerable` |

#### Passive Scan Evidence (no active probe, always collected)

1. **Homepage** → WordPress fingerprint (meta generator, asset `?ver=` params, wp-content references)
2. **Login page** → Reachability, stock login form detection, `user-profile.js` gadget enqueued, core asset versions
3. **REST JSONP smoke test** → Harmless GET on `/?rest_route=/&_method=GET&_jsonp=<random>` — is the JSONP pathway open?
4. **Feed/Readme fallback** → Version extraction if homepage fingerprint is missing

#### Active Probe (one POST, `--active` flag)

Sends a single failed login with username `< area id=<RANDOM> href=/x2s>` and classifies the HTML response:

- **`bypass`** — Real `<area>` element with our marker survived → strip_tags/KSES mismatch CONFIRMED
- **`escaped`** — Marker present but entity-encoded → patch or hardening present
- **`stripped`** — Default WP error shown, tags removed → `acevomod` or patched
- **`closed`** — No username reflection at all → login-hardening plugin installed

### PoC Generator (`make_poc.py`)

```
usage: make_poc.py [-h] [--target TARGET] [--from-results FROM_RESULTS]
                   [-o OUTDIR]
```

Generates the **published pwn.ai PoC page** for each target — the exact HTML form that triggers `alert()` on an unpatched WordPress. Three payload variants are included in comments:

| Variant | `href` value | When to use |
|---|---|---|
| **Default** | `/?rest_route=/&_method=GET&_jsonp=alert` | Standard WordPress |
| **Envelope** | `/?rest_route=/&_method=GET&_envelope=1&_jsonp=alert` | REST returns 401 (wraps in 200) |
| **WAF Pivot** | `/wp-json/wp/v2/statuses/publish?_jsonp=alert&_method=GET` | `?rest_route=` blocked by WAF |

---

## 🧠 Decision Matrix

The scanner's decision engine combines version classification (from WordPress.org's stable-check API) with behavioral evidence to produce 10 distinct verdicts:

| Verdict | Conditions |
|---|---|
| **`confirmed_vulnerable`** 🔴 | Version is insecure AND probe marker survived as `<area>` element AND `user-profile.js` gadget is present |
| **`vulnerable`** 🔴 | Version is insecure per wordpress.org; behavioral probe NOT run (re-run with `--active`) |
| **`likely_vulnerable`** 🟠 | Probe marker survived BUT `user-profile.js` not enqueued (published auto-fire gadget missing) |
| **`mitigated`** 🟣 | Version is insecure BUT probe marker was escaped/stripped/closed (silent backport or hardening) |
| **`likely_patched`** 🟢 | Version hidden/unknown BUT probe marker was escaped/stripped |
| **`patched`** 🟢 | Version is `latest` or `outdated` (has security backports) |
| **`not_wordpress`** ⚫ | No WordPress fingerprint detected |
| **`unreachable`** ⚫ | Connection failed (timeout, SSL, DNS) |
| **`inconclusive`** 🟡 | WAF block, Cloudflare challenge, hidden version without probe, or login page absent |
| **`error`** 🟡 | Unexpected failure during scan |

### Output Format

**CSV columns:** `host`, `url`, `status`, `checker_status`, `wp_version`, `branch_status`, `evidence`, `http`, `ms`, `error`

The `checker_status` column maps to the **pwn.ai public checker's vocabulary** (`vulnerable` / `patched` / `not_wordpress` / `unreachable` / `inconclusive` / `error`) for direct correlation.

---

## 🔍 Detection Signatures (Blue Team / SOC)

If you're on the defending side, here are the forensic signals this vulnerability leaves:

### Server-Side (Web Server / WAF Logs)

```
# Primary signal: encoded '<' in the log parameter
POST /wp-login.php  →  log=%3C...  (URL-encoded < in username field)

# Higher confidence: paired with REST pivoting
GET /?rest_route=/&_method=GET&_jsonp=...     # JSONP callback
GET /wp-json/wp/v2/statuses/publish?_jsonp=...  # WAF-bypass variant

# Escalation stage indicators
GET /wp-admin/authorize-application.php?success_url=<off-origin>
POST /wp-admin/update.php?action=upload-plugin
GET /wp-content/plugins/<random>/shell.php
```

### Edge / WAF Blocking Rule

Block `POST /wp-login.php` where the `log` parameter contains `%3C` (URL-encoded `<`). Valid WordPress usernames **never** contain angle brackets. Do **not** narrow to specific tags — KSES allows tab, newline, and carriage return after `<` and any allowlisted tag, so a tag-specific rule is trivially evaded. [citation:hadrian.io blog]

### Key Insight for Defenders

The `_jsonp=` callback in the escalation stage uses **dots** for property traversal (e.g., `window.opener.approve.click`). Flag REST requests with dotted JSONP callbacks as strong indicators of exploitation. [citation:hadrian.io blog]

---

## ⚖️ Legal & Ethical Use

```
THIS TOOL IS DETECTION-ONLY. IT DOES NOT:
  ✗ Weaponize the JSONP callback beyond the public alert()
  ✗ Include admin-lure pages or Application Password capture
  ✗ Include REST abuse, plugin upload, or PHP shell code
  ✗ Execute more than one failed login per target per scan

YOU MUST:
  ✓ Only scan assets you own or have written authorization to test
  ✓ Only generate PoCs for your own browser on your own server
  ✓ Never send PoC links to site admins/users
  ✓ Never escalate past alert() without program written approval
  ✓ Follow the bug bounty program scope and rules

This toolkit exists for authorized security research, bug bounty
programs, and defensive detection engineering. Misuse is your
responsibility.
```

---

## 📁 Repository Structure

```
xss2shell/
├── README.md                  ← You are here
├── xss2shell_mass.py          ← Behavior-first mass scanner (v1.1.0)
├── make_poc.py                ← Evidence-grade PoC page generator
├── requirements.txt           ← Python dependencies (just `requests`)
├── .gitignore                 ← Ignores scan outputs and cache
└── example/
    ├── domains.txt            ← Example input file
    └── example_output.csv     ← Example scan output
```

---

## ❓ FAQ

**Q: Why not just check the WordPress version string?**  
A: Managed hosts (WP Engine, Kinsta, Pantheon, etc.) frequently backport security patches without bumping the version. Login-hardening plugins replace the error message entirely. Both cases produce **false positives** in version-only scanners and **false negatives** for hidden versions. This scanner tests the *actual sanitizer behavior*.

**Q: Is the `--active` probe dangerous?**  
A: No. It sends exactly one failed login with a benign marker username. It does not attempt to execute JavaScript, does not enumerate valid usernames, and does not trigger any actual exploit. It is less intrusive than a standard login attempt.

**Q: Can this tool be used for unauthorized scanning?**  
A: No. The active probe sends an HTTP POST to `/wp-login.php`, which is a request to the target server. Only use on assets you own or have explicit written authorization to test.

**Q: What's the difference between `vulnerable` and `confirmed_vulnerable`?**  
A: `vulnerable` means the WordPress.org API says the version is insecure, but we haven't confirmed the strip_tags/KSES mismatch behaviorally. `confirmed_vulnerable` means we sent a probe and the `<area>` element survived both sanitizers — **the published chain can fire**.

**Q: Can I use this for my bug bounty program reports?**  
A: Yes! The `checker_status` column maps directly to pwn.ai's public checker vocabulary for easy correlation. Pair scan results with PoC video evidence from `make_poc.py` for complete reports.

**Q: Does this detect the RCE chain?**  
A: No. This toolkit detects the **pre-auth XSS entry point**. The full RCE chain requires a logged-in administrator, Application Passwords enabled, and plugin upload permissions — conditions this scanner does not evaluate. The scanner focuses on what's externally observable: the sanitizer bypass.

---

## 🏆 Credits & References

- **Discovery & Disclosure:** [pwn.ai](https://pwn.ai) — autonomously discovered by a multi-agent AI system
- **SOME Technique Foundation:** [Paulos Yibelo](https://x.com/@paulosyibelo) — 2022 research nominated for Top Web Hacking Techniques
- **Technical Analysis:** [Hadrian](https://hadrian.io) — comprehensive detection and mitigation guidance
- **CVE:** CVE-2026-64638 / GHSA-52p2-r8wf-jcrf
- **Patch:** [WordPress 7.0.3](https://wordpress.org/news/2026/08/wordpress-7-0-3-release/)

---

<p align="center">
  <sub>Built by <a href="https://github.com/0xlipon">0xlipon</a> • Detection-only • For authorized use only</sub>
</p>
