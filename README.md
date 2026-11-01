ZephyrOS

<div align="center">

Account Recon · Login Flow Probing · Client-Side Deobfuscation

https://img.shields.io/badge/version-11.1.0-cyan?style=flat-square
https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python
https://img.shields.io/badge/license-Authorized%20Use%20Only-red?style=flat-square
https://img.shields.io/badge/author-SYLHETYHACKVENGER%20(THE--ERROR808)-magenta?style=flat-square

An authorized-testing toolkit for analyzing data masking, obfuscation, and client-side credential exposure on login flows — built for lab, CTF, and bug-bounty engagements.

</div>

---

⚠️ Legal & Ethical Notice — Read First

ZephyrOS is intended exclusively for authorized security testing.

· You must have explicit written authorization before running this tool against any system you do not own.
· Running this tool against production systems without permission may violate the Computer Fraud and Abuse Act (CFAA), GDPR, and/or local laws.
· The author assumes no liability for misuse. Every engagement requires an authorization reference (ticket/contract ID), which is recorded in the generated report.
· The tool enforces a request budget, rate limiting, scope allow-list, and guard detection to reduce accidental impact — but these do not replace your own judgment.

By running ZephyrOS you agree that you are operating within the bounds of a signed engagement or an isolated lab environment.

---

Table of Contents

1. What ZephyrOS Does
2. Feature Matrix
3. Architecture Overview
4. Requirements
5. Installation
6. Installation of Companion Tools
   · CyberChef
   · webcrack
   · REstringer
7. Quick Start
8. CLI Reference
9. Interactive Mode Walkthrough
10. Autopilot Mode
11. Analysis Modules Explained
12. Report Schema
13. Exit Codes
14. Rate Limiting & Guard Behavior
15. Self-Test
16. Troubleshooting
17. Roadmap
18. Credits

---

🎯 What ZephyrOS Does

ZephyrOS is a single-file Python reconnaissance and analysis tool that inspects how a web application masks, obfuscates, or leaks account-related data through its login flow, public profile endpoints, and client-side assets.

It answers questions like:

· How does the server mask my data? Partial? Format-preserving? Fixed-width padding? Tokenized?
· Is the login response obfuscated? URL-encoded? Base64? PHP gzinflate? Multi-layer cascade?
· Does the login endpoint leak user existence? Timing/response diff against a non-existent baseline identifier?
· Is the login page hiding something? Skimmers? Phishing forms? Packer-obfuscated JS? Injected data: URIs?
· What is recoverable? Given authorized plaintext, how much of the masked value can be reconstructed?

Everything is scoped, rate-limited, and produces a machine-readable report with a full audit log and SHA-256 chain-of-custody.

---

✨ Feature Matrix

Category Capability
Data Masking Classification Partial masking · Format-preserving masking · Fixed-width padding · Full redaction · Tokenization/pseudonymization · Generalization/binning · Character scrambling · Structured ID detection (Luhn, IBAN, SSN, Aadhaar)
Mask Analyzer Stack Beginner prefix/suffix · Intermediate multi-segment · Advanced format-aware (email/phone/name) · Hyper-adaptive Bayesian ranker learned from training pairs
Recovery Reasoning Iterative multi-layer decoder (URL, Base64, Base32, Hex, ROT13, Caesar, Reverse, JS-escape, HTML-entity, PHP gzinflate) with chain enumeration
Differential Analysis Deterministic masking · Shuffle detection · k-anonymity · l-diversity · t-closeness · role-based diff
Repeated-Read Stats Stability, variance, Laplace/Gaussian differential-privacy ε estimation
Binning Detection Equal-width · Equal-frequency · Log-scale
Cryptographic Fingerprinting Passive ZKP (groth16, bulletproof) · Homomorphic (BFV/CKKS/SEAL) · SMPC
Enumeration Login error diff · Forgot-password diff · Check-username endpoint · Public-profile existence
Account Recon Public profile discovery · ID shape (numeric/alpha/mixed) · Visibility classification · Public-field scrape (allow-listed)
Client-Side Deobfuscation Packer unpacker · Array rotation · String-array resolver · Eval unnest · Concat fold · Control-flow flattening detection · Dead-code detection · Optional AST bridge via Node + Babel
Security Analysis Skimmer/credential-exfil flow detection · Off-origin phishing form detection · Hidden password form detection · Data-URI and javascript: URI decoding
Instrumentation Generates pause.js + Playwright runner to halt before fetch / XHR.send / form submit
Safety Rails Request budget · Token-bucket rate limit · Host allow-list · Guard tolerance · Response size cap · Redacted HTTP log · PII-redacted reports by default
Reporting JSON report with log_sha256, technique_contracts, per-technique detected/attempted state, dependencies, target_info (IPv4/IPv6/domain/subdomain)

---

🏗 Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        ZephyrOS main()                       │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  CLI/Args  │→ │ Config+PII   │→ │  AuthorizedClient    │  │
│  │  or Prompts│  │  Redaction   │  │  (throttle, scope,   │  │
│  └────────────┘  └──────────────┘  │   guard, budget)     │  │
│                                    └──────────────────────┘  │
│                                               │              │
│  ┌────────────────────────────────────────────┼───────────┐  │
│  │                Analysis Pipeline           │           │  │
│  │  ┌─────────────┐ ┌────────────┐ ┌──────────▼─────────┐ │  │
│  │  │ Target      │ │ Client-Side│ │  Account Recon     │ │  │
│  │  │ Validator   │ │ Deobfusc.  │ │  (public profile)  │ │  │
│  │  │ (DNS/HTTP)  │ │ (HTML+JS)  │ └──────────┬─────────┘ │  │
│  │  └─────────────┘ └────────────┘            │           │  │
│  │  ┌──────────────┐ ┌────────────────┐ ┌─────▼─────────┐ │  │
│  │  │ Login Flow   │ │ Enumeration    │ │ Profile       │ │  │
│  │  │ Prober       │ │ Analyzer       │ │ Analyzer      │ │  │
│  │  └──────────────┘ └────────────────┘ └─────┬─────────┘ │  │
│  │  ┌──────────────────────────────────────┐  │           │  │
│  │  │ Differential / DP / Binning / Crypto │◄─┘           │  │
│  │  │ Fingerprinting / Role Diff           │              │  │
│  │  └──────────────────────────────────────┘              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                               │              │
│  ┌────────────────────────────────────────────▼───────────┐  │
│  │  Technique Contract Builder + JSON Report + SHA-256 log │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

📦 Requirements

· Python ≥ 3.9
· pip packages:
  · requests (required)
  · dnspython (optional — improved DNS fallback)
· Optional but recommended:
  · Node.js ≥ 18 + @babel/parser, @babel/traverse, @babel/generator (for AST-based JS beautification)
  · Playwright (for the generated pause_runner.py instrumentation)

ZephyrOS ships as a single file (zephyros.py or 10.py), so no packaging step is required.

---

🚀 Installation

1. Clone and enter the directory

```bash
git clone https://github.com/your-org/zephyros.git
cd zephyros
```

2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate            # Linux/macOS
# .venv\Scripts\activate             # Windows PowerShell
```

3. Install Python dependencies

```bash
pip install --upgrade pip
pip install requests
pip install dnspython               # optional, improves DNS fallback
```

4. (Optional) Install Node + Babel for AST bridge

```bash
# macOS / Linux
brew install node                   # or your distro's package manager

# Then, in the zephyros directory:
npm init -y
npm install @babel/parser @babel/traverse @babel/generator
```

5. (Optional) Install Playwright for pause instrumentation

```bash
pip install playwright
playwright install chromium
```

6. Make the script executable

```bash
chmod +x zephyros.py
./zephyros.py --self-test
```

You should see N/N checks passed if everything is wired up correctly.

---

🧰 Installation of Companion Tools

ZephyrOS produces raw artifacts (deobfuscated.html, deobfuscated.js, pause.js, pause_runner.py) that pair well with three well-known open-source tools. Installing them locally dramatically improves your manual verification workflow.

🔬 CyberChef

What it is: A browser-based "cyber swiss army knife" for encoding/decoding, hashing, regex, and crypto operations — the single best visual companion for ZephyrOS's StringCascade decoder trail.

When to use it: When ZephyrOS reports a trail like ["base64","url","js-escape"] and you want to replay it step-by-step on the decoded value.

Install — Method A: Docker (recommended)

```bash
docker pull ghcr.io/gchq/cyberchef:latest
docker run -d --rm -p 8080:80 --name cyberchef ghcr.io/gchq/cyberchef:latest
```

Then open http://localhost:8080 in your browser.

Install — Method B: Static release (no Docker)

1. Download the latest release archive from github.com/gchq/CyberChef/releases.
2. Extract CyberChef_vX.Y.Z.html.
3. Open it in any modern browser — everything runs locally.

Install — Method C: Build from source

```bash
git clone https://github.com/gchq/CyberChef.git
cd CyberChef
npm install
npm run build            # produces build/prod/CyberChef_*.html
```

ZephyrOS ↔ CyberChef workflow

1. ZephyrOS writes the report → note the decode_chains array.
2. Open CyberChef, drag From Base64 → URL Decode → From Escape Sequence into the Recipe pane.
3. Paste the raw masked value. Verify the decoded output matches ZephyrOS's chain output.

---

🕸 webcrack

What it is: A modern JavaScript deobfuscator (webcrack on npm) that unminifies, unpacks, and simplifies bundles — a powerful second opinion after ZephyrOS's built-in passes.

When to use it: When ZephyrOS reports PackerUnpackerPass hits or heavy control-flow flattening, feed the original external script to webcrack for cross-validation.

Install

```bash
# Global install
npm install -g webcrack

# Verify
webcrack --version
```

Or, project-local:

```bash
cd zephyros
npm install --save-dev webcrack
npx webcrack --version
```

Basic usage

```bash
# Deobfuscate a single script
webcrack deobfuscated.js -o webcrack_out

# Deobfuscate with unminification + unpacking
webcrack input.js --unpack --unminify -o webcrack_out

# Recursively process a folder of scripts
webcrack scripts/ -o webcrack_out
```

ZephyrOS ↔ webcrack workflow

```bash
# Extract a script body from the ZephyrOS report (jq required)
jq -r '.client_side.js_findings.per_script[] | .name' \
   authorized_lab_report.json

# Then run webcrack against the raw script URL you noted in the report
curl -s "https://target.example.com/static/app.js" > app.js
webcrack app.js --unpack --unminify -o webcrack_out
diff <(cat zephyros_out/deobfuscated.js) webcrack_out/app.js
```

---

🔁 REstringer

What it is: A JavaScript deobfuscation framework (npm restringer) that specifically handles obfuscator.io, javascript-obfuscator, and similar string-array/control-flow patterns — a deep counterpart to ZephyrOS's lightweight passes.

When to use it: When ZephyrOS detects ControlFlowDetector hits or StringArrayResolverPass resolves, run REstringer to produce a fully beautified reference build.

Install

```bash
# Global install
npm install -g restringer

# Verify
restringer --version
```

Or project-local:

```bash
cd zephyros
npm install --save-dev restringer
npx restringer --version
```

Basic usage

```bash
# Deobfuscate a single file with all passes
restringer input.js -o restringer_out.js

# Deobfuscate and preserve source-map-ish comments
restringer input.js --verbose -o restringer_out.js
```

ZephyrOS ↔ REstringer workflow

```bash
# Use the same raw script you fed webcrack
restringer app.js -o app.restringered.js

# Diff REstringer's output against ZephyrOS's deobfuscator output
diff -u zephyros_out/deobfuscated.js app.restringered.js | less
```

Pro tip: Keep all three tools in the same working directory so you can quickly cross-reference outputs. ZephyrOS artifacts are already written to zephyros_out/ by default.

---

⚡ Quick Start

1. Run the self-test

```bash
./zephyros.py --self-test
```

2. Run against a lab target (enumeration mode)

```bash
./zephyros.py \
  --base-url https://lab.example.com \
  --login-page https://lab.example.com/login \
  --identifier john.doe \
  --operator "jdoe" \
  --authorization-reference "TICKET-1234" \
  --env lab \
  --i-have-written-authorization \
  --report ./report.json
```

3. Run with an authenticated session (profile analysis)

```bash
./zephyros.py \
  --base-url https://lab.example.com \
  --identifier john.doe@example.com \
  --password 'CorrectHorseBatteryStaple' \
  --known-email john.doe@example.com \
  --known-name "John Doe" \
  --operator "jdoe" \
  --authorization-reference "TICKET-1234" \
  --i-have-written-authorization \
  --report ./report.json
```

4. Generate pause instrumentation only

```bash
./zephyros.py --pause-only \
  --login-page https://lab.example.com/login \
  --client-out-dir ./instrument

# Follow the printed next step:
python ./instrument/pause_runner.py \
  https://lab.example.com/login \
  ./instrument/pause.js
```

---

📘 CLI Reference

Flag Type Default Description
--version — — Print version and exit.
--self-test flag — Run internal checks.
--interactive flag — Launch the guided wizard.
--autopilot flag — Auto-detect mode, minimal prompts.
--pause-only flag — Only generate pause.js + runner.
--base-url str — Target base URL (required in non-interactive mode).
--login-page str base URL Login page URL for client-side analysis.
--identifier / --username / --email / --phone str — Exactly one required.
--country-code str — Hint for phone normalization (BD, +880, …).
--password str — If set, runs authenticated mode.
--login-url str /api/login Login POST endpoint.
--profile-url str auto Profile GET endpoint.
--username-field / --password-field str auto Override request body keys.
--known-name / --known-email / --known-phone str — Authorized plaintext for mask reconstruction.
--secondary-username / --secondary-password str — Second account for role-diff.
--dictionary path built-in Extra candidate words.
--word-priors path built-in JSON of {word: prior}.
--training path — JSON [{original, masked}] pairs to learn from.
--evaluate path — JSON eval pairs; runs harness and exits.
--eval-with-known flag — Use known plaintext during eval.
--rate float 0.5 Requests per second (capped at 0.1 in prod).
--timeout int 20 Per-request timeout (seconds).
--insecure-tls flag — Disable TLS verification (lab only).
--allow-plaintext flag — Permit http:// targets.
--repeat-reads int 5 Repeated profile fetches for DP/binning stats.
--guard-tolerance int 1 Hard 401/403/429 budget before abort.
--max-requests int 500 Total request budget.
--allowed-hosts csv origin Additional allowed host[:port] entries.
--scope-file path — JSON {"hosts": [...]}.
--auth-header repeat — Extra header: "Name: Value".
--auth-token-file path — File containing bearer token.
--operator str unknown Operator name.
--authorization-reference str unspecified Ticket / contract ID.
--env choice lab lab / staging / prod.
--confirm-prod flag — Required for --env prod.
--report path authorized_lab_report.json Report output.
--include-pii flag — Keep raw PII in report.
--redact-report flag — Force redaction even if --include-pii.
--no-enumeration flag — Skip enumeration probes.
--client-side / --no-client-side flag on Toggle client-side deobfuscation.
--client-out-dir path zephyros_out Artifact directory.
--client-max-scripts int 20 Cap on external scripts fetched.
--no-node flag — Disable AST bridge.
--no-pause flag — Skip pause.js generation.
--account-recon / --no-account-recon flag on Toggle account recon.
--json-out flag — Print final JSON report to stdout.
--no-color flag — Disable ANSI colors.
--dry-run flag — Skip enumeration; run access-control test only.
--probe-auth-shape flag — Probe login error shape before real login.
--quiet / --verbose / --no-verbose flag verbose Log verbosity.
--resume path — Merge additional training pairs from a prior run.
--i-have-written-authorization flag — Required in non-interactive mode (except --evaluate / --self-test / --pause-only).

---

🧭 Interactive Mode Walkthrough

Running ./zephyros.py with no arguments opens the guided wizard:

```
Target base URL > https://lab.example.com
Login page URL [default: base URL root] >
Operator identity (optional) > jdoe
Authorization reference / ticket (optional) > TICKET-1234
Confirm written authorization to test this target? [y/N]: y

Identifier (username / email / phone with country code) > john.doe
Password [Enter to skip -> enumeration mode] >
[interactive] mode: enumeration
Run client-side HTML/JS deobfuscation on login page? [Y/n]:
Client-side output directory [zephyros_out] >
...
[setup summary]
  target          : https://lab.example.com
  login page      : https://lab.example.com
  identifier      : username
  mode            : enumeration
  account recon   : True
  client-side     : True (out=zephyros_out, scripts<=20)
  node AST bridge : True
  pause generator : True
  operator        : jdoe
  auth reference  : TICKET-1234
  env             : lab
  rate            : 0.5/s
  repeats         : 5
  enumeration     : True
  second account  : no
  allowed hosts   : <origin>
  scope file      : <none>
  report          : authorized_lab_report.json
  include PII     : False
Proceed? [Y/n]:
```

Defaults are tuned for lab use. For prod, the wizard double-confirms and caps the rate at 0.1 req/s.

---

🤖 Autopilot Mode

```bash
./zephyros.py --autopilot
```

Autopilot asks only:

1. Target base URL
2. Identifier
3. Password (optional)
4. Two confirmations (authorization + prod-ack)

It then auto-detects environment from the URL (.lab., localhost, staging, dev, qa) and chooses defaults accordingly.

---

🔬 Analysis Modules Explained

1. Mask Analyzer Stack

Four analyzers run in sequence on every masked field:

Analyzer Family What it detects
beginner_fixed_mask prefix_suffix abc****xyz — mask position and fixed-width hint
intermediate_partial_mask multi_segment Multiple visible/mask segments
advanced_format_aware format_aware Email/phone/name structure; ranks candidates via P(mask\|candidate) × P(candidate)
hyper_adaptive learned_rule_bayesian Skeleton similarity + rule agreement + Bayesian posterior over learned pairs

Scores are aggregated into a confidence interval via softmax over the top-20 logits plus a Wilsonian-style margin.

2. Iterative Decoder

StringCascade + recursive_decode build up to depth-5 chains of:

```
URL → Base64 → Base32 → Hex → ROT13 → Caesar → Reverse
    → JS-escape → HTML-entity → PHP gzinflate(base64) → PHP str_rot13
```

Every chain is preserved in the report so you can replay it in CyberChef.

3. Differential Privacy Estimator

RepeatedReadAnalyzer reads the same endpoint N times and reports:

· verdict: stable | numeric_noise | categorical_noise
· noise_scale_laplace_b = sqrt(var / 2)
· noise_scale_gaussian_sigma = sqrt(var)
· epsilon_laplace and epsilon_gaussian at δ = 1e-5

4. Binning Detector

Detects equal_width, equal_frequency, and log_scale binning using coefficient-of-variation on adjacent-value gaps.

5. Client-Side Deobfuscation

Pass Purpose
ArrayRotationPass Detects and inlines the classic _0x… rotation IIFE
StringArrayResolverPass Replaces _0xabc(0x12) calls with literal strings
PackerUnpackerPass Decodes Dean Edwards eval(function(p,a,c,k,e,d){…}) packs
EvalUnnestPass Unwraps eval("…") / new Function("…") literals (max depth 6)
StringConcatFoldPass Folds "a" + "b" into "ab"
ControlFlowDetector Flags var a="x\|y\|z".split("\|") order tables
DeadCodeDetector Flags unused var declarations
NodeBridge (optional) Sends output to Babel for identifier normalization + beautification

6. Skimmer & Phishing Detection

· Skimmer: credential-field read + keyboard listener + network sink co-occurrence → HIGH
· Phishing: off-origin form action · password-in-GET · hidden password form → HIGH / MEDIUM

7. Account Recon

Finds a public profile endpoint by probing a curated list and comparing against a random baseline. Extracts:

· Public ID and shape (numeric / alpha / mixed)
· Visibility (public / private / unknown) from allow-listed fields
· Public fields limited to ALLOWED_PROFILE_FIELDS

8. Login Flow Prober

· POSTs {identifier: value, password: wrong_pw} and extracts fields_required heuristically
· Runs the cascade decoder on the response → reports obfuscated: true + deobfuscated preview
· Falls back to /api/forgot-password, /api/auth/forgot, etc. if login is uninformative

9. Enumeration Analyzer

Compares identifier-vs-baseline responses across:

1. Login error body/status
2. Forgot-password response
3. /api/check-username/{id} variants
4. /api/users/{id} variants

Reports *_differs or *_consistent for each.

---

📄 Report Schema (Abridged)

```jsonc
{
  "tool": "ZephyrOS",
  "tool_version": "11.1.0",
  "zephyr_author": "SYLHETYHACKVENGER (THE-ERROR808)",
  "generated_at": "2025-01-01T00:00:00+00:00",
  "mode": "authenticated",
  "identifier": { "type": "email", "raw_sha256_16": "…" },
  "operator": "jdoe",
  "authorization_reference": "TICKET-1234",
    "target_info": {
    "ipv4": ["203.0.113.42"],
    "ipv6": ["2001:db8::1"],
    "domain": "example.com",
    "subdomain": "lab",
    "reachable": true,
    "http_status": 200,
    "tls_ok": true
  },
  "request_count": 37,
  "soft_guard_count": 0,
  "hard_guard_count": 0,
  "guard_hits": [],
  "technique_contracts": {
    "partial_masking":          { "name": "Partial masking",            "detected": true,  "attempted": true },
    "format_preserving_masking":{ "name": "Format-preserving masking",  "detected": true,  "attempted": true },
    "tokenization_or_pseudonymization": { "name": "Tokenization or pseudonymization", "detected": false, "attempted": true },
    "enumeration_login_diff":   { "name": "Username enumeration via login diff", "detected": true, "attempted": true },
    "client_js_obfuscation":    { "name": "Client-side JS obfuscation","detected": true,  "attempted": true }
  },
  "profile_findings": [
    {
      "field": "user.email",
      "parent": ["user"],
      "original_value": "jo***@example.com",
      "classification": {
        "technique_id": "partial_masking",
        "technique": "Partial masking",
        "confidence": 0.82,
        "ci": [0.72, 0.92],
        "algorithmically_reversible": true,
        "authorized_recovery_available": true,
        "recovery_path": "known_plaintext"
      },
      "masked": true,
      "mask_analyses": [
        {
          "method_family": "format_aware",
          "confidence": 0.61,
          "ci": [0.51, 0.71],
          "candidates": ["john", "joe", "joan", "joanne"]
        }
      ],
      "decode_chains": [],
      "plausibility": { "plausibility": 0.0031, "verdict": "plausible_real_value" },
      "id_structure": null
    }
  ],
  "repeated_read": {
    "user.reputation": {
      "verdict": "numeric_noise",
      "noise_scale_laplace_b": 12.4,
      "epsilon_laplace_if_sensitivity_1": 0.081
    }
  },
  "binning": {
    "user.age": { "verdict": "equal_frequency_binning", "samples": 5 }
  },
  "crypto_fingerprint": {
    "verdict": "cryptographic_endpoint_fingerprint",
    "schemes": { "zkp": ["pi_a", "pi_b", "groth16"] },
    "strength": "strong"
  },
  "account_recon": {
    "public_endpoint": "/api/users/john.doe",
    "id": "10042",
    "id_shape": "numeric",
    "visibility": "public",
    "public_field_count": 6
  },
  "login_flow": {
    "login": {
      "status": 401,
      "fields_required": ["password"],
      "obfuscated": true,
      "trail": ["base64", "url"]
    }
  },
  "client_side": {
    "enabled": true,
    "inline_script_count": 3,
    "external_script_count": 4,
    "js_findings": {
      "control_flow_flattening": [{ "order_var": "_0xabc", "script": "app.js" }],
      "dead_vars": [],
      "per_script": [
        { "name": "app.js", "original_len": 51200, "deobfuscated_len": 28400 }
      ]
    },
    "skimmer_hits": [
      { "pattern": "credential-exfil-flow", "verdict": "HIGH", "script": "app.js" }
    ],
    "phishing_hits": [],
    "artifacts": {
      "html": "zephyros_out/deobfuscated.html",
      "js":   "zephyros_out/deobfuscated.js",
      "pause_js": "zephyros_out/pause.js",
      "pause_runner": "zephyros_out/pause_runner.py"
    }
  },
  "log_sha256": "8f14e45fceea167a5a36dedd4bea2543…",
  "status": "ok",
  "dependencies": {
    "requests": "2.32.3",
    "urllib3": "2.2.2",
    "certifi": "2024.7.4"
  }
}

    All PII values (names, emails, phones, IDs) are automatically redacted unless you explicitly pass --include-pii. See redact_sensitive_values() in the source.

---

🚦 Exit Codes

Code Constant Meaning
0 EXIT_OK Scan completed successfully.
1 EXIT_ERROR Generic error (parsing, I/O, unexpected exception).
2 EXIT_GUARD Guard tolerance exceeded (repeated 401/403/429).
3 EXIT_AUTH_REFUSED Authorization not acknowledged, or login refused.
4 EXIT_SCOPE Scope violation (host outside allow-list, request budget hit, plaintext HTTP without --allow-plaintext).
5 EXIT_INTERRUPT User-interrupted (SIGINT / SIGTERM).
6 EXIT_NO_TARGET --pause-only invoked without a target URL.

Exit codes make ZephyrOS easy to chain in CI or bug-bounty pipelines:

```bash
./zephyros.py ... --report report.json
case $? in
  0) echo "✅ clean report";;
  2) echo "⚠️  target is actively blocking us";;
  3) echo "❌ authorization problem";;
  4) echo "❌ scope problem — check --allowed-hosts";;
  *) echo "❌ unexpected failure";;
esac
```

---

🛡 Rate Limiting & Guard Behavior

ZephyrOS is deliberately slow by default. Three independent controls protect the target:

1. Token-bucket throttle

· --rate 0.5 → one request every ~2 seconds.
· In --env prod, the effective rate is capped at 0.1 req/s regardless of --rate.
· Discovery requests (robots.txt, OpenAPI, script fetches) reserve min(20, max_requests // 3) slots so you never starve the main analysis.

2. Guard detection

· Any 401, 403, or 429 response increments the guard counter.
· Soft probes (enumeration, enumeration fallbacks) increment soft_guard_count but do not abort.
· Hard probes abort once --guard-tolerance (default 1) is reached — because repeated hard failures usually mean you've tripped a WAF.
· All hits are preserved in guard_hits / soft_guard_hits in the report.

3. Host allow-list

· The target origin is always allowed; add more with --allowed-hosts or --scope-file.
· Every request URL is checked before the socket is opened. Violations raise ScopeViolationError and exit with code 4.

4. Response size cap

· Responses larger than 20 MiB abort with LabToolError. This prevents accidental download of a CDN tarball.

---

✅ Self-Test

--self-test runs 35+ offline checks covering:

· Luhn / IBAN checksums (valid + invalid cases)
· Base64 / hex / ROT13 / Caesar / reverse decoders
· URL and JS-escape cascade behavior
· Mask skeleton parsing, mask-symbol detection, leak detection
· Identifier type + phone normalization (including BD country hint)
· Target validator (localhost resolution)
· Account recon visibility / ID shape / scrape counts
· Config PII redaction defaults — verifies --include-pii is off unless explicitly requested
· Packer unpacker smoke test
· Phishing + skimmer detection signatures
· Author identity check

```bash
$ ./zephyros.py --self-test
  [PASS] luhn_valid
  [PASS] luhn_invalid
  [PASS] iban_valid
  ...
  38/38 checks passed
```

If any check fails, you're either on an extremely old Python or missing requests.

---

🩺 Troubleshooting

[FATAL] requests required

```bash
pip install requests
```

Node bridge unavailable

You can safely ignore this warning — ZephyrOS falls back to its own passes. If you want AST support:

```bash
node --version                                    # must be ≥ 18
npm install @babel/parser @babel/traverse @babel/generator
```

If node is present but the bridge still fails, the Babel packages likely aren't in NODE_PATH. Run node -e "require('@babel/parser')" to confirm.

playwright install fails

Try:

```bash
pip install --upgrade playwright
playwright install --with-deps chromium
```

On Linux you may need libnss3, libatk-bridge2.0-0, libgbm1, libasound2.

GuardTriggeredError on the first request

The target is returning 401/403/429 for the bare lab identifier. Common causes:

· Missing auth header — add --auth-header "X-Lab-Token: …" or --auth-token-file.
· The identifier doesn't exist — try --dry-run first to confirm the origin is reachable.
· Cloudflare / Akamai bot challenge — this is the target telling you to stop; do not retry aggressively.

ScopeViolationError: Host … not in allowed hosts

Your login redirect points to a CDN or auth subdomain (e.g. auth.example.com, cdn.example.net). Add them explicitly:

```bash
./zephyros.py --allowed-hosts "auth.example.com,cdn.example.net" ...
```

Or use a scope file:

```json
{ "hosts": ["auth.example.com", "cdn.example.net"] }
```

Report has "status": "guard" but exit code is 2

That's expected: guard abort is a successful analysis outcome. Check technique_contracts — everything you probed before the guard is still recorded.

cyberchef, webcrack, restringer not found

All three are optional. ZephyrOS doesn't call them automatically; they're for manual verification. Install them only if you want a stronger second opinion:

```bash
# CyberChef (Docker)
docker run -p 8080:80 ghcr.io/gchq/cyberchef:latest

# webcrack
npm install -g webcrack

# REstringer
npm install -g restringer
```

"It runs but finds nothing"

Check technique_contracts.<tid>.attempted in the report:

· attempted: false → the stage was skipped (e.g. enumeration disabled, no password).
· attempted: true, detected: false → the probe ran but the target behaved cleanly. This is a positive result for the target.

Try --verbose to see each HTTP call, or --probe-auth-shape to inspect the login error body shape before real login.

---

🗺 Roadmap

☐ Har mode — replay a .har file instead of hitting the network, for offline re-analysis.
☐ SARIF export — emit SARIF 2.1.0 alongside JSON for GitHub Code Scanning.
☐ HTTP/2 + HTTP/3 — via httpx fallback when available.
☐ GraphQL support — auto-discover __typename and probe /graphql for masked fields.
☐ YAML scope — support both scope.json and scope.yml.
☐ Playwright pre-run — optional headless capture of network + DOM before static analysis.
☐ --diff-report old.json new.json — CI-friendly regression comparison.

---

🤝 Credits

Role Contributor
Author & Maintainer SYLHETYHACKVENGER (THE-ERROR808)
Mask-analyzer methodology Inspired by publicly documented work on format-preserving encryption and k-anonymity research
Decoder cascades Pattern-adapted from the cyber-chef recipe library and well-known CTF writeups
JS deobfuscation Pass design inspired by webcrack, restringer, and synchrony
Skimmer detection Modeled after the "Magecart" credential-harvest taxonomy

If you build something on top of ZephyrOS, please credit the author and link back to this repository.

---

📜 License & Acceptable Use

ZephyrOS is distributed for authorized security research and defensive engineering only. It is not licensed for use against systems you do not own or lack written permission to test.

· Do not use ZephyrOS to attack, damage, or exfiltrate data from any system.
· Do not remove or alter the authorization confirmation prompts.
· Do not redistribute modified builds without preserving the ZEPHYR_AUTHOR banner and the --i-have-written-authorization gate.

By using this software, you accept full responsibility for ensuring your activity is lawful in your jurisdiction and covered by a valid engagement.

---

<div align="center">

ZephyrOS 11.1.0 · built by SYLHETYHACKVENGER (THE-ERROR808)

Prove the mask. Understand the leak. Stay authorized.

```
account recon  ·  login flow  ·  deobfuscation
──────────────────────────────────────────────
```

</div>
