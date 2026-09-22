# recon.py + secret-scan.py

Complete bug bounty reconnaissance and JS secret scanning toolkit.

```
recon.py  →  subdomain enum → httpx → URL collection → GF → nuclei
                    ↓
secret-scan.py  →  port scan → JS discovery → Playwright → secrets → key validation → endpoints
```

Both tools are designed to chain: `recon.py` output feeds directly into `secret-scan.py` via `--recon-dir`.

---

## Installation

### Python

```bash
pip install requests playwright
playwright install chromium   # for runtime JS capture (optional)
```

### Go tools (recon.py)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/gf@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Nuclei fuzzing templates

```bash
git clone https://github.com/projectdiscovery/fuzzing-templates.git
```

### Custom GF patterns

Two GF patterns not in the default collection. Copy them to `~/.gf/`:

```bash
mkdir -p ~/.gf
cp tools/csti.json tools/rfi.json ~/.gf/
```

### API keys

```bash
# ~/.bashrc or ~/.zshrc
export CHAOS_KEY="your-projectdiscovery-chaos-key"
export GITHUB_TOKEN="ghp_your_github_pat"
```

Both tools parse rc files with regex (bypasses Ubuntu's `[ -z "$PS1" ] && return` guard).

---

## Quick start

```bash
# Full pipeline: recon → JS secret scan
python3 recon.py example.com -o ./recon_output
python3 secret-scan.py --recon-dir recon_output/example.com_20260922_143000/

# Recon only, skip nuclei
python3 recon.py example.com --skip-nuclei

# Secret scan only (from an existing recon)
python3 secret-scan.py --recon-dir ./recon_output/example.com_20260922_143000/

# Secret scan via TOR, critical + high only
python3 secret-scan.py --recon-dir . --tor --severity critical,high

# Secret scan without browser / port scan (faster)
python3 secret-scan.py --recon-dir . --no-playwright --no-port-scan
```

---

# recon.py

## Pipeline

| Phase | Description | Tools |
|-------|-------------|-------|
| **1 · Subdomain Enum** | Passive subdomain discovery from 5 sources in parallel | crt.sh · chaos · github-subdomains · assetfinder · subfinder |
| **2 · Host Validation** | Validate live hosts, extract IP, title, tech stack | httpx |
| **2b · Extract** | Write bare hostnames and unique IPs to separate folders | — |
| **3 · URL Collection** | Historical + active URL collection (passive first, then crawlers) | gau · waybackurls · wayback-api · commoncrawl · katana · hakrawler · gospider |
| **4 · GF Patterns** | Pre-filter URLs by injection parameter class | gf |
| **5 · Nuclei** | Fuzz GF-filtered URLs and all hosts with fuzzing-templates | nuclei |

## Usage

```bash
python3 recon.py example.com
python3 recon.py example.com -o /tmp/recon --tor
python3 recon.py example.com --skip-nuclei
python3 recon.py example.com --nuclei-patterns xss sqli crlf xxe
python3 recon.py example.com --rate-limit 50 --concurrency 10
python3 recon.py example.com --nuclei-flags '-H "Authorization: Bearer TOKEN"'
python3 recon.py example.com --subdomains-file subs.txt --skip-enum
```

## Options

```
positional:
  domain                  Target domain (e.g. example.com)

general:
  -o, --output DIR        Output base directory (default: ./recon_output)

tokens:
  --chaos-key KEY         ProjectDiscovery CHAOS key (or $CHAOS_KEY)
  --github-token TOKEN    GitHub PAT for github-subdomains (or $GITHUB_TOKEN)

proxy:
  --tor                   Route Python HTTP through TOR (socks5h://127.0.0.1:9050)
                          Also sets HTTP_PROXY/HTTPS_PROXY for CLI tools

input override:
  --subdomains-file FILE  Use existing file; implies --skip-enum

skip phases:
  --skip-enum             Skip Phase 1
  --skip-httpx            Skip Phase 2
  --skip-urls             Skip Phase 3
  --skip-gf               Skip Phase 4
  --skip-nuclei           Skip Phase 5

nuclei:
  --nuclei-patterns LIST  Patterns to run (default: all 11)
  --user-agent UA         User-Agent header (default: Chrome/124 desktop)
  --rate-limit N          Max requests/second (default: 150)
  --concurrency N         Template concurrency (default: 25)
  --nuclei-flags FLAGS    Extra raw flags forwarded verbatim to nuclei
```

## GF patterns

GF pre-filters `all_urls.txt` before nuclei. Only URLs with matching parameters reach the scanner.

| Pattern | Matched parameters | Nuclei templates |
|---------|-------------------|-----------------|
| `redirect` | `url=`, `next=`, `return=`, `to=`, `dest=` | `fuzzing-templates/redirect/` |
| `xss` | `q=`, `search=`, `input=`, `query=` | `fuzzing-templates/xss/` |
| `sqli` | `id=`, `page=`, `cat=`, `order=` | `fuzzing-templates/sqli/` |
| `ssti` | `template=`, `view=`, `render=` | `fuzzing-templates/ssti/` |
| `rce` | `cmd=`, `exec=`, `ping=`, `run=` | `fuzzing-templates/cmdi/` |
| `lfi` | `file=`, `path=`, `dir=`, `inc=` | `fuzzing-templates/lfi/` |
| `ssrf` | `url=`, `api=`, `endpoint=`, `proxy=` | `fuzzing-templates/ssrf/` |
| `csti` | `template=`, `tpl=`, `expr=`, `ng=`, `angular=` | `fuzzing-templates/csti/` |
| `rfi` | `include=`, `load=`, `import=`, `src=` | `fuzzing-templates/rfi/` |

Two patterns skip GF (run against all URLs):

| Pattern | Why no GF filter |
|---------|-----------------|
| `crlf` | Injection possible in any endpoint, not only specific params |
| `xxe` | POST-body attack; URL parameters are irrelevant |

> `-dast` is always passed. Without it, fuzzing-templates fuzz-type templates are silently skipped.

## Output structure

```
recon_output/
└── example.com_20260922_143000/
    ├── subdomains/
    │   ├── raw_crtsh.txt
    │   ├── raw_chaos.txt
    │   ├── raw_github_subdomains.txt
    │   ├── raw_assetfinder.txt
    │   ├── raw_subfinder.txt
    │   └── all_subdomains.txt          ← deduplicated merge
    ├── httpx/
    │   ├── httpx_results.jsonl         ← IP, title, tech stack per host
    │   └── httpx_live.txt              ← live URLs with scheme
    ├── hosts/
    │   └── live_hosts.txt              ← bare hostnames (no scheme)
    ├── ips/
    │   └── unique_ips.txt              ← unique IPs sorted
    ├── urls/
    │   ├── raw_gau.txt
    │   ├── raw_waybackurls.txt
    │   ├── raw_wayback_api.txt
    │   ├── raw_commoncrawl.txt
    │   ├── raw_katana.txt
    │   ├── raw_hakrawler.txt
    │   ├── raw_gospider.txt
    │   └── all_urls.txt                ← deduplicated merge
    ├── gf/
    │   ├── gf_redirect.txt
    │   ├── gf_xss.txt
    │   └── ...                         ← one file per pattern
    └── nuclei/
        ├── nuclei_xss.txt              ← human-readable findings
        ├── nuclei_xss.jsonl            ← structured findings (JSONL)
        └── ...                         ← .txt + .jsonl per pattern
```

---

# secret-scan.py

JavaScript secret and endpoint scanner. Discovers, downloads, and analyses JS files from a target — including runtime-loaded bundles via a real browser — and validates collected API keys against live APIs.

## Pipeline

| Phase | Description |
|-------|-------------|
| **0 · Port Discovery** | nmap (or socket fallback) on 34 HTTP ports against each unique IP → finds hidden services |
| **1 · JS Discovery** | Filter `all_urls.txt` for `.js` files + probe common paths on all live hosts |
| **1b · Playwright** | Headless Chromium intercepts all network responses → captures lazy-loaded chunks, webpack splits, dynamic imports, and `.map` files in a single browser pass |
| **2 · Download** | Concurrent download of all discovered JS files (skips known CDN/tracker domains) |
| **3 · Source Maps** | Fetch `.map` files → extract original unminified source from `sourcesContent[]` |
| **4 · Secret Scan** | 46 built-in patterns covering AWS, GitHub, Stripe, Firebase, Supabase, OpenAI, Anthropic, JWTs, private keys, DB connection strings, and more |
| **4b · Key Validation** | Live API validation for 16 credential types — confirms which keys are actually active |
| **5 · Endpoints** | Extract API paths with HTTP method inference from JS context |

## Usage

```bash
# From recon.py output (recommended)
python3 secret-scan.py --recon-dir recon_output/example.com_20260922_143000/

# Manual inputs
python3 secret-scan.py --urls-file urls.txt --hosts-file hosts.txt --ips-file ips.txt

# Scan pre-downloaded JS directory
python3 secret-scan.py --js-dir ./js/ --severity critical,high

# TOR + skip browser
python3 secret-scan.py --recon-dir . --tor --no-playwright

# Fast mode — no port scan, no browser, no key validation
python3 secret-scan.py --recon-dir . --no-port-scan --no-playwright --no-validate
```

## Options

```
input:
  --recon-dir DIR         recon.py output dir (auto-detects all inputs)
  --urls-file FILE        URL list (overrides recon-dir urls)
  --hosts-file FILE       Live hosts list (overrides recon-dir hosts)
  --ips-file FILE         IPs for port scan (overrides recon-dir ips)
  --js-dir DIR            Pre-downloaded JS directory (skips download phase)

general:
  -o, --output DIR        Output base directory (default: ./secret_output)
  --target NAME           Target name label
  --severity LEVELS       Comma-separated: critical,high,medium,low (default: all)
  --threads N             Download/scan threads (default: 15)
  --user-agent UA         User-Agent header

proxy:
  --tor                   Route all requests through TOR (socks5h://127.0.0.1:9050)

skip phases:
  --no-port-scan          Skip Phase 0
  --no-playwright         Skip Phase 1b (browser crawl)
  --no-sourcemaps         Skip Phase 3
  --no-validate           Skip Phase 4b (key validation)
  --no-endpoints          Skip Phase 5

playwright:
  --playwright-timeout N  Page timeout in seconds (default: 25)
```

## Secret patterns (46 total)

| Severity | Patterns |
|----------|---------|
| **Critical** | AWS Access Key, AWS Secret Key, GCP Service Account JSON, Azure Storage Connection String, GitHub Fine-grained PAT, GitHub Classic PAT, GitLab PAT, Stripe Secret Key (live), Square OAuth Secret, PayPal/Braintree Token, Anthropic API Key, OpenAI API Key, Database Connection String, Private Key (PEM) |
| **High** | Google API Key, Google OAuth Client ID, GitHub OAuth/Actions Token, Stripe Publishable Key (live), Slack Token, Slack Webhook, Twilio SID, SendGrid API Key, Mailgun API Key, Firebase Server Key, Supabase Service Key (JWT), Heroku API Key, npm Access Token, HuggingFace Token, DataDog API Key, URL with Embedded Credentials |
| **Medium** | Stripe Secret Key (test), Discord Webhook, Mapbox Token, Algolia Key, Cloudinary URL, Sentry DSN, JWT Token, Hardcoded Credential, Google OAuth Client ID, Internal IP Address |
| **Low** | AWS ARN, S3 Bucket Reference, Internal IP Address |

### False positive filters

The `hardcoded_cred` pattern applies multiple filters to eliminate noise from minified JS:

- **Placeholder values** — `access_token`, `client_secret`, `your-api-key-here`, `wrong-password`, Firebase Auth error codes, etc.
- **UI label phrases** — multi-word strings composed only of letters/spaces/punctuation (e.g. `"Confirmar senha"`, `"Password required"`)
- **JS code fragments** — values containing `()`,`;{}[]` (minified code accidentally captured after `secret:`)
- **CSS selectors** — values starting with `.`, `#`, `[`, `*`
- **VAPID public keys** — `B[A-Za-z0-9_-]{86,88}` (RFC 8292 Web Push — intentionally public)

### CDN domain blocklist

JS from these domains is skipped entirely (public library / third-party tracker code):

`cdn.jsdelivr.net` · `unpkg.com` · `cdnjs.cloudflare.com` · `www.youtube.com` · `connect.facebook.net` · `analytics.tiktok.com` · `www.googletagmanager.com` · `static.hotjar.com` · `js.stripe.com` · `static.zohocdn.com` · `cdn.onetrust.com` · and 20+ more

## Key validation

Live API tests for discovered secrets:

| Pattern | API endpoint used |
|---------|-----------------|
| `github_pat_*` | `GET /user` with `Authorization: token` |
| `gitlab_token` | `GET https://gitlab.com/api/v4/user` |
| `stripe_sk_*` | `GET /v1/charges?limit=1` with basic auth |
| `slack_token` | `GET /api/auth.test` |
| `openai_key` | `GET /v1/models` |
| `anthropic_key` | `POST /v1/messages` (1-token probe) |
| `sendgrid` | `GET /v3/user/profile` |
| `npm_token` | `GET /-/whoami` |
| `huggingface` | `GET /api/whoami` |
| `discord_webhook` | `GET <webhook_url>` |
| `mapbox_token` | `GET /tokens/v2?access_token=` |

Validation status per finding: `valid: true` / `valid: false` / `valid: null` (indeterminate).

## Endpoint extraction

Endpoints are extracted from all JS files and source maps, grouped by domain, with HTTP method inference from surrounding JS context.

Method inference priority:
1. Explicit: `method: "POST"` in fetch/axios options
2. Named methods: `axios.post(`, `axios.get(`, `router.post(`
3. Path heuristics: paths containing `create`, `authorize`, `checkout` → `POST?`; paths with `?`, `/list`, `/status` → `GET?`
4. Unknown: `?`

Output files:
- `findings/endpoints.txt` — grouped by domain, human-readable
- `findings/endpoints.json` — machine-readable with method, domains, occurrence count

Example `endpoints.txt`:

```
# app.openfinance.nuclea.com.br  (47 endpoints)

  POST?    /api/automatic/authorize
  GET?     /api/automatic/authorizations
  POST?    /api/automatic/enrollments/create
  GET?     /api/automatic/enrollments/list
  GET?     /api/automatic/status?authorizationId=${r}&linkId=${i?.id}
  POST?    /api/broadcast
  POST?    /api/checkout
  ...
```

## Output structure

```
secret_output/
└── example.com_20260922_150000/
    ├── js/                             ← downloaded JS files
    ├── sourcemaps/
    │   ├── playwright/                 ← .map files fetched by browser
    │   └── <chunk_name>/               ← extracted original source files
    ├── findings/
    │   ├── secrets.jsonl               ← all findings + validation status
    │   ├── endpoints.txt               ← API paths grouped by domain with methods
    │   ├── endpoints.json              ← machine-readable endpoints
    │   └── gitleaks.json               ← gitleaks output (if installed)
    └── report.md                       ← full markdown report
```

### `secrets.jsonl` schema

```json
{
  "pattern":   "github_pat_classic",
  "label":     "GitHub Classic PAT",
  "severity":  "critical",
  "value":     "ghp_AbCdEf...",
  "line":      42,
  "context":   "const TOKEN = \"ghp_AbCdEf...\"",
  "source":    "https://app.example.com/static/js/main.abc123.js",
  "validated": {
    "valid": true,
    "info":  "GitHub user: johndoe"
  }
}
```

---

## Notes

- **Deduplication:** When the same value matches multiple patterns (e.g. a Supabase JWT matches both `supabase_key` and `jwt_token`), only the highest-severity finding is kept.
- **Source maps:** Playwright intercepts `.map` responses during page load — no separate fetch needed. Static JS falls back to parsing `//# sourceMappingURL=` comments.
- **Port scanning:** Uses `nmap` if available, falls back to Python `socket.create_connection`. Probes 34 ports: 80, 443, 3000, 3001, 8080, 8443, 9000, and others.
- **TOR:** Applied to all `requests.Session` calls in both phases — download, probing, and key validation.
- **Tool detection:** Missing tools are skipped with a warning, not a hard failure. A scan with only 3 of 5 subdomain tools still runs and produces valid output.
