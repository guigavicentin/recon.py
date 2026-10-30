#!/usr/bin/env python3
"""
secret-scan.py — JavaScript secret & endpoint scanner  v2.1

Phases:
  0  Port Discovery   nmap on IPs → find hidden HTTP/HTTPS services
  1  JS Discovery     all_urls.txt filter + common-path probing + Playwright crawl
                      (Playwright captures JS + .map files in a single browser pass)
  2  JS Download      concurrent download of static JS
  3  Source Maps      decompile .map → original source (only for non-Playwright JS)
  4  Secret Scan      66 built-in patterns + trufflehog/gitleaks if available
  4b Key Validation   live-test discovered keys against real APIs
  5  Endpoint Scan    API paths, hardcoded URLs, internal params

Usage:
  python3 secret-scan.py --recon-dir recon_output/example.com_20260922/
  python3 secret-scan.py --urls urls.txt --hosts hosts.txt -o ./out
  python3 secret-scan.py --js-dir ./js/ --severity critical,high
  python3 secret-scan.py --recon-dir . --tor --no-playwright --no-port-scan
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ─── Port Config ──────────────────────────────────────────────────────────────

HTTP_PORTS = [
    80, 81, 443, 3000, 3001, 4000, 4443, 5000, 5001,
    5900, 6000, 6443, 6885, 7077, 8000, 8080, 8081,
    8181, 8443, 9000, 9091, 9443, 9999, 10000, 15672,
    161, 2075, 2076, 3306, 3366, 3868, 4044,
]
HTTPS_PORTS  = {443, 8443, 9443, 4443, 6443, 2076, 10000, 5001}
NMAP_PORTS   = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))

_TOOL_DIR    = Path(__file__).resolve().parent
_KEYHUNT_PATH = _TOOL_DIR / "Google-api-key-scanner" / "keyhunt.py"

# JS from these domains is third-party / public library code — skip downloading entirely
CDN_DOMAINS = {
    # Generic CDNs
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "code.jquery.com", "ajax.googleapis.com", "ajax.aspnetcdn.com",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "code.angularjs.org",
    # Google / YouTube — own JS bundles embed placeholder AWS keys and internal API keys
    "www.google.com", "www.google.com.br",  # Google search XJS (embeds fake AWS key IDs)
    "maps.googleapis.com",                  # Google Maps JS API loader
    "accounts.google.com",                  # Google Sign-In widget
    "apis.google.com",                      # Google API Platform JS
    "www.youtube.com", "s.ytimg.com", "i.ytimg.com",
    "www.youtube-nocookie.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "www.googleadservices.com", "googleads.g.doubleclick.net",
    # Social / Tracking pixels
    "connect.facebook.net", "static.fbcdn.net",
    "analytics.tiktok.com", "static.tiktokanalytics.com",
    "snap.licdn.com", "platform.linkedin.com",
    "platform.twitter.com", "cdn.syndication.twimg.com",
    "ct.pinterest.com", "s.pinimg.com",
    "bat.bing.com", "sc-static.net",
    # Analytics
    "static.hotjar.com", "script.hotjar.com",
    "cdn.segment.com", "cdn.amplitude.com",
    "cdn.mxpnl.com", "cdn.heapanalytics.com",
    "js.intercomcdn.com", "widget.intercom.io",
    "js.driftt.com", "js.hs-scripts.com",
    # Payments
    "js.stripe.com", "checkout.stripe.com",
    "js.braintreegateway.com",
    # CRM / Widgets
    "static.zohocdn.com", "static.zdassets.com",
    "ekr.zdassets.com", "static.klaviyo.com",
    # Consent / Privacy
    "cdn.cookielaw.org", "cdn.onetrust.com",
    "cdn.privacy-mgmt.com", "cdn.cookiepro.com",
    # Email marketing CDNs (own Sentry DSNs etc.)
    "js.createsend1.com",                   # Campaign Monitor
}

# Domain suffix patterns — any subdomain of these is skipped (third-party SDKs/widgets)
CDN_SUFFIXES = (
    ".freshdesk.com",       # Freshdesk support widget (assets1-10.freshdesk.com)
    ".atlassian.com",       # Atlassian JS CDN, OneTrust wrapper
    ".atlassian.net",       # Atlassian cloud
    ".awsstatic.com",       # AWS marketing/console assets
    ".appcues.com",         # Appcues onboarding widget
    ".adyen.com",           # Adyen payment SDK
    ".gstatic.com",         # Google Static (Firebase SDK, fonts, etc.)
    ".squarespace.com",     # Squarespace
    ".queue-it.net",        # Queue-it waiting room widget
    ".stay22.com",          # Stay22 accommodation widget
    ".zendesk.com",         # Zendesk support widget
    ".zopim.com",           # Zendesk chat
    ".hubspot.com",         # HubSpot marketing
    ".hubspotusercontent.com",
    ".intercom.io",         # Intercom
    ".crisp.chat",          # Crisp chat
    ".tawk.to",             # Tawk.to chat
    ".olark.com",           # Olark chat
    ".pusher.com",          # Pusher (realtime SDK)
    ".sentry-cdn.com",      # Sentry browser SDK
    ".datadoghq.com",       # Datadog RUM
    ".nr-data.net",         # New Relic
    ".cookiebot.com",       # Cookie consent
    ".iubenda.com",         # Cookie policy
    ".termly.io",           # Terms/consent
    ".createsend1.com",     # Campaign Monitor email CDN
    ".t-assets.net",        # Atlassian Neo design system CDN
    ".atl-paas.net",        # Atlassian PaaS frontend CDN
    ".kwai.net",            # Kwai/Kuaishou pixel
)

# Raw IP regex — to skip JS downloaded from bare IPs on standard ports (CDN edge nodes)
import re as _re_mod
_RAW_IP_RE = _re_mod.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# ─── Secret Patterns ──────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # ── Cloud ────────────────────────────────────────────────────────────────
    {"id": "aws_access_key",    "sev": "critical",
     "re": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
     "label": "AWS Access Key ID"},
    {"id": "aws_secret_key",    "sev": "critical",
     "re": r"(?i)(?:aws.secret|secret.access.key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
     "label": "AWS Secret Access Key"},
    {"id": "google_api_key",    "sev": "high",
     "re": r"AIza[0-9A-Za-z\-_]{35}",
     "label": "Google API Key"},
    {"id": "google_oauth_id",   "sev": "medium",
     "re": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
     "label": "Google OAuth Client ID"},
    {"id": "gcp_service_acct",  "sev": "critical",
     "re": r'"type"\s*:\s*"service_account"',
     "label": "GCP Service Account JSON"},
    {"id": "azure_storage",     "sev": "critical",
     "re": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
     "label": "Azure Storage Connection String"},
    # ── Source Control ────────────────────────────────────────────────────────
    {"id": "github_pat_fine",   "sev": "critical",
     "re": r"github_pat_[0-9a-zA-Z_]{82}",
     "label": "GitHub Fine-grained PAT"},
    {"id": "github_pat_classic","sev": "critical",
     "re": r"ghp_[0-9a-zA-Z]{36}",
     "label": "GitHub Classic PAT"},
    {"id": "github_oauth",      "sev": "high",
     "re": r"gho_[0-9a-zA-Z]{36}",
     "label": "GitHub OAuth Token"},
    {"id": "github_actions",    "sev": "high",
     "re": r"ghs_[0-9a-zA-Z]{36}",
     "label": "GitHub Actions Token"},
    {"id": "gitlab_token",      "sev": "critical",
     "re": r"glpat-[0-9a-zA-Z_-]{20}",
     "label": "GitLab PAT"},
    # ── Payment ───────────────────────────────────────────────────────────────
    {"id": "stripe_sk_live",    "sev": "critical",
     "re": r"sk_live_[0-9a-zA-Z]{24,}",
     "label": "Stripe Secret Key (LIVE)"},
    {"id": "stripe_pk_live",    "sev": "medium",
     "re": r"pk_live_[0-9a-zA-Z]{24,}",
     "label": "Stripe Publishable Key (LIVE)"},
    {"id": "stripe_sk_test",    "sev": "low",
     "re": r"sk_test_[0-9a-zA-Z]{24,}",
     "label": "Stripe Secret Key (test)"},
    {"id": "square_secret",     "sev": "critical",
     "re": r"sq0csp-[0-9A-Za-z\-_]{43}",
     "label": "Square OAuth Secret"},
    {"id": "paypal_braintree",  "sev": "critical",
     "re": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
     "label": "PayPal/Braintree Access Token"},
    # ── Messaging ─────────────────────────────────────────────────────────────
    {"id": "slack_token",       "sev": "high",
     "re": r"xox[baprs]-(?:[0-9a-zA-Z]{10,48}-?)+",
     "label": "Slack Token"},
    {"id": "slack_webhook",     "sev": "high",
     "re": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,}",
     "label": "Slack Webhook"},
    {"id": "discord_webhook",   "sev": "medium",
     "re": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
     "label": "Discord Webhook"},
    {"id": "twilio_sid",        "sev": "high",
     "re": r"\bAC[a-zA-Z0-9]{32}\b",
     "label": "Twilio Account SID"},
    {"id": "sendgrid",          "sev": "high",
     "re": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
     "label": "SendGrid API Key"},
    {"id": "mailgun",           "sev": "high",
     "re": r"\bkey-[0-9a-zA-Z]{32}\b",
     "label": "Mailgun API Key"},
    {"id": "mailchimp_key",     "sev": "high",
     "re": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
     "label": "Mailchimp API Key"},
    # ── AI / LLM ──────────────────────────────────────────────────────────────
    {"id": "anthropic_key",     "sev": "critical",
     "re": r"sk-ant-(?:api03-)?[a-zA-Z0-9_-]{40,}",
     "label": "Anthropic API Key"},
    {"id": "openai_key",        "sev": "critical",
     "re": r"sk-(?:proj-)?[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
     "label": "OpenAI API Key"},
    {"id": "huggingface",       "sev": "high",
     "re": r"hf_[a-zA-Z0-9]{34,}",
     "label": "HuggingFace Token"},
    # ── Backend ───────────────────────────────────────────────────────────────
    {"id": "firebase_key",      "sev": "high",
     "re": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
     "label": "Firebase Server Key"},
    {"id": "supabase_key",      "sev": "high",
     "re": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}",
     "label": "Supabase Service Key (JWT)"},
    {"id": "heroku_api",        "sev": "high",
     "re": r"(?i)heroku.{0,30}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
     "label": "Heroku API Key"},
    {"id": "npm_token",         "sev": "high",
     "re": r"npm_[0-9a-zA-Z]{36}",
     "label": "npm Access Token"},
    {"id": "db_connstring",     "sev": "critical",
     "re": r"(?i)(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis(?:://)?|mssql)://[^\s'\"<>]{15,}",
     "label": "Database Connection String"},
    {"id": "jwt_token",         "sev": "medium",
     "re": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "label": "JSON Web Token"},
    {"id": "private_key",       "sev": "critical",
     "re": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?:----- BLOCK)? ?-----",
     "label": "Private Key (PEM)"},
    # ── SaaS ──────────────────────────────────────────────────────────────────
    {"id": "mapbox_token",      "sev": "medium",
     "re": r"pk\.eyJ1[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
     "label": "Mapbox Public Token"},
    {"id": "algolia_key",       "sev": "medium",
     "re": r"(?i)algolia.{0,20}['\"]([a-zA-Z0-9]{32})['\"]",
     "label": "Algolia API Key"},
    {"id": "cloudinary",        "sev": "medium",
     "re": r"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9]+",
     "label": "Cloudinary URL"},
    {"id": "datadog",           "sev": "high",
     "re": r"(?i)(?:datadog|dd_api).{0,20}['\"]([a-fA-F0-9]{32})['\"]",
     "label": "DataDog API Key"},
    {"id": "sentry_dsn",        "sev": "medium",
     # Matches both modern (o123.ingest[.us].sentry.io) and legacy (sentry.io/ID) DSN formats
     "re": r"https://[a-fA-F0-9]{32}@(?:o[0-9]+\.ingest(?:\.us)?\.sentry\.io|sentry\.io)/[0-9]+",
     "label": "Sentry DSN"},
    # ── Generic ───────────────────────────────────────────────────────────────
    {"id": "hardcoded_cred",    "sev": "medium",
     "re": r"""(?i)(?:password|passwd|pwd|secret|api.?key|auth.?token|access.?token|client.?secret)\s*[:=]\s*['"]([^'"]{8,100})['"]""",
     "group": 1,   # capture group 1 = actual credential value (not the key name)
     "label": "Hardcoded Credential"},
    {"id": "basic_auth_url",    "sev": "high",
     # Restrict user/pass chars to RFC 3986 userinfo safe chars — excludes {}"`,<> to avoid
     # matching JSON-LD structured data (@type, @context) that looks like user:pass@host
     "re": r"""https?://[^@\s{}"'`,<>]{3,60}:[^@\s{}"'`,<>]{3,60}@[a-zA-Z0-9._-]+""",
     "label": "URL with Embedded Credentials"},
    {"id": "internal_ip",       "sev": "low",
     # Strict octet validation: each octet 0-255 only (avoids matching version numbers like 10.3.51.5 or 10.881.26)
     "re": r"(?<![.\d])(?:"
           r"10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
           r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
           r"|192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
           r")(?![.\d])",
     "label": "Internal IP Address"},
    {"id": "aws_arn",           "sev": "low",
     "re": r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s'\"<>]{5,}",
     "label": "AWS ARN"},
    {"id": "s3_bucket",         "sev": "low",
     "re": r"(?:s3://|s3\.amazonaws\.com/)[a-zA-Z0-9._-]+",
     "label": "S3 Bucket Reference"},
    # Firebase Web Config block — detects full config objects (apiKey + at least 2 other fields)
    # The apiKey alone is already caught by google_api_key; this catches the complete config
    {"id": "firebase_config",  "sev": "medium",
     "re": r"""(?:firebaseConfig|firebaseOptions|firebase(?:_options)?)\s*[=:]\s*\{[^}]{0,300}"""
           r"""apiKey\s*:\s*["'](AIza[0-9A-Za-z\-_]{35})["'][^}]{0,300}(?:authDomain|projectId|storageBucket)""",
     "group": 1,
     "label": "Firebase Web Config (complete config block)"},
    # Adyen Client-side Encryption / JS SDK key — origin-restricted public key, LOW severity
    {"id": "adyen_client_key",  "sev": "low",
     "re": r"\blive_[A-Z0-9]{28,}\b",
     "label": "Adyen Client Key (public, origin-restricted)"},
    # ── DevOps / Infrastructure ───────────────────────────────────────────────
    {"id": "digitalocean_token", "sev": "critical",
     "re": r"dop_v1_[a-fA-F0-9]{64}",
     "label": "DigitalOcean Personal Access Token"},
    {"id": "postman_api_key",    "sev": "high",
     "re": r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
     "label": "Postman API Key"},
    {"id": "pypi_token",         "sev": "critical",
     "re": r"pypi-[A-Za-z0-9_\-]{50,}",
     "label": "PyPI Upload Token"},
    {"id": "hashicorp_vault",    "sev": "critical",
     "re": r"hvs\.[A-Za-z0-9_\-]{24,}",
     "label": "HashiCorp Vault Token"},
    {"id": "netlify_token",      "sev": "high",
     "re": r"(?i)netlify.{0,30}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
     "group": 1,
     "label": "Netlify Personal Access Token"},
    {"id": "cloudflare_api_key", "sev": "critical",
     "re": r"(?i)cloudflare.{0,30}['\"]([A-Za-z0-9_\-]{37})['\"]",
     "group": 1,
     "label": "Cloudflare API Key"},
    {"id": "twilio_auth_token",  "sev": "critical",
     # Auth token is different from SID — always 32 lowercase hex chars
     "re": r"(?i)twilio.{0,40}['\"]([a-f0-9]{32})['\"]",
     "group": 1,
     "label": "Twilio Auth Token"},
    {"id": "doppler_token",      "sev": "critical",
     "re": r"dp\.pt\.[A-Za-z0-9]{40,}",
     "label": "Doppler Service Token"},
    {"id": "terraform_cloud",    "sev": "critical",
     "re": r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}",
     "label": "Terraform Cloud Token"},
    {"id": "vercel_token",       "sev": "high",
     "re": r"(?i)vercel.{0,30}['\"]([A-Za-z0-9]{24})['\"]",
     "group": 1,
     "label": "Vercel API Token"},
    {"id": "linear_api_key",     "sev": "high",
     "re": r"lin_api_[A-Za-z0-9]{40}",
     "label": "Linear API Key"},
    # ── E-commerce ────────────────────────────────────────────────────────────
    {"id": "shopify_private_app",   "sev": "critical",
     "re": r"shppa_[0-9a-fA-F]{64}",
     "label": "Shopify Private App Password"},
    {"id": "shopify_access_token",  "sev": "critical",
     "re": r"shpat_[0-9a-fA-F]{64}",
     "label": "Shopify Admin API Access Token"},
    {"id": "shopify_shared_secret", "sev": "high",
     "re": r"shpss_[0-9a-fA-F]{64}",
     "label": "Shopify Shared Secret"},
    # ── Database-as-a-Service ─────────────────────────────────────────────────
    {"id": "planetscale_token",     "sev": "critical",
     "re": r"pscale_tkn_[A-Za-z0-9_]{32,}",
     "label": "PlanetScale Service Token"},
    # ── Database-as-a-Service (extended) ──────────────────────────────────────
    {"id": "neon_token",            "sev": "critical",
     "re": r"neon_[A-Za-z0-9_-]{40,}",
     "label": "Neon Database Access Token"},
    # ── Auth / Identity ────────────────────────────────────────────────────────
    {"id": "clerk_secret_key",      "sev": "critical",
     "re": r"sk_live_[A-Za-z0-9]{48,}",
     "label": "Clerk Secret Key (LIVE)"},
    {"id": "okta_ssws_token",       "sev": "critical",
     "re": r"\bSSWS [A-Za-z0-9_-]{40,}",
     "label": "Okta SSWS API Token"},
    # ── Email / Transactional ─────────────────────────────────────────────────
    {"id": "brevo_api_key",         "sev": "high",
     "re": r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9_]{1,25}",
     "label": "Brevo (Sendinblue) API Key"},
    {"id": "resend_api_key",        "sev": "high",
     "re": r"\bre_[A-Za-z0-9_-]{32,60}\b",
     "label": "Resend.com API Key"},
    # ── Package registry ──────────────────────────────────────────────────────
    {"id": "npmrc_token",           "sev": "high",
     "re": r"//registry\.npmjs\.org/:_authToken=(npm_[A-Za-z0-9]{36})",
     "group": 1,
     "label": "npmrc Auth Token"},
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Values that look like credential keys but are obviously placeholder/enum names
_CRED_PLACEHOLDER = re.compile(
    r"""^(?:password|passwd|pwd|secret|api.?key|auth.?token|access.?token|
            client.?secret|bearer.?token|private.?key|apikey|accesstoken|
            clientsecret|your.{0,3}(?:api.{0,3})?(?:key|secret|token)(?:[.\-_]\w+)*|
            \$\{[^}]+\}|<[^>]+>|%[A-Z_]+%|xxx+|changeme|placeholder|
            insert.{0,6}here|replace.{0,4}me|null|none|undefined|true|false|
            sample|demo|example|test|fake|dummy|
            strong[_\-]?password|weak[_\-]?password|medium[_\-]?password|
            very[_\-]?strong[_\-]?password|too[_\-]?weak|
            new[_\-]?password|old[_\-]?password|confirm[_\-]?password|
            current[_\-]?password|repeat[_\-]?password|
            wrong[_\-]?password|missing[_\-]?password|invalid[_\-]?password|
            expired[_\-]?password|requires[_\-]?recent[_\-]?login|
            user[_\-]?disabled|admin[_\-]?restricted[_\-]?operation|
            too[_\-]?many[_\-]?requests|network[_\-]?request[_\-]?failed|
            email[_\-]?already[_\-]?in[_\-]?use|user[_\-]?not[_\-]?found|
            # React prop-types internal sentinel
            SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED|
            # Firebase SDK documentation placeholders
            registration.{0,4}api.{0,4}key|
            # Password policy type enums (Amazon Cognito/Connect, Adyen, etc.)
            empty(?:string|cache|user|custom)?[_\-]?password|
            custom(?:string)?[_\-]?password|
            one[_\-]?time[_\-]?password|
            # Okta SDK string constants used as enum values, not actual credentials
            okta[_\-]?password|forgot[_\-]?password|reset[_\-]?password|
            change[_\-]?password|unlock[_\-]?account|
            # CSS/routing constants like default::reset-password (namespace::route)
            default::[a-zA-Z0-9\-_/]+|
            # Generic "XyzPassword" / "XyzToken" PascalCase enum names (no digits, no specials)
            (?:[A-Z][a-z]+){2,}(?:Password|Secret|Token|Key))$""",
    re.I | re.X,
)
# Multi-word strings composed only of letters/accented chars/spaces/punctuation = UI label
# Real credentials always have digits, symbols, or underscores mixed in
_CRED_LABEL_PHRASE = re.compile(r"^[A-Za-zÀ-ú]+(?:[\s.,!?]+[A-Za-zÀ-ú]+)+[.,!?]?$", re.I)

# Minified JS code fragments that fell after secret:/password: in minified bundles.
# Contain JS syntax chars that no real credential would have.
_CRED_CODE_FRAGMENT = re.compile(r"[(),;{}\[\]]")

# VAPID / Web Push public keys — ECDH P-256 uncompressed point (04 || x || y) in base64url
# The byte 0x04 encodes to "B" in base64url; P-256 keys are always ~87 base64url chars.
# These are INTENTIONALLY PUBLIC per RFC 8292 and must never be reported as secrets.
_VAPID_PUBLIC_KEY = re.compile(r"^B[A-Za-z0-9_-]{86,88}$")

# PostHog public project API key — browser-side, always public (like FingerprintJS Pro)
_POSTHOG_PUB_KEY = re.compile(r"^phc_[A-Za-z0-9_]{20,}$")

# ─── Key Validators ───────────────────────────────────────────────────────────

def _req_get(url, *, headers=None, auth=None, session=None, timeout=10):
    try:
        r = (session or requests).get(url, headers=headers, auth=auth,
                                       timeout=timeout, allow_redirects=True)
        return r.status_code, r.text[:500]
    except Exception as e:
        return None, str(e)

def _validate_github(value, session=None, **_):
    sc, body = _req_get("https://api.github.com/user",
                         headers={"Authorization": f"token {value}",
                                  "User-Agent": "secret-scan"},
                         session=session)
    if sc == 200:
        try:
            data = json.loads(body + "}")  # body is truncated
        except Exception:
            data = {}
        login = re.search(r'"login"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"GitHub user: {login.group(1) if login else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid/revoked token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_gitlab(value, session=None, **_):
    sc, body = _req_get("https://gitlab.com/api/v4/user",
                         headers={"PRIVATE-TOKEN": value}, session=session)
    if sc == 200:
        username = re.search(r'"username"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"GitLab user: {username.group(1) if username else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_stripe(value, session=None, **_):
    sc, body = _req_get("https://api.stripe.com/v1/charges?limit=1",
                         auth=(value, ""), session=session)
    if sc == 200:
        return {"valid": True,  "info": "Stripe key active — can list charges"}
    if sc == 401:
        return {"valid": False, "info": "Invalid key"}
    if sc == 403:
        return {"valid": True,  "info": "Stripe key valid but restricted scope"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_slack(value, session=None, **_):
    sc, body = _req_get(f"https://slack.com/api/auth.test?token={value}",
                         session=session)
    if sc == 200:
        ok_val = re.search(r'"ok"\s*:\s*(true|false)', body)
        if ok_val and ok_val.group(1) == "true":
            team = re.search(r'"team"\s*:\s*"([^"]+)"', body)
            user = re.search(r'"user"\s*:\s*"([^"]+)"', body)
            return {"valid": True,
                    "info": f"Slack team: {team.group(1) if team else '?'}, user: {user.group(1) if user else '?'}"}
        return {"valid": False, "info": "Token invalid"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_openai(value, session=None, **_):
    sc, body = _req_get("https://api.openai.com/v1/models",
                         headers={"Authorization": f"Bearer {value}"},
                         session=session)
    if sc == 200:
        return {"valid": True,  "info": "OpenAI key active"}
    if sc == 401:
        return {"valid": False, "info": "Invalid/revoked key"}
    if sc == 429:
        return {"valid": True,  "info": "Rate limited — key likely valid"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_anthropic(value, session=None, **_):
    # Send minimal valid request to check auth
    try:
        r = (session or requests).post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": value, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1,
                  "messages": [{"role": "user", "content": "hi"}]},
            timeout=15,
        )
        if r.status_code in (200, 400):  # 400 = bad request but auth OK
            return {"valid": True,  "info": "Anthropic key active"}
        if r.status_code == 401:
            return {"valid": False, "info": "Invalid key"}
        if r.status_code == 429:
            return {"valid": True,  "info": "Rate limited — key likely valid"}
        return {"valid": None, "info": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"valid": None, "info": str(e)}

def _validate_sendgrid(value, session=None, **_):
    sc, body = _req_get("https://api.sendgrid.com/v3/user/profile",
                         headers={"Authorization": f"Bearer {value}"},
                         session=session)
    if sc == 200:
        email = re.search(r'"email"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"SendGrid account: {email.group(1) if email else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid key"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_npm(value, session=None, **_):
    sc, body = _req_get("https://registry.npmjs.org/-/whoami",
                         headers={"Authorization": f"Bearer {value}"},
                         session=session)
    if sc == 200:
        user = re.search(r'"username"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"npm user: {user.group(1) if user else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_huggingface(value, session=None, **_):
    sc, body = _req_get("https://huggingface.co/api/whoami",
                         headers={"Authorization": f"Bearer {value}"},
                         session=session)
    if sc == 200:
        user = re.search(r'"name"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"HuggingFace user: {user.group(1) if user else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_discord_webhook(value, session=None, **_):
    sc, body = _req_get(value, session=session)
    if sc == 200:
        name = re.search(r'"name"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"Discord webhook: {name.group(1) if name else '?'}"}
    if sc in (401, 404):
        return {"valid": False, "info": "Webhook deleted or invalid"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_mapbox(value, session=None, **_):
    sc, body = _req_get(
        f"https://api.mapbox.com/tokens/v2?access_token={value}",
        session=session)
    if sc == 200:
        return {"valid": True,  "info": "Mapbox token valid"}
    if sc == 401:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_aws(value, session=None, **_):
    """
    Validate AWS Access Key ID using aws CLI (STS GetCallerIdentity).
    A 403 from STS means the key exists but the secret is wrong — key is REAL.
    A 401/InvalidClientTokenId means the key ID itself is invalid.
    """
    if not _which_local("aws"):
        return {"valid": None, "info": "aws CLI not found — cannot validate"}
    import subprocess as _sp
    # We intentionally use a wrong secret to trigger AuthFailure (403), not execute anything
    _os = __import__("os")
    env = {k: v for k, v in _os.environ.items()
           if k not in ("AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
                        "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE")}
    env.update({
        "AWS_ACCESS_KEY_ID": value,
        "AWS_SECRET_ACCESS_KEY": "INVALID_SECRET_FOR_PROBE_ONLY",
        "AWS_DEFAULT_REGION": "us-east-1",
    })
    try:
        p = _sp.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True, text=True, timeout=12, env=env,
        )
        if p.returncode == 0:
            data = __import__("json").loads(p.stdout)
            return {"valid": True,
                    "info": f"Account {data.get('Account','?')} / ARN {data.get('Arn','?')}"}
        combined = (p.stdout + p.stderr).lower()
        if "invalidclienttokenid" in combined or "notauthorized" in combined:
            return {"valid": False, "info": "Key ID does not exist"}
        if "signaturedoesnotmatch" in combined or "authfailure" in combined:
            # Key ID is valid, only the fake secret failed
            return {"valid": True,  "info": "Key ID valid (wrong secret used for probe)"}
        return {"valid": None, "info": f"Unexpected: {p.stderr[:120]}"}
    except Exception as e:
        return {"valid": None, "info": str(e)}

def _which_local(name):
    import subprocess as _sp
    return _sp.run(["which", name], capture_output=True).returncode == 0

def _validate_google_full(value, session=None, findings_dir=None, proxy_env=None, **_):
    """Quick Maps geocoding probe + full keyhunt.py 21-endpoint permission sweep."""
    # ── quick probe (1 request, fast) ────────────────────────────────────────
    sc, body = _req_get(
        f"https://maps.googleapis.com/maps/api/geocode/json"
        f"?address=1600+Amphitheatre+Parkway&key={value}",
        session=session)
    quick_valid = None
    quick_info  = f"HTTP {sc}"
    if sc == 200:
        try:
            status = json.loads(body).get("status", "")
        except Exception:
            status = ""
        if status == "OK":
            quick_valid, quick_info = True,  "Maps Geocoding active"
        elif status == "REQUEST_DENIED":
            quick_valid, quick_info = False, "Key exists — Geocoding disabled"
        elif status == "OVER_DAILY_LIMIT":
            quick_valid, quick_info = True,  "Quota exceeded — key likely valid"
        else:
            quick_valid, quick_info = None,  f"status={status}"

    # ── keyhunt.py: 21-endpoint permission map ────────────────────────────────
    if quick_valid is not False and _KEYHUNT_PATH.is_file():
        slug   = value[:8]
        kh_out = None
        if findings_dir:
            kh_dir = Path(findings_dir) / "google_keys"
            kh_dir.mkdir(parents=True, exist_ok=True)
            kh_out = kh_dir / f"keyhunt_{slug}.txt"

        cmd = ["python3", str(_KEYHUNT_PATH), "-k", value, "--poc", "-q"]
        if kh_out:
            cmd += ["-o", str(kh_out)]

        rc, stdout, stderr = run(cmd, timeout=120, env_extra=proxy_env)
        output = (stdout or "") + (stderr or "")
        if kh_out and not kh_out.exists():
            kh_out.write_text(output)

        vuln_lines = [l.strip() for l in output.splitlines()
                      if "[VULN]" in l or "[+]" in l]
        if vuln_lines:
            services = ", ".join(l.split("]", 1)[-1].strip() for l in vuln_lines[:6])
            return {
                "valid":    True,
                "info":     f"{len(vuln_lines)} enabled service(s): {services}",
                "keyhunt":  vuln_lines,
            }
        return {"valid": quick_valid, "info": quick_info + " | keyhunt: no enabled services"}

    return {"valid": quick_valid, "info": quick_info}

def _validate_mailchimp(value, session=None, **_):
    # Mailchimp DC is embedded in the key: key-usN → dc=usN
    m = re.search(r'-([a-z]{2}[0-9]+)$', value)
    if not m:
        return {"valid": None, "info": "Cannot extract DC from key format"}
    dc = m.group(1)
    sc, body = _req_get(
        f"https://{dc}.api.mailchimp.com/3.0/ping",
        headers={"Authorization": f"apikey {value}"},
        session=session)
    if sc == 200:
        return {"valid": True,  "info": "Mailchimp API key valid"}
    if sc == 401:
        return {"valid": False, "info": "Invalid key"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_twilio(value, session=None, **_):
    # Twilio auth token alone doesn't identify the account; paired with SID.
    # We do a lightweight check against the REST API using just the token as password
    # with a placeholder SID — 401 means token format OK, account not found is also informative.
    sc, body = _req_get(
        "https://api.twilio.com/2010-04-01/Accounts.json",
        auth=("ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", value),
        session=session)
    if sc == 200:
        return {"valid": True,  "info": "Twilio auth token active"}
    if sc == 401:
        return {"valid": False, "info": "Invalid auth token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_cloudflare(value, session=None, **_):
    sc, body = _req_get(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        headers={"Authorization": f"Bearer {value}"},
        session=session)
    if sc == 200:
        return {"valid": True,  "info": "Cloudflare token valid"}
    if sc == 403:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_digitalocean(value, session=None, **_):
    sc, body = _req_get(
        "https://api.digitalocean.com/v2/account",
        headers={"Authorization": f"Bearer {value}"},
        session=session)
    if sc == 200:
        email = re.search(r'"email"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"DO account: {email.group(1) if email else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid token"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_supabase(value, session=None, **_):
    try:
        import base64 as _b64, json as _j
        payload_b64 = value.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = _j.loads(_b64.b64decode(payload_b64).decode())
        iss = payload.get("iss", "")
        m = re.search(r'https://([a-z0-9]+)\.supabase\.co', iss)
        if m:
            ref = m.group(1)
            sc, body = _req_get(
                f"https://{ref}.supabase.co/rest/v1/",
                headers={"apikey": value, "Authorization": f"Bearer {value}"},
                session=session)
            if sc == 200:
                return {"valid": True,  "info": f"Supabase key valid (project: {ref})"}
            if sc == 401:
                return {"valid": False, "info": "Invalid key"}
    except Exception:
        pass
    return {"valid": None, "info": "Project URL not in JWT — check manually"}

def _validate_postman(value, session=None, **_):
    sc, body = _req_get(
        "https://api.getpostman.com/me",
        headers={"X-Api-Key": value},
        session=session)
    if sc == 200:
        user = re.search(r'"username"\s*:\s*"([^"]+)"', body)
        return {"valid": True,  "info": f"Postman user: {user.group(1) if user else '?'}"}
    if sc == 401:
        return {"valid": False, "info": "Invalid key"}
    return {"valid": None, "info": f"HTTP {sc}"}

def _validate_linear(value, session=None, **_):
    try:
        r = (session or requests).post(
            "https://api.linear.app/graphql",
            headers={"Authorization": value, "Content-Type": "application/json"},
            json={"query": "{ viewer { id name } }"},
            timeout=10,
        )
        if r.status_code == 200:
            name = ((r.json().get("data") or {}).get("viewer") or {}).get("name", "?")
            return {"valid": True,  "info": f"Linear user: {name}"}
        if r.status_code == 401:
            return {"valid": False, "info": "Invalid key"}
        return {"valid": None, "info": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"valid": None, "info": str(e)}

def _validate_pypi(value, session=None, **_):
    try:
        r = (session or requests).post(
            "https://upload.pypi.org/legacy/",
            auth=("__token__", value),
            data={"action": "file_upload"},
            timeout=10,
        )
        if r.status_code in (400, 422):   # auth accepted, bad/missing form data
            return {"valid": True,  "info": "PyPI token valid (auth accepted)"}
        if r.status_code == 403:
            return {"valid": False, "info": "Invalid or revoked token"}
        return {"valid": None, "info": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"valid": None, "info": str(e)}

def _validate_firebase_server_key(value, session=None, **_):
    try:
        r = (session or requests).post(
            "https://fcm.googleapis.com/fcm/send",
            headers={"Authorization": f"key={value}", "Content-Type": "application/json"},
            json={"to": "invalid_probe_token"},
            timeout=10,
        )
        if r.status_code == 400:   # auth OK, invalid target token
            return {"valid": True,  "info": "Firebase server key valid (FCM accepted)"}
        if r.status_code == 200:
            return {"valid": True,  "info": "Firebase server key valid"}
        if r.status_code == 401:
            return {"valid": False, "info": "Invalid server key"}
        return {"valid": None, "info": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"valid": None, "info": str(e)}

def _validate_shopify(value, session=None, **_):
    # Without the shop domain we cannot call the Admin API.
    # The token format alone is sufficient evidence; flag as unknown.
    return {"valid": None, "info": "Shop domain needed for live validation — report as found"}

# pattern_id → validator function
KEY_VALIDATORS = {
    "github_pat_fine":    _validate_github,
    "github_pat_classic": _validate_github,
    "github_oauth":       _validate_github,
    "github_actions":     _validate_github,
    "gitlab_token":       _validate_gitlab,
    "stripe_sk_live":     _validate_stripe,
    "stripe_sk_test":     _validate_stripe,
    "slack_token":        _validate_slack,
    "slack_webhook":      _validate_discord_webhook,
    "openai_key":         _validate_openai,
    "anthropic_key":      _validate_anthropic,
    "sendgrid":           _validate_sendgrid,
    "npm_token":          _validate_npm,
    "huggingface":        _validate_huggingface,
    "discord_webhook":    _validate_discord_webhook,
    "mapbox_token":       _validate_mapbox,
    "aws_access_key":        _validate_aws,
    "google_api_key":        _validate_google_full,
    "mailchimp_key":         _validate_mailchimp,
    "twilio_auth_token":     _validate_twilio,
    "cloudflare_api_key":    _validate_cloudflare,
    "digitalocean_token":    _validate_digitalocean,
    "supabase_key":          _validate_supabase,
    "postman_api_key":       _validate_postman,
    "linear_api_key":        _validate_linear,
    "pypi_token":            _validate_pypi,
    "firebase_key":          _validate_firebase_server_key,
    "shopify_private_app":   _validate_shopify,
    "shopify_access_token":  _validate_shopify,
}

# ─── Endpoint Patterns ────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r"""['"` ](/(?:api|v[0-9]+|admin|internal|debug|test|dev|beta|graphql|rest|service|backend|auth|oauth|token|login|logout|user|account|payment|webhook|upload|download|export|import|report|analytics|config|settings|manage|dashboard)[^\s'"`<>]{0,150})['"` ]""",
    r"""['"` ](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*/?(?:\?[^\s'"`<>]{0,100})?)['"` ]""",
    r"""['"` ](https?://(?!(?:www\.)?(?:google|facebook|twitter|cdn|fonts|jquery|bootstrap|cloudflare|unpkg|jsdelivr))[a-zA-Z0-9._-]{4,}/[^\s'"`<>]{5,100})['"` ]""",
    # Base URL / API base assignments
    r"""(?:baseURL|BASE_URL|api_url|API_URL|apiUrl|base_url|API_BASE|api_base|baseUrl)\s*[=:]\s*['"`]([^'"`\s]{8,120})['"`]""",
    r"""window\.(?:API_URL|BASE_URL|apiUrl|baseUrl)\s*=\s*['"`]([^'"`\s]{8,120})['"`]""",
    r"""['"](?:baseURL|base_url|apiUrl|api_url|endpoint|base_endpoint)['"]\s*:\s*['"`]([^'"`\s]{8,120})['"`]""",
]

COMMON_JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js", "/index.js", "/vendor.js",
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/assets/js/app.js", "/assets/main.js", "/dist/bundle.js",
    "/js/app.js", "/js/main.js", "/js/config.js", "/js/settings.js",
    "/js/env.js", "/env.js", "/config.js", "/settings.js",
    "/runtime.js", "/polyfills.js", "/chunk-vendors.js",
    # Next.js
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/webpack.js",
    # Service workers (hardcode URLs, API keys, push keys)
    "/sw.js", "/service-worker.js", "/firebase-messaging-sw.js",
    "/precache-manifest.js",
    # Nuxt / Vue
    "/_nuxt/app.js", "/_nuxt/runtime.js",
    # Vite / modern bundlers
    "/assets/index.js", "/dist/assets/index.js",
]

# ─── Colors / Logging ─────────────────────────────────────────────────────────

class C:
    R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
    B  = "\033[94m"; M  = "\033[95m"; CY = "\033[96m"
    BD = "\033[1m";  DM = "\033[2m";  RS = "\033[0m"

def _c(col, t):  return f"{col}{t}{C.RS}"
def bold(t):     return _c(C.BD, t)
def red(t):      return _c(C.R, t)
def green(t):    return _c(C.G, t)
def yellow(t):   return _c(C.Y, t)
def cyan(t):     return _c(C.CY, t)
def dim(t):      return _c(C.DM, t)

_lock = threading.Lock()
def info(m):  _lock and print(f"{C.CY}[*]{C.RS} {m}")
def ok(m):    _lock and print(f"{C.G}[+]{C.RS} {m}")
def warn(m):  _lock and print(f"{C.Y}[!]{C.RS} {m}")
def err(m):   print(f"{C.R}[-]{C.RS} {m}", file=sys.stderr)

def finding_line(sev, m):
    col = {"critical": C.R+C.BD, "high": C.R, "medium": C.Y, "low": C.DM}.get(sev, C.RS)
    with _lock: print(f"{col}[{sev[:4].upper()}]{C.RS} {m}")

def valid_line(label, info_str, valid):
    tag = green("VALID  ") if valid is True else (red("INVALID") if valid is False else yellow("UNKNOWN"))
    with _lock: print(f"  {tag}  {bold(label[:35])}  {dim(info_str)}")

def phase_header(n, title):
    with _lock:
        print(f"\n{C.BD}{C.B}{'─'*64}{C.RS}")
        print(f"{C.BD}{C.B}  [{n}] {title}{C.RS}")
        print(f"{C.BD}{C.B}{'─'*64}{C.RS}")

# ─── Utilities ────────────────────────────────────────────────────────────────

def which(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0

def run(cmd, *, timeout=120, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=env)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def count_lines(p):
    p = Path(p)
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text(errors="replace").splitlines() if ln.strip())

def mask(v, keep=6):
    return (v[:keep] + "…" + v[-keep:]) if len(v) > keep * 2 else v[:keep] + "***"

def url_to_filename(url):
    h    = hashlib.md5(url.encode()).hexdigest()[:10]
    base = Path(urlparse(url).path).name[:40] or "index.js"
    return f"{h}_{base}"

def _source_bashrc():
    import re as _r
    _pat = _r.compile(r"""^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\n]*)["']?\s*$""", _r.MULTILINE)
    for rc in [Path.home() / f for f in (".bashrc", ".bash_profile", ".profile", ".zshrc")]:
        if not rc.exists():
            continue
        try:
            for m in _pat.finditer(rc.read_text()):
                k, v = m.group(1), m.group(2).strip()
                if k and not os.environ.get(k):
                    os.environ[k] = v
        except Exception:
            pass

# ─── Phase 0 · Port Discovery ─────────────────────────────────────────────────

def _tcp_probe(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def _nmap_scan(ip, ports_str, timeout=90):
    """Returns list of open ports via nmap grepable output."""
    rc, out, _ = run(
        ["nmap", "-p", ports_str, "--open", "-T4",
         "--host-timeout", "60s", "-oG", "-", ip],
        timeout=timeout,
    )
    ports = []
    for line in out.splitlines():
        if "Ports:" in line:
            for part in line.split():
                if "/open/" in part:
                    try:
                        ports.append(int(part.split("/")[0]))
                    except ValueError:
                        pass
    return ports

def discover_ports(ips_file, threads=20):
    phase_header(0, "Port Discovery")
    if not ips_file or not Path(ips_file).exists():
        warn("No IPs file — skipping port scan")
        return []

    ips = [l.strip() for l in Path(ips_file).read_text().splitlines() if l.strip()]
    if not ips:
        warn("IPs file is empty")
        return []

    info(f"Scanning {len(ips)} IPs on {len(HTTP_PORTS)} ports "
         f"({'nmap' if which('nmap') else 'socket fallback'})...")

    services = []   # list of (scheme, host_or_ip, port)
    lock     = threading.Lock()

    def scan_ip(ip):
        if which("nmap"):
            open_ports = _nmap_scan(ip, NMAP_PORTS)
        else:
            open_ports = [p for p in HTTP_PORTS if _tcp_probe(ip, p)]
        for port in open_ports:
            scheme = "https" if port in HTTPS_PORTS else "http"
            url    = f"{scheme}://{ip}:{port}"
            with lock:
                services.append(url)
        if open_ports:
            with _lock:
                ok(f"  {ip}: {len(open_ports)} open  {open_ports}")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_ip, ip) for ip in ips]
        for f in as_completed(futures):
            try: f.result()
            except Exception: pass

    ok(f"Discovered services: {bold(str(len(services)))}")
    return services

# ─── Phase 1 · JS Discovery ───────────────────────────────────────────────────

def _playwright_crawl_host(url, pw_timeout, js_out, map_out, session, ua):
    """
    Open url in a headless browser, intercept ALL network responses.
    Collect JS URLs and .map URLs.
    Playwright sees lazy-loaded chunks, webpack splits, dynamic imports —
    things static scraping never finds.
    """
    js_found  = set()
    map_found = set()

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         args=["--no-sandbox", "--disable-setuid-sandbox"])
            ctx = browser.new_context(
                user_agent=ua,
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            page = ctx.new_page()

            def on_response(resp):
                url_r = resp.url
                ct    = resp.headers.get("content-type", "")
                p     = urlparse(url_r).path.lower().split("?")[0]
                if p.endswith((".js", ".mjs")) or "javascript" in ct:
                    js_found.add(url_r)
                    # Prefer explicit SourceMap header; fall back to speculative probe
                    sm_hdr = (resp.headers.get("sourcemap") or
                              resp.headers.get("x-sourcemap"))
                    if sm_hdr:
                        sm_url = sm_hdr if sm_hdr.startswith("http") else urljoin(url_r, sm_hdr)
                        map_found.add(sm_url)
                    else:
                        map_found.add(url_r.split("?")[0] + ".map")
                elif p.endswith(".map") or ("application/json" in ct and ".map" in p):
                    map_found.add(url_r)

            page.on("response", on_response)

            try:
                page.goto(url, wait_until="networkidle", timeout=pw_timeout)
                # Also grab <script src> that might not have fired a response event
                srcs = page.evaluate("""() =>
                    [...document.querySelectorAll('script[src]')].map(s => s.src)
                """)
                js_found.update(s for s in srcs if s)
            except Exception:
                pass

            browser.close()
    except Exception:
        pass

    with _lock:
        js_out.update(js_found)
        map_out.update(map_found)

def playwright_crawl(hosts, js_out, map_out, ua, pw_timeout=25000, threads=5):
    """Crawl live hosts with real browser. Updates js_out and map_out sets."""
    phase_header("1b", "Playwright JS Capture")
    info(f"Crawling {len(hosts)} hosts with headless Chromium...")

    crawled = [0]
    lock    = threading.Lock()

    def crawl_one(host):
        url = host if host.startswith("http") else f"https://{host}"
        before = len(js_out)
        _playwright_crawl_host(url, pw_timeout, js_out, map_out, None, ua)
        gained = len(js_out) - before
        with lock:
            crawled[0] += 1
            if gained:
                ok(f"  [{crawled[0]}/{len(hosts)}] {url[:50]}  +{gained} JS")
            else:
                info(f"  [{crawled[0]}/{len(hosts)}] {url[:50]}  (no new JS)")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(crawl_one, h) for h in hosts]
        for f in as_completed(futures):
            try: f.result()
            except Exception: pass

    ok(f"Playwright found: {bold(str(len(js_out)))} JS  |  {bold(str(len(map_out)))} source maps")

def discover_js_urls(urls_file, hosts_file, extra_hosts, session, ua, threads):
    phase_header(1, "JS Discovery")
    js_urls = set()

    if urls_file and Path(urls_file).exists():
        total = count_lines(urls_file)
        info(f"Filtering {total} collected URLs for JS...")
        for line in Path(urls_file).read_text(errors="replace").splitlines():
            u = line.strip()
            if not u:
                continue
            path = urlparse(u).path.lower()
            if path.endswith((".js", ".mjs")) or "/js/" in path:
                js_urls.add(u)
        ok(f"  all_urls.txt → {len(js_urls)} JS URLs")

    # Probe common paths on all hosts (live + port-scan discovered)
    all_hosts = set()
    if hosts_file and Path(hosts_file).exists():
        all_hosts.update(l.strip() for l in Path(hosts_file).read_text().splitlines() if l.strip())
    all_hosts.update(extra_hosts)

    if all_hosts and HAS_REQUESTS:
        info(f"Probing {len(all_hosts)} hosts × {len(COMMON_JS_PATHS)} paths...")
        found = [0]

        def probe(host):
            base = host if host.startswith("http") else f"https://{host}"
            for path in COMMON_JS_PATHS:
                url = base.rstrip("/") + path
                try:
                    r = session.head(url, timeout=(5, 8), allow_redirects=True)
                    if r.status_code == 200 and "javascript" in r.headers.get("content-type", "").lower():
                        with _lock:
                            js_urls.add(url)
                            found[0] += 1
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=threads) as ex:
            for f in as_completed([ex.submit(probe, h) for h in all_hosts]):
                try: f.result()
                except Exception: pass
        ok(f"  Common path probing → {found[0]} additional JS URLs")

    ok(f"Static JS total: {bold(str(len(js_urls)))}")
    return js_urls, list(all_hosts)

# ─── Phase 2 · Download ───────────────────────────────────────────────────────

def _download_one(url, outdir, session, ua, max_size=10_000_000):
    parsed = urlparse(url)
    netloc = parsed.netloc
    host   = netloc.split(":")[0]
    port   = int(netloc.split(":")[1]) if ":" in netloc else (443 if url.startswith("https") else 80)
    if netloc in CDN_DOMAINS or any(netloc.endswith(s) for s in CDN_SUFFIXES):
        return None, url   # third-party CDN / widget SDK — skip
    # Skip bare-IP URLs on standard ports: almost always CDN edge nodes serving the
    # same content as the named hostname. Non-standard ports are kept (hidden services).
    if _RAW_IP_RE.match(host) and port in (80, 443):
        return None, url
    dest = outdir / url_to_filename(url)
    if dest.exists():
        return dest, url
    try:
        # Check Content-Length before downloading to avoid wasting bandwidth on huge files
        head = session.head(url, timeout=(5, 10), headers={"User-Agent": ua},
                            allow_redirects=True)
        cl = head.headers.get("Content-Length") if head and head.status_code == 200 else None
        if cl and int(cl) > max_size:
            return None, url
        r = session.get(url, timeout=(10, 60), headers={"User-Agent": ua},
                        allow_redirects=True)
        if r.status_code != 200 or len(r.content) > max_size:
            return None, url
        ct = r.headers.get("content-type", "")
        if ct and "html" in ct and "javascript" not in ct:
            return None, url
        dest.write_bytes(r.content)
        return dest, url
    except Exception:
        return None, url

def download_all_js(js_urls, playwright_map_urls, outdir, session, ua, threads, max_size=10_000_000):
    phase_header(2, "JS Download")
    outdir.mkdir(parents=True, exist_ok=True)

    # Download Playwright-discovered source maps directly
    map_dir  = outdir.parent / "sourcemaps" / "playwright"
    map_dir.mkdir(parents=True, exist_ok=True)
    playwright_maps = {}   # dest → url

    if playwright_map_urls:
        info(f"Downloading {len(playwright_map_urls)} Playwright-discovered .map files...")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_download_one, u, map_dir, session, ua): u
                       for u in playwright_map_urls}
            for f in as_completed(futures):
                dest, url = f.result()
                if dest:
                    playwright_maps[dest] = url
        ok(f"  Source maps downloaded: {len(playwright_maps)}")

    if not js_urls:
        warn("No JS URLs to download")
        return {}, playwright_maps

    info(f"Downloading {len(js_urls)} JS files ({threads} threads, max {max_size//1_000_000}MB each)...")
    url_map = {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_download_one, u, outdir, session, ua, max_size): u
                   for u in js_urls}
        done = 0
        for f in as_completed(futures):
            dest, url = f.result()
            done += 1
            if dest:
                url_map[dest] = url
            if done % 50 == 0 or done == len(js_urls):
                info(f"  {done}/{len(js_urls)}  saved: {len(url_map)}")

    ok(f"Downloaded: {bold(str(len(url_map)))}  maps: {len(playwright_maps)}")
    return url_map, playwright_maps

# ─── Phase 3 · Source Maps (static JS only) ───────────────────────────────────

_MAP_RE   = re.compile(r"//# sourceMappingURL=(.+)$", re.MULTILINE)
_DATA_RE  = re.compile(r"^data:application/json;(?:charset=utf-8;)?base64,(.+)$", re.I)

def _fetch_map(map_url, source_url, session, ua):
    if _DATA_RE.match(map_url):
        return json.loads(base64.b64decode(_DATA_RE.match(map_url).group(1)).decode("utf-8", errors="replace"))
    if not map_url.startswith("http"):
        map_url = urljoin(source_url, map_url)
    try:
        r = session.get(map_url, timeout=(10, 30), headers={"User-Agent": ua})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def process_sourcemaps(url_map, playwright_map_files, sourcemaps_dir, session, ua):
    phase_header(3, "Source Map Analysis")
    sourcemaps_dir.mkdir(parents=True, exist_ok=True)

    extracted = []   # (path, origin_url)

    def _extract_map(data, subdir_name, origin_url):
        sources         = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        if not sources_content:
            return []
        out_dir = sourcemaps_dir / subdir_name
        out_dir.mkdir(exist_ok=True)
        out = []
        for i, (name, content) in enumerate(zip(sources, sources_content)):
            if not content:
                continue
            # Skip node_modules sources — these are npm library internals, never app code.
            # They account for the vast majority of sourcesContent[] entries and produce
            # thousands of files with zero bug-bounty value (React, lodash, webpack runtime…)
            name_str = str(name)
            if "node_modules" in name_str or "webpack/runtime" in name_str:
                continue
            safe = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(name).name)[:80] or f"src_{i}"
            dest = out_dir / f"{i:04d}_{safe}"
            dest.write_text(content, errors="replace")
            out.append((dest, origin_url))
        return out

    # Playwright-downloaded .map files
    for map_path, map_url in playwright_map_files.items():
        try:
            data = json.loads(map_path.read_text(errors="replace"))
            found = _extract_map(data, f"pw_{map_path.stem}", map_url)
            extracted.extend(found)
            if found:
                info(f"  ✓ (playwright) {map_path.name} → {len(found)} files")
        except Exception:
            pass

    # Static JS → look for sourceMappingURL comment
    for js_path, js_url in url_map.items():
        try:
            content = js_path.read_text(errors="replace")
        except Exception:
            continue
        m = _MAP_RE.search(content[-2000:])
        if not m:
            continue
        data = _fetch_map(m.group(1).strip(), js_url, session, ua)
        if not data:
            continue
        found = _extract_map(data, js_path.stem, js_url)
        extracted.extend(found)
        if found:
            info(f"  ✓ (static) {js_path.name} → {len(found)} files")

    ok(f"Source map files extracted: {bold(str(len(extracted)))}")
    return extracted

# ─── Phase 4 · Secret Scan ────────────────────────────────────────────────────

_COMPILED = [(p, re.compile(p["re"])) for p in SECRET_PATTERNS]

def _scan_text(text, label, sev_filter):
    out = []
    lines = text.splitlines()
    for pat, rx in _COMPILED:
        if pat["sev"] not in sev_filter:
            continue
        grp = pat.get("group", 0)
        for m in rx.finditer(text):
            try:
                value = m.group(grp)
            except IndexError:
                value = m.group(0)
            if not value:
                continue
            # Drop obvious placeholder/enum values for hardcoded_cred
            if pat["id"] == "hardcoded_cred":
                if _CRED_PLACEHOLDER.match(value.strip()):
                    continue
                if _CRED_LABEL_PHRASE.match(value.strip()):
                    continue
                # Minified JS code fragments — contain syntax chars no real credential has
                if _CRED_CODE_FRAGMENT.search(value):
                    continue
                # CSS selectors / glob patterns — start with . # [ *
                if re.match(r'^[.#\[*]', value.strip()):
                    continue
                # VAPID public keys are intentionally public (RFC 8292)
                if _VAPID_PUBLIC_KEY.match(value.strip()):
                    continue
                # PostHog public project API key — browser-side, always public
                if _POSTHOG_PUB_KEY.match(value.strip()):
                    continue
                # JS string concatenation expressions: value starts with + or contains ` + `
                v = value.strip()
                if v.startswith("+") or " + " in value:
                    continue
                # Pure PascalCase words with no digits or separators = React component / class name
                # e.g. LinkCard, FormSignup, ButtonPrimary — appear in Sentry module metadata
                if re.match(r'^(?:[A-Z][a-z]+){2,}$', v):
                    continue
                # snake_case or SCREAMING_SNAKE identifiers that name a credential field, not
                # a credential value — e.g. model_api_key, FORGOT_PASSWORD, okta_password.
                # Restrict to pure-alpha segments only: real credentials contain digits
                # (e.g. abc123, s3cr3t_x4) so only skip all-letter snake_case like
                # "forgot_password" or "OKTA_API_KEY" which are variable names, not values.
                if re.match(r'^[A-Za-z][A-Za-z]*(?:[_][A-Za-z]+)+$', v) and \
                   re.search(r'(?:password|passwd|secret|token|key|auth|cred|pwd)', v, re.I):
                    continue
                # 32-char hex strings adjacent to UA-parser / device-capability keys
                # (model, vendor, architecture, console, mobile) — device fingerprint maps, not API keys
                if re.match(r'^[a-f0-9]{32}$', v, re.I):
                    ctx_window = text[max(0, m.start()-150):m.end()+150]
                    if re.search(r'"(?:model|vendor|architecture|console|mobile|tablet|os)"', ctx_window):
                        continue
            # Supabase anon keys are intentionally public (browser-side). Decode JWT
            # payload to check role — only service_role keys are sensitive.
            if pat["id"] == "supabase_key":
                try:
                    import base64 as _b64, json as _json
                    payload_b64 = value.split(".")[1]
                    # add padding
                    payload_b64 += "=" * (-len(payload_b64) % 4)
                    payload = _json.loads(_b64.b64decode(payload_b64).decode())
                    if payload.get("role") == "anon":
                        continue  # anon key is public by design
                except Exception:
                    pass  # can't decode → keep the finding
            # PEM private key header inside a template literal is a format string, not a real key
            # e.g. `-----BEGIN RSA PRIVATE KEY-----\n${key}\n-----END...`
            if pat["id"] == "private_key":
                post = text[m.end():m.end() + 120]
                if "${" in post or "\\${" in post:
                    continue
            lnum = text[:m.start()].count("\n") + 1
            ctx  = lines[lnum - 1].strip()[:200] if lnum <= len(lines) else ""
            sev  = pat["sev"]
            # DB connection strings pointing to localhost/127.0.0.1/test are development
            # configs — still worth reporting but not critical (no real exposure)
            if pat["id"] == "db_connstring" and sev == "critical":
                if re.search(r':/+(?:[^@]+@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?/',
                             value, re.I):
                    sev = "high"
            entry = {
                "pattern":  pat["id"],
                "label":    pat["label"],
                "severity": sev,
                "value":    value,
                "line":     lnum,
                "context":  ctx,
                "source":   label,
                "validated": None,
            }
            # JWT: decode header + payload inline to expose alg and key claims
            if pat["id"] in ("jwt_token", "supabase_key"):
                try:
                    parts = value.split(".")
                    if len(parts) == 3:
                        def _b64d(s):
                            s += "=" * (-len(s) % 4)
                            return json.loads(base64.urlsafe_b64decode(s).decode())
                        hdr = _b64d(parts[0])
                        pay = _b64d(parts[1])
                        alg = hdr.get("alg", "?")
                        claims = {k: pay[k] for k in ("sub", "iss", "exp", "aud", "role", "email") if k in pay}
                        entry["jwt_info"] = {"alg": alg, "claims": claims}
                        entry["context"] = f"alg={alg} " + " ".join(f"{k}={v}" for k, v in list(claims.items())[:3])
                except Exception:
                    pass
            out.append(entry)
    return out

def _dedup(findings):
    """
    Two-pass dedup:
    1. Same (pattern, value) → keep first occurrence (same file vs .map duplicate)
    2. Same value matched by multiple patterns → keep only the highest-severity/most-specific one
       (e.g. google_api_key HIGH beats hardcoded_cred MEDI for the same AIzaSy... string)
    """
    # Pass 1: deduplicate same pattern+value
    seen1, stage1 = set(), []
    for f in findings:
        key = (f["pattern"], hashlib.md5(f["value"].encode()).hexdigest())
        if key not in seen1:
            seen1.add(key)
            stage1.append(f)

    # Pass 2: per unique value, keep only the finding with best (lowest) SEV_ORDER rank
    by_value = {}
    for f in stage1:
        vh   = hashlib.md5(f["value"].encode()).hexdigest()
        rank = SEV_ORDER.get(f["severity"], 9)
        prev = by_value.get(vh)
        if prev is None or rank < SEV_ORDER.get(prev["severity"], 9):
            by_value[vh] = f
        elif rank == SEV_ORDER.get(prev["severity"], 9):
            # Same severity — prefer more-specific pattern over generic hardcoded_cred
            if prev["pattern"] == "hardcoded_cred" and f["pattern"] != "hardcoded_cred":
                by_value[vh] = f

    # Preserve original order for readability
    seen2 = set()
    out   = []
    for f in stage1:
        vh = hashlib.md5(f["value"].encode()).hexdigest()
        if by_value.get(vh) is f and vh not in seen2:
            seen2.add(vh)
            out.append(f)
    return out

def scan_secrets(url_map, sourcemap_files, findings_dir, sev_filter, threads):
    phase_header(4, "Secret Detection")
    findings_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    all_files    = [(p, u) for p, u in url_map.items()] + sourcemap_files

    if not all_files:
        warn("No files to scan")
        return []

    info(f"Scanning {len(all_files)} files  ({len(SECRET_PATTERNS)} patterns)...")
    lock = threading.Lock()

    def scan_one(pu):
        path, url = pu
        try:
            text = path.read_text(errors="replace")
        except Exception:
            return
        hits = _scan_text(text, str(url), sev_filter)
        if hits:
            with lock:
                all_findings.extend(hits)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for f in as_completed([ex.submit(scan_one, pu) for pu in all_files]):
            try: f.result()
            except Exception: pass

    deduped = _dedup(all_findings)
    ok(f"Raw: {len(all_findings)}  deduped: {bold(str(len(deduped)))}")

    # Print findings AFTER dedup — avoids showing JWT+Supabase duplicates etc.
    for h in sorted(deduped, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        finding_line(h["severity"],
                     f"{h['label']}: {mask(h['value'])}  {dim(str(h['source'])[:55])}")

    # Write raw JSONL (without validation yet)
    out_jsonl = findings_dir / "secrets.jsonl"
    with out_jsonl.open("w") as fh:
        for f in sorted(deduped, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    # Write secrets_by_type.txt — grouped summary per pattern category
    by_type: dict = {}
    for f in deduped:
        by_type.setdefault(f["label"], []).append(f)
    type_lines = ["SECRET SCAN SUMMARY BY TYPE", "=" * 50, ""]
    for lbl in sorted(by_type, key=lambda l: SEV_ORDER.get(by_type[l][0]["severity"], 9)):
        entries_t = by_type[lbl]
        sev_t = entries_t[0]["severity"]
        type_lines.append(f"[{sev_t.upper():<8}] {lbl} ({len(entries_t)})")
        for fe in entries_t[:3]:
            masked = fe["value"][:4] + "…" + fe["value"][-4:] if len(fe["value"]) > 12 else fe["value"]
            src = str(fe["source"])[:50]
            type_lines.append(f"  {masked:<30}  ← {src}")
        if len(entries_t) > 3:
            type_lines.append(f"  … and {len(entries_t) - 3} more")
        type_lines.append("")
    (findings_dir / "secrets_by_type.txt").write_text("\n".join(type_lines))
    ok(f"  secrets_by_type.txt written ({len(by_type)} types)")

    # Optional extra scanners
    for tool, cmd_fn in [
        ("trufflehog", lambda d: ["trufflehog", "filesystem", d, "--json", "--no-update", "--only-verified"]),
        ("gitleaks",   lambda d: ["gitleaks", "detect", "--source", d, "--report-format", "json",
                                   "--report-path", str(findings_dir / "gitleaks.json"),
                                   "--no-git", "--exit-code", "0"]),
    ]:
        if which(tool) and url_map:
            js_dir = str(next(iter(url_map)).parent)
            info(f"Running {tool}...")
            run(cmd_fn(js_dir), timeout=300)

    return deduped

# ─── Phase 4b · Key Validation ────────────────────────────────────────────────

def validate_keys(findings, findings_dir, session, threads=8, proxy_env=None):
    phase_header("4b", "Key Validation")

    validatable = [f for f in findings if f["pattern"] in KEY_VALIDATORS]
    if not validatable:
        info("No validatable keys found")
        return findings

    info(f"Validating {len(validatable)} keys against live APIs...")
    if _KEYHUNT_PATH.is_file():
        info(f"keyhunt.py available → Google keys get 21-endpoint permission sweep")

    # Deduplicate by value (same key in multiple files = validate once)
    by_value = {}
    for f in validatable:
        by_value.setdefault(f["value"], f)

    results = {}
    lock = threading.Lock()

    def validate_one(value, finding):
        fn = KEY_VALIDATORS[finding["pattern"]]
        result = fn(value, session=session, findings_dir=findings_dir, proxy_env=proxy_env)
        with lock:
            results[value] = result
        valid_line(finding["label"], result.get("info", ""), result.get("valid"))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(validate_one, v, f) for v, f in by_value.items()]
        for fut in as_completed(futures):
            try: fut.result()
            except Exception: pass

    # Write back validation results
    for f in findings:
        if f["value"] in results:
            f["validated"] = results[f["value"]]

    # Overwrite JSONL with validation data
    out_jsonl = findings_dir / "secrets.jsonl"
    with out_jsonl.open("w") as fh:
        for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    confirmed = sum(1 for f in findings if (f.get("validated") or {}).get("valid") is True)
    ok(f"Confirmed active keys: {bold(red(str(confirmed)) if confirmed else str(confirmed))}")
    return findings

# ─── Phase 5 · Endpoints ──────────────────────────────────────────────────────

_EP_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in ENDPOINT_PATTERNS]
_NOISE = re.compile(
    # Third-party libraries / CDN
    r"googleapis|gstatic|jquery|bootstrap|cloudflare|unpkg|jsdelivr|"
    r"facebook|twitter|youtube|fonts\.googleapis|"
    # Static assets (not API paths)
    r"\.woff2?|\.ttf|\.eot|\.otf|\.svg|\.png|\.jpg|\.jpeg|\.gif|\.ico|\.webp|\.map|\.css|"
    # Documentation, specs, guides — not API endpoints
    r"schema\.org|w3\.org|ietf\.org|rfc-editor\.org|"
    r"momentjs\.com|angularjs\.org|reactjs\.org|redux\.js\.org|vuejs\.org|"
    r"npmjs\.|github\.com|gist\.github|gitlab\.com|bit\.ly|"
    r"developer\.mozilla|mdn\.io|"
    # App stores / social media / marketing — clearly not API endpoints
    r"itunes\.apple\.com|play\.google\.com|apps\.apple\.com|"
    r"instagram\.com|notion\.so|twitter\.com|t\.co/|fb\.me/|"
    r"squarespace\.com|mailchimp\.com|list-manage\.com|"
    # Support / issue trackers (href links in JS strings)
    r"freshdesk\.com/support|atlassian\.com|zendesk\.com/hc|"
    # Template expression — AngularJS {{ }}, Handlebars, Jinja
    r"\{\{|\}\}|"
    # URL fragments that are clearly docs, not API paths
    r"#/guide/|#/warning|#/docs|/issues/|/commit/|/blob/|/tree/|/releases/|/pull/|"
    r"/docs/#|/guides/#|/changelog|/license|/readme|"
    # Specific non-API patterns
    r"prerender\.io/recache|vjs\.zencdn\.net|",
    re.I,
)

# ── Method inference ──────────────────────────────────────────────────────────
_METHOD_EXPLICIT = re.compile(
    r"""method\s*[:=]\s*['"]?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]?""", re.I
)
_METHOD_AXIOS = re.compile(
    r"""axios\.(get|post|put|delete|patch|head)\s*\(""", re.I
)
_METHOD_FETCH = re.compile(
    r"""(?:fetch|http|request|superagent|got|ky|wretch)\.(get|post|put|delete|patch)\s*\(""", re.I
)
_METHOD_ROUTER = re.compile(
    r"""(?:router|app|server|express)\.(get|post|put|delete|patch|all)\s*\(""", re.I
)

# Path-based heuristics (fallback when no explicit method found)
_POST_PATH_HINTS = re.compile(
    r"/(?:create|submit|register|enroll|authorize|login|signin|signup|upload|send|"
    r"broadcast|cancel|checkout|pay|reset|revoke|refresh|generate|initiat|add|set|update)(?:/|$)",
    re.I,
)
_GET_PATH_HINTS  = re.compile(
    r"(?:[?&]|/(?:list|search|status|details|balance|participants|options|types|info|get|fetch|query)(?:/|$))",
    re.I,
)

def _infer_method(ctx_before, path):
    """Infer HTTP method from context preceding the endpoint URL."""
    for rx in (_METHOD_EXPLICIT, _METHOD_AXIOS, _METHOD_FETCH, _METHOD_ROUTER):
        m = None
        for m in rx.finditer(ctx_before):
            pass   # keep last match (closest to the endpoint)
        if m:
            return m.group(1).upper()
    # Path heuristics
    if _POST_PATH_HINTS.search(path):
        return "POST?"
    if _GET_PATH_HINTS.search(path):
        return "GET?"
    return "?"

def extract_endpoints(url_map, sourcemap_files, findings_dir):
    phase_header(5, "Endpoint Extraction")

    # Build file → source_url mapping (url_map values are already URLs; sourcemap tuples carry URL)
    all_pairs = list(url_map.items()) + sourcemap_files  # (Path, url)
    info(f"Extracting endpoints from {len(all_pairs)} files...")

    # ep_path → {method, domains, count}
    ep_map = {}

    for fpath, source_url in all_pairs:
        src_netloc = urlparse(str(source_url)).netloc or "unknown"
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue

        for rx in _EP_COMPILED:
            for m in rx.finditer(text):
                ep = m.group(1).strip().rstrip("/")
                if not ep or _NOISE.search(ep) or len(ep) < 5:
                    continue

                # For full URLs: group by the endpoint's own hostname, not the JS source.
                # Relative paths stay attributed to the JS source domain.
                if ep.startswith("http://") or ep.startswith("https://"):
                    domain = urlparse(ep).netloc or src_netloc
                else:
                    domain = src_netloc
                    # Skip raw-IP source domains on standard ports — same as named host,
                    # already covered; they just create duplicate groups in the report.
                    host = src_netloc.split(":")[0]
                    port_str = src_netloc.split(":")[1] if ":" in src_netloc else ""
                    port = int(port_str) if port_str.isdigit() else 80
                    if _RAW_IP_RE.match(host) and port in (80, 443):
                        continue

                # Grab up to 250 chars before the match for method inference
                ctx_before = text[max(0, m.start() - 250):m.start()]
                method = _infer_method(ctx_before, ep)

                if ep not in ep_map:
                    ep_map[ep] = {"path": ep, "method": method, "domains": set(), "count": 0}
                else:
                    # Upgrade uncertain method if we find a definite one
                    cur = ep_map[ep]["method"]
                    if "?" in cur and "?" not in method:
                        ep_map[ep]["method"] = method
                ep_map[ep]["domains"].add(domain)
                ep_map[ep]["count"] += 1

    # Sort: API paths first, then by domain, then alphabetically
    def _sort_key(e):
        is_api = 0 if re.search(r"/api/|/v[0-9]+/|/graphql|/admin", e["path"], re.I) else 1
        return (is_api, sorted(e["domains"])[0], e["path"])

    entries = sorted(ep_map.values(), key=_sort_key)

    # ── Write endpoints.txt (human-readable, grouped by domain) ──────────────
    # For full-URL endpoints the domain IS the path's own host — appears once.
    # For relative paths, list under all source domains that served JS containing them,
    # but de-duplicate: pick the single most meaningful domain (named host over raw IP).
    by_domain = {}
    for e in entries:
        if e["path"].startswith("http://") or e["path"].startswith("https://"):
            # Full URL: already grouped by the URL's own host in ep_map["domains"]
            for d in sorted(e["domains"]):
                by_domain.setdefault(d, []).append(e)
        else:
            # Relative path: pick one representative source domain.
            # Prefer named hostnames (contain a dot and no digit-only segments) over raw IPs.
            domains = sorted(e["domains"])
            named = [d for d in domains if not _RAW_IP_RE.match(d.split(":")[0])]
            rep = named[0] if named else domains[0]
            by_domain.setdefault(rep, []).append(e)

    txt_lines = []
    for domain in sorted(by_domain):
        eps = by_domain[domain]
        txt_lines.append(f"# {domain}  ({len(eps)} endpoints)")
        txt_lines.append("")
        for e in sorted(eps, key=lambda x: x["path"]):
            method = e["method"].ljust(7)
            txt_lines.append(f"  {method}  {e['path']}")
        txt_lines.append("")

    out_txt = findings_dir / "endpoints.txt"
    out_txt.write_text("\n".join(txt_lines))

    # ── Write endpoints.json (machine-readable) ───────────────────────────────
    out_json = findings_dir / "endpoints.json"
    serial = [
        {"path": e["path"], "method": e["method"],
         "domains": sorted(e["domains"]), "occurrences": e["count"]}
        for e in entries
    ]
    out_json.write_text(json.dumps(serial, indent=2, ensure_ascii=False))

    # ── Terminal summary ──────────────────────────────────────────────────────
    api_count   = sum(1 for e in entries if re.search(r"/api/|/v[0-9]+/|/graphql|/admin", e["path"], re.I))
    other_count = len(entries) - api_count
    ok(f"Endpoints: {bold(str(len(entries)))}  (API: {api_count}, other: {other_count})")
    ok(f"  Domains: {', '.join(sorted(by_domain)[:6])}{'…' if len(by_domain) > 6 else ''}")
    ok(f"  Files: {out_txt.name}, {out_json.name}")

    # Print all to terminal grouped by domain
    for domain in sorted(by_domain):
        eps = by_domain[domain]
        with _lock:
            print(f"\n  {cyan(domain)}  {dim(str(len(eps)) + ' paths')}")
            for e in sorted(eps, key=lambda x: x["path"]):
                col = green if "?" not in e["method"] else dim
                print(f"    {col(e['method'].ljust(7))}  {e['path']}")

    return entries

# ─── Phase 5b · Sensitive File Probing ───────────────────────────────────────

SENSITIVE_PATHS = [
    # Environment files
    "/.env", "/.env.local", "/.env.production", "/.env.prod",
    "/.env.staging", "/.env.development", "/.env.dev",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.example",
    "/.env.test", "/.env.ci",
    # Config files that are sometimes accidentally exposed
    "/config.json", "/config.js", "/config.yaml", "/config.yml",
    "/settings.json", "/settings.py", "/app.config.js",
    "/application.properties", "/application.yml",
    # Build artifacts that leak env vars
    "/.env.build", "/build/.env", "/dist/.env",
    # Docker
    "/docker-compose.yml", "/docker-compose.yaml",
    "/docker-compose.override.yml",
    # Kubernetes secrets sometimes accidentally committed and served
    "/.kube/config", "/kubeconfig",
    # Common CI secrets
    "/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml",
    # Database / backup
    "/dump.sql", "/backup.sql", "/db.sql",
    "/database.sql", "/.htpasswd",
    # VCS
    "/.git/config", "/.svn/entries",
    # PHP/Laravel/Symfony
    "/.env.php", "/laravel/.env", "/.symfony.env",
    "/storage/logs/laravel.log",
    "/_profiler/",
    "/telescope",
    # Rails
    "/config/database.yml", "/config/secrets.yml",
    "/config/credentials.yml.enc",
    # Spring Boot actuators (frequent in Java)
    "/actuator/env", "/actuator/heapdump", "/actuator/configprops",
    "/actuator/mappings",
    # Server-level exposures
    "/.htaccess", "/web.config", "/server-status",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    # PHP debug pages
    "/phpinfo.php", "/info.php", "/test.php",
    # Cloud credentials
    "/.npmrc", "/.aws/credentials", "/.aws/config",
    "/.pip/pip.conf", "/.pypirc",
    # Shell history / SSH (misconfigured web roots)
    "/.bash_history", "/.ssh/id_rsa", "/.ssh/id_ecdsa",
    # Node / package metadata
    "/package.json", "/.nvmrc",
]

def probe_sensitive_files(hosts_file, extra_hosts, session, ua, findings_dir, threads, sev_filter):
    """
    Phase 5b: Probe live hosts for exposed .env and sensitive config files.
    Scan discovered content with the secret patterns.
    """
    phase_header("5b", "Sensitive File Probing (.env / config)")

    all_hosts = set()
    if hosts_file and Path(hosts_file).exists():
        all_hosts.update(l.strip() for l in Path(hosts_file).read_text().splitlines() if l.strip())
    all_hosts.update(h for h in extra_hosts if h)

    if not all_hosts:
        warn("No hosts — skipping sensitive file probe")
        return []

    info(f"Probing {len(all_hosts)} hosts × {len(SENSITIVE_PATHS)} paths...")

    new_findings: list = []
    hits_found   = [0]
    lock         = threading.Lock()

    def probe_host(host):
        base_url = host if host.startswith("http") else f"https://{host}"
        for path in SENSITIVE_PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = session.get(url, timeout=(5, 10),
                                headers={"User-Agent": ua},
                                allow_redirects=True)
                if r.status_code != 200 or len(r.content) > 1_000_000:
                    continue
                ct = r.headers.get("content-type", "")
                snippet = r.text[:300].lower().strip()
                # Skip HTML pages: login redirects, 404 pages, etc.
                if "text/html" in ct or snippet.startswith(("<!doctype", "<html", "<head")):
                    continue
                # Scan content for secrets
                hits = _scan_text(r.text, f"{url} [probe]", sev_filter)
                if hits:
                    with lock:
                        new_findings.extend(hits)
                        hits_found[0] += len(hits)
                        for h in hits:
                            finding_line(h["severity"],
                                         f"{h['label']}: {mask(h['value'])}  "
                                         f"{dim(path + ' @ ' + host[:40])}")
                else:
                    # File exists but no secrets — still worth noting
                    with lock:
                        warn(f"  Exposed (no secrets): {url}")
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(probe_host, h) for h in all_hosts]
        for f in as_completed(futs):
            try: f.result()
            except Exception: pass

    if new_findings:
        ok(f"Sensitive file probe: {bold(str(hits_found[0]))} new secret hits")
        # Persist to the same secrets.jsonl
        out_jsonl = findings_dir / "secrets.jsonl"
        existing  = []
        if out_jsonl.exists():
            for line in out_jsonl.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        existing.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        combined = existing + new_findings
        with out_jsonl.open("w") as fh:
            for f in sorted(combined, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    else:
        info("Sensitive file probe: no secrets found in exposed files")

    return new_findings

# ─── Report ───────────────────────────────────────────────────────────────────

def write_report(base, findings, endpoints, url_map, sourcemap_files, extra_services, target):
    path = base / "report.md"
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    confirmed = [f for f in findings if (f.get("validated") or {}).get("valid") is True]

    lines = [
        f"# Secret Scan Report — {target}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**JS files:** {len(url_map)}  |  **Source map files:** {len(sourcemap_files)}",
        f"**New services (port scan):** {len(extra_services)}",
        "",
        "## Summary",
        "",
        "| Severity | Count | Confirmed Active |",
        "|----------|-------|-----------------|",
    ]
    for sev in ("critical", "high", "medium", "low"):
        n = counts.get(sev, 0)
        c = sum(1 for f in confirmed if f["severity"] == sev)
        lines.append(f"| {sev.capitalize()} | {n} | {c} |")

    if extra_services:
        lines += ["", "## Discovered Services (Port Scan)", ""]
        for s in extra_services:
            lines.append(f"- `{s}`")

    if confirmed:
        lines += ["", "## ⚠ Confirmed Active Keys", ""]
        for f in confirmed:
            v = f.get("validated", {})
            lines += [
                f"**{f['label']}** ({f['severity']})",
                f"- Value: `{mask(f['value'])}`",
                f"- Info: {v.get('info', '')}",
                f"- Source: {f['source']} (line {f['line']})",
                "",
            ]

    if findings:
        lines += ["## All Secrets", ""]
        for sev in ("critical", "high", "medium", "low"):
            sf = [f for f in findings if f["severity"] == sev]
            if not sf:
                continue
            lines.append(f"### {sev.capitalize()} ({len(sf)})")
            lines.append("")
            for f in sf:
                v = f.get("validated") or {}
                status = f" ✓ ACTIVE — {v.get('info')}" if v.get("valid") is True else (
                         " ✗ invalid" if v.get("valid") is False else "")
                lines += [
                    f"**{f['label']}**{status}",
                    f"- `{mask(f['value'])}`  ← {f['source']} line {f['line']}",
                    f"- Context: `{f['context'][:120]}`",
                    "",
                ]

    # Secrets grouped by source host
    if findings:
        by_src: dict = {}
        for f in findings:
            src = str(f.get("source", "unknown"))
            try:
                netloc = urlparse(src).netloc
                h = netloc if netloc else src.split("/")[0]
            except Exception:
                h = src[:40]
            by_src.setdefault(h, []).append(f)
        if len(by_src) > 1:
            lines += ["", "## Secrets by Source Host", ""]
            for h_src in sorted(by_src):
                hf = by_src[h_src]
                lines.append(f"### {h_src} ({len(hf)})")
                for f in sorted(hf, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
                    v = f.get("validated") or {}
                    status = " ✓" if v.get("valid") is True else ""
                    lines.append(f"- [{f['severity'].upper()}] {f['label']}{status}: `{mask(f['value'])}`")
                lines.append("")

    if endpoints:
        # Group by domain for report
        by_domain = {}
        for e in endpoints:
            for d in sorted(e["domains"]):
                by_domain.setdefault(d, []).append(e)
        lines += ["## Endpoints", ""]
        for domain in sorted(by_domain):
            eps = sorted(by_domain[domain], key=lambda x: x["path"])
            lines.append(f"### {domain} ({len(eps)})")
            lines.append("")
            lines.append("| Method | Path |")
            lines.append("|--------|------|")
            for e in eps:
                lines.append(f"| `{e['method']}` | `{e['path']}` |")
            lines.append("")

    path.write_text("\n".join(lines) + "\n")
    ok(f"Report → {path}")

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""{C.M}{C.BD}
  ███████╗███████╗ ██████╗██████╗ ███████╗████████╗
  ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ███████╗█████╗  ██║     ██████╔╝█████╗     ██║
  ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║
  ███████║███████╗╚██████╗██║  ██║███████╗   ██║
  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝{C.RS}
{C.DM}  JS secret & endpoint scanner  v2.1  (port-scan · playwright · key-validation · env-probe){C.RS}
"""

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="secret-scan.py",
        description="JS secret & endpoint scanner with port discovery, Playwright, and key validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
input:
  --recon-dir   auto-loads urls/all_urls.txt + httpx/httpx_live.txt + ips/unique_ips.txt
  --urls-file   URL list (overrides recon-dir urls)
  --hosts-file  live hosts (overrides recon-dir hosts)
  --ips-file    IPs for port scan (overrides recon-dir ips)
  --js-dir      skip download, scan pre-existing JS files

examples:
  python3 secret-scan.py --recon-dir recon_output/target_20260922/
  python3 secret-scan.py --urls urls.txt --hosts hosts.txt --ips ips.txt
  python3 secret-scan.py --js-dir ./js/ --severity critical,high --no-validate
  python3 secret-scan.py --recon-dir . --no-playwright --no-port-scan --tor
  python3 secret-scan.py --recon-dir . --playwright-timeout 45

playwright install:
  pip install playwright && playwright install chromium
        """,
    )
    p.add_argument("--recon-dir",  help="recon.py output dir (auto-detects all inputs)")
    p.add_argument("--urls-file")
    p.add_argument("--hosts-file")
    p.add_argument("--ips-file",   help="IPs file for port scan")
    p.add_argument("--js-dir",     help="Pre-downloaded JS directory")
    p.add_argument("-o", "--output", default="./secret_output")
    p.add_argument("--target",     default="")
    p.add_argument("--severity",   default="critical,high,medium,low")
    p.add_argument("--threads",    type=int, default=15)
    p.add_argument("--user-agent",
                   default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
    p.add_argument("--tor",           action="store_true")
    p.add_argument("--no-port-scan",  action="store_true")
    p.add_argument("--no-playwright", action="store_true")
    p.add_argument("--no-sourcemaps", action="store_true")
    p.add_argument("--no-validate",   action="store_true",
                   help="Skip live API key validation")
    p.add_argument("--no-endpoints",  action="store_true")
    p.add_argument("--no-env-probe",  action="store_true",
                   help="Skip .env / sensitive config file probing (Phase 5b)")
    p.add_argument("--playwright-timeout", type=int, default=25,
                   help="Playwright page timeout in seconds (default: 25)")
    p.add_argument("--max-js-size", type=int, default=10_000_000, metavar="BYTES",
                   help="Max JS file size to download in bytes (default: 10MB)")
    return p

def main():
    _source_bashrc()
    args = build_parser().parse_args()
    print(BANNER)

    if not HAS_REQUESTS:
        err("pip install requests")
        sys.exit(1)

    sev_filter = set(s.strip().lower() for s in args.severity.split(","))

    # ── HTTP session ──────────────────────────────────────────────────────────
    proxy_env = None
    session = requests.Session()
    if args.tor:
        tor = "socks5h://127.0.0.1:9050"
        session.proxies = {"http": tor, "https": tor}
        proxy_env = {"HTTP_PROXY": tor, "HTTPS_PROXY": tor,
                     "http_proxy": tor, "https_proxy": tor}
        info(f"TOR proxy: {tor}")
    session.headers["User-Agent"] = args.user_agent
    session.verify = False  # many targets have self-signed certs
    import urllib3; urllib3.disable_warnings()

    # ── Resolve inputs ────────────────────────────────────────────────────────
    urls_file = hosts_file = ips_file = None
    target = args.target

    if args.recon_dir:
        rd = Path(args.recon_dir)
        for attr, rel in [("urls_file",  "urls/all_urls.txt"),
                          ("hosts_file", "httpx/httpx_live.txt"),
                          ("ips_file",   "ips/unique_ips.txt")]:
            p = rd / rel
            if p.exists():
                if attr == "urls_file":  urls_file  = p
                if attr == "hosts_file": hosts_file = p
                if attr == "ips_file":   ips_file   = p
                info(f"Auto-detected {rel} ({count_lines(p)} lines)")
        if not target:
            target = rd.name

    if args.urls_file:  urls_file  = Path(args.urls_file)
    if args.hosts_file: hosts_file = Path(args.hosts_file)
    if args.ips_file:   ips_file   = Path(args.ips_file)
    if not target: target = "scan"

    # ── Output dir ────────────────────────────────────────────────────────────
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(args.output) / f"{target}_{ts}"
    base.mkdir(parents=True, exist_ok=True)

    info(f"Target   : {bold(target)}")
    info(f"Output   : {bold(str(base))}")
    info(f"Playwright: {'yes' if HAS_PLAYWRIGHT and not args.no_playwright else 'no'}")
    info(f"Port scan : {'yes' if not args.no_port_scan else 'no'}")

    # ── Phase 0: Port Scan ────────────────────────────────────────────────────
    extra_services = []
    if not args.no_port_scan:
        extra_services = discover_ports(ips_file, threads=args.threads)
    else:
        warn("Port scan skipped (--no-port-scan)")

    # ── Phase 1: JS Discovery ─────────────────────────────────────────────────
    url_map       = {}
    sourcemap_files = []
    playwright_map_urls = set()

    if args.js_dir:
        js_dir = Path(args.js_dir)
        url_map = {p: str(p) for p in js_dir.glob("*.js")}
        ok(f"Pre-downloaded JS: {len(url_map)} files")
    else:
        js_urls, all_hosts = discover_js_urls(
            urls_file, hosts_file, extra_services,
            session, args.user_agent, args.threads,
        )
        playwright_js_urls = set()

        if HAS_PLAYWRIGHT and not args.no_playwright and all_hosts:
            playwright_crawl(
                all_hosts, playwright_js_urls, playwright_map_urls,
                args.user_agent,
                pw_timeout=args.playwright_timeout * 1000,
                threads=min(5, args.threads),
            )
            js_urls |= playwright_js_urls
        elif not HAS_PLAYWRIGHT and not args.no_playwright:
            warn("Playwright not installed — skipping browser crawl")
            warn("Install: pip install playwright && playwright install chromium")

        # ── Phase 2: Download ─────────────────────────────────────────────────
        url_map, playwright_map_files = download_all_js(
            js_urls, playwright_map_urls,
            base / "js", session, args.user_agent, args.threads,
            max_size=args.max_js_size,
        )

        # ── Phase 3: Source Maps ──────────────────────────────────────────────
        if not args.no_sourcemaps:
            sourcemap_files = process_sourcemaps(
                url_map, playwright_map_files,
                base / "sourcemaps", session, args.user_agent,
            )
        else:
            warn("Source maps skipped (--no-sourcemaps)")

    # ── Phase 4: Secret Scan ──────────────────────────────────────────────────
    findings_dir = base / "findings"
    findings = scan_secrets(
        url_map, sourcemap_files, findings_dir, sev_filter, args.threads,
    )

    # ── Phase 4b: Key Validation ──────────────────────────────────────────────
    if not args.no_validate and findings:
        findings = validate_keys(findings, findings_dir, session, threads=8, proxy_env=proxy_env)
    elif args.no_validate:
        warn("Key validation skipped (--no-validate)")

    # ── Phase 5b: Sensitive file probing (.env / config) ─────────────────────
    env_findings = []
    if not args.no_env_probe:
        env_findings = probe_sensitive_files(
            hosts_file, extra_services,
            session, args.user_agent,
            findings_dir, args.threads, sev_filter,
        )
        if env_findings:
            if not args.no_validate:
                env_findings = validate_keys(
                    env_findings, findings_dir, session, threads=8, proxy_env=proxy_env)
            findings = _dedup(findings + env_findings)
    else:
        warn("Sensitive file probe skipped (--no-env-probe)")

    # ── Phase 5: Endpoints ────────────────────────────────────────────────────
    endpoints = []
    if not args.no_endpoints:
        endpoints = extract_endpoints(url_map, sourcemap_files, findings_dir)

    # ── Report ────────────────────────────────────────────────────────────────
    write_report(base, findings, endpoints, url_map, sourcemap_files,
                 extra_services, target)

    # ── Summary ───────────────────────────────────────────────────────────────
    phase_header("✓", "Complete")
    print(f"\n{bold('Output:')} {base}\n")

    counts    = {}
    confirmed = 0
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        if (f.get("validated") or {}).get("valid") is True:
            confirmed += 1

    for sev in ("critical", "high", "medium", "low"):
        n = counts.get(sev, 0)
        col = red if sev in ("critical", "high") else yellow
        tag = col(str(n).rjust(4)) if n else dim("   0")
        print(f"  {tag}  {sev}")

    if confirmed:
        print(f"\n  {red(bold(str(confirmed).rjust(4)))}  keys confirmed ACTIVE (check report.md)")

    print(f"\n  {green(str(len(endpoints)).rjust(4))}  endpoints extracted")
    print(f"  {dim(str(len(url_map)).rjust(4))}  JS files scanned")
    print(f"  {dim(str(len(sourcemap_files)).rjust(4))}  source map files")
    print(f"  {dim(str(len(extra_services)).rjust(4))}  services from port scan\n")
    print(f"  {cyan('findings/secrets.jsonl')}  full findings + validation")
    print(f"  {cyan('findings/endpoints.txt')} extracted API paths")
    print(f"  {cyan('report.md')}              summary")
    if env_findings:
        print(f"\n  {yellow(str(len(env_findings)).rjust(4))}  secrets from .env/config probing")
    print()


if __name__ == "__main__":
    main()
