#!/usr/bin/env python3
"""
recon.py — Full recon pipeline  v1.3

  Phase 1    Subdomain enum    crt.sh · chaos · github-subdomains · assetfinder · subfinder
                               shodanx · subcat · alienvault OTX · webarchive · urlscan.io
  Phase 1.5  DNS brute force   puredns / dnsx / massdns  [opt-in: --brute-force]
  Phase 2    httpx validation  live hosts + IP extraction — hosts/ (domains only) + ips/
  Phase 2b   Port scan         httpx multi-port (30+ ports) → hosts/alive.txt
  Phase 2c   Tech fingerprint  CMS/framework detection — passive (httpx) + active probes
  Phase 2.5  Takeover detect   candidates (non-2xx/3xx + dead) → dnsx CNAME · subjack · subzy · nuclei
  Phase 3    URL collection    gau · waybackurls · wayback-api · commoncrawl · katana · hakrawler · gospider
  Phase 4    GF patterns       redirect · xss · sqli · ssti · rce · lfi · ssrf  (URL pre-filter)
  Phase 5    Nuclei            fuzzing-templates/ — GF-filtered + direct-host scans
                               GF-filtered : redirect xss sqli ssti rce lfi ssrf
                               Direct URLs : crlf csti rfi xxe  (no GF pattern → all_urls.txt)
  Phase 6    Cloud buckets     S3 · GCS · Azure — list/write/delete/objects
Nuclei notes:
  • -dast is always passed — required for fuzzing-templates/ (fuzz-type templates)
  • Output: nuclei_<pattern>.txt (human) + nuclei_<pattern>.jsonl (structured)
  • User-agent, rate-limit, concurrency configurable

Usage:
  python3 recon.py example.com
  python3 recon.py example.com -o /tmp/results --tor
  python3 recon.py example.com --skip-nuclei
  python3 recon.py example.com --nuclei-patterns xss sqli crlf xxe
  python3 recon.py example.com --user-agent "Mozilla/5.0" --rate-limit 50
  python3 recon.py example.com --subdomains-file /path/to/subs.txt --skip-enum
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Constants ────────────────────────────────────────────────────────────────

RAPTOR_DIR = Path(os.environ.get("RAPTOR_DIR", Path(__file__).resolve().parent.parent))
NUCLEI_TEMPLATES_BASE = RAPTOR_DIR / "nuclei_fuzz" / "fuzzing-templates"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Ports probed by phase_port_scan (httpx multi-port sweep)
HTTPX_PORTS = (
    "80,81,161,443,2075,2076,2082,2083,2087,2379,"
    "3000,3001,3306,3366,3868,4000,4044,4443,4848,"
    "5000,5432,5601,5900,6000,6443,6885,7001,7002,"
    "7077,8000,8069,8080,8081,8161,8181,8443,8500,"
    "8888,8983,9000,9001,9090,9091,9200,9443,9999,"
    "10000,10250,15672"
)

# GF pre-filtered: nuclei receives only URLs where GF found matching params
GF_NUCLEI_MAP = {
    "xss":      NUCLEI_TEMPLATES_BASE / "xss",
    "redirect": NUCLEI_TEMPLATES_BASE / "redirect",
    "sqli":     NUCLEI_TEMPLATES_BASE / "sqli",
    "lfi":      NUCLEI_TEMPLATES_BASE / "lfi",
    "rce":      NUCLEI_TEMPLATES_BASE / "cmdi",
    "rfi":      NUCLEI_TEMPLATES_BASE / "rfi",
    "csti":     NUCLEI_TEMPLATES_BASE / "csti",
    "ssrf":     NUCLEI_TEMPLATES_BASE / "ssrf",
}

# No GF pattern available — run directly against all collected URLs
HOST_NUCLEI_MAP = {
    "crlf": NUCLEI_TEMPLATES_BASE / "crlf",  # any endpoint can leak CRLF
    "xxe":  NUCLEI_TEMPLATES_BASE / "xxe",   # POST-body attacks; no URL param filter
}

GF_PATTERNS   = list(GF_NUCLEI_MAP.keys())
HOST_PATTERNS = list(HOST_NUCLEI_MAP.keys())
ALL_PATTERNS  = GF_PATTERNS + HOST_PATTERNS

# GF patterns collected for manual review only — no nuclei fuzzing step
GF_ONLY_PATTERNS: list[str] = []

# ─── CMS / Framework Fingerprinting ──────────────────────────────────────────

# Canonical name → substrings matched (case-insensitive) against httpx technologies[]
_CMS_PATTERNS: dict = {
    # ── E-commerce ──────────────────────────────────────────────────────────
    "Magento":          ["magento", "adobe commerce"],
    "WooCommerce":      ["woocommerce"],
    "PrestaShop":       ["prestashop"],
    "OpenCart":         ["opencart"],
    "Shopify":          ["shopify"],
    "VTEX":             ["vtex"],
    "Salesforce CC":    ["salesforce commerce cloud", "demandware"],
    "SAP Hybris":       ["sap hybris", "hybris", "sap commerce"],
    "Magento 1":        ["magento 1"],
    # ── General CMS ─────────────────────────────────────────────────────────
    "WordPress":        ["wordpress"],
    "Drupal":           ["drupal"],
    "Joomla":           ["joomla"],
    "TYPO3":            ["typo3"],
    "Ghost":            ["ghost"],
    "Craft CMS":        ["craft cms", "craftcms"],
    "October CMS":      ["october cms", "octobercms"],
    "Grav":             ["grav cms", "grav"],
    "Concrete CMS":     ["concrete5", "concrete cms"],
    "Umbraco":          ["umbraco"],
    "Sitecore":         ["sitecore"],
    "AEM":              ["adobe experience manager", "aem"],
    "Kentico":          ["kentico"],
    "Sitefinity":       ["sitefinity"],
    "HubSpot CMS":      ["hubspot cms"],
    "Moodle":           ["moodle"],
    "Wix":              ["wix"],
    "Squarespace":      ["squarespace"],
    "Webflow":          ["webflow"],
    "Strapi":           ["strapi"],
    # ── Headless / JS frameworks ─────────────────────────────────────────────
    "Next.js":          ["next.js"],
    "Nuxt.js":          ["nuxt.js"],
    "Gatsby":           ["gatsby"],
    "Angular":          ["angular"],
    "React":            ["react"],
    "Vue.js":           ["vue.js"],
    # ── Backend frameworks ───────────────────────────────────────────────────
    "Laravel":          ["laravel"],
    "Symfony":          ["symfony"],
    "Django":           ["django"],
    "Ruby on Rails":    ["ruby on rails", "rails"],
    "ASP.NET":          ["asp.net"],
    "Spring":           ["spring boot", "spring framework"],
    "Flask":            ["flask"],
    "FastAPI":          ["fastapi"],
    "Express.js":       ["express"],
    # ── Dev / ops panels ────────────────────────────────────────────────────
    "Plesk":            ["plesk"],
    "cPanel":           ["cpanel"],
    "Jenkins":          ["jenkins"],
    "Grafana":          ["grafana"],
    "GitLab":           ["gitlab"],
    "Jira":             ["jira", "atlassian jira"],
    "Confluence":       ["confluence"],
    # ── Network / Firewall / Infra ───────────────────────────────────────────
    "FortiGate":        ["fortigate", "fortinet fortigate"],
    "FortiMail":        ["fortimail"],
    "FortiClient EMS":  ["forticlient ems", "forticlientems"],
    "Citrix NetScaler": ["netscaler", "citrix adc", "citrix gateway"],
    "Cisco FMC":        ["firepower management center", "cisco fmc"],
    "Cisco ASA":        ["cisco asa", "adaptive security appliance"],
    "Checkpoint":       ["check point", "checkpoint firewall"],
    "pfSense":          ["pfsense"],
    "F5 BIG-IP":        ["big-ip", "f5 big-ip"],
    "Palo Alto":        ["palo alto", "pan-os", "globalprotect"],
    # ── AI / ML / Automation Platforms ───────────────────────────────────────
    "Flowise":          ["flowise"],
    "n8n":              ["n8n"],
    "Langflow":         ["langflow"],
    "Metabase":         ["metabase"],
    "Gogs":             ["gogs"],
    "Gitea":            ["gitea"],
    # ── Databases, Middleware & DevOps ──────────────────────────────────────────
    "ActiveMQ":         ["apache activemq", "activemq"],
    "Elasticsearch":    ["elasticsearch"],
    "Kibana":           ["kibana"],
    "WebLogic":         ["oracle weblogic", "weblogic server"],
    "GlassFish":        ["glassfish", "payara"],
    "Jupyter":          ["jupyter notebook", "jupyterlab", "jupyter"],
    "Prometheus":       ["prometheus"],
    "Cockpit":          ["cockpit"],
    "Apache Solr":      ["apache solr", "solr"],
    "Consul":           ["consul"],
    "Odoo":             ["odoo", "openobject"],
    "Portainer":        ["portainer"],
    "etcd":             ["etcd"],
    "MinIO":            ["minio"],
    "WHM":              ["whm", "web host manager"],
}

# ─── Active probe format ──────────────────────────────────────────────────────
#
# Each CMS maps to a list of probe dicts.  A probe FIRES when ALL its checks
# pass.  A CMS is confirmed if at least ONE probe fires.
#
# Probe keys:
#   path        str             URL path to GET (required)
#   statuses    tuple[int,...]  accepted HTTP status codes     (default: (200,))
#   body        str             MUST appear in body (case-insensitive)
#   body_re     str             regex MUST match body (re.I | re.M | re.S)
#   header      str             response header name that MUST be present
#   header_val  str             substring header value MUST contain
#   cookie      str             prefix/name that MUST appear in Set-Cookie
#   min_len     int             body MUST be >= N bytes — gates catch-all pages
#                               (default 200; set 0 only for header/cookie-only probes)
#
# Design rules that prevent false positives:
#   1. Never use an empty body marker — every probe must verify specific content.
#   2. Never accept 301/302 as a hit — redirects give no CMS evidence.
#   3. 403 only when combined with a specific body or header check.
#   4. min_len=0 only for header/cookie probes that need no body.
#   5. Generic paths (/index.php, /login) always require a regex that is
#      structurally unique to the target CMS.

_ACTIVE_PROBES: dict = {

    "Magento": [
        # REST API returns a JSON array of store configs — the key combo is unique
        {"path": "/rest/V1/store/storeConfigs",
         "body_re": r'"base_url"\s*:\s*"https?://',
         "min_len": 30},
        # Magento 2 injects inline JSON-config blocks with this exact type attribute
        {"path": "/",
         "body_re": r'<script[^>]+type=["\']text/x-magento-init["\']',
         "min_len": 500},
        # Magento 1 JS library — unique filename + content combo
        {"path": "/js/mage/cookies.js",
         "body": "Mage.Cookies",
         "min_len": 50},
    ],

    "WordPress": [
        # xmlrpc.php always returns this exact string; no other platform shares it
        {"path": "/xmlrpc.php",
         "body": "XML-RPC server accepts POST requests only",
         "min_len": 30},
        # wp-submit is the name of the login button — WP-specific form field
        {"path": "/wp-login.php",
         "body": "wp-submit",
         "min_len": 200},
        # WP REST API root always contains the "namespaces" key
        {"path": "/wp-json/",
         "body_re": r'"namespaces"\s*:\s*\[',
         "min_len": 100},
    ],

    "Drupal": [
        # Changelog always starts with "Drupal X." — very specific
        {"path": "/core/CHANGELOG.txt",
         "body_re": r"^Drupal\s+\d+\.",
         "min_len": 10},
        # Drupal 7 (core changelog in root)
        {"path": "/CHANGELOG.txt",
         "body_re": r"^Drupal\s+\d+\.",
         "min_len": 10},
        # X-Generator header set by Drupal — no body check needed
        {"path": "/",
         "header": "X-Generator",
         "header_val": "Drupal",
         "min_len": 0},
    ],

    "Joomla": [
        # This XML manifest is only present in Joomla; content is exact
        {"path": "/administrator/manifests/files/joomla.xml",
         "body": "<name>Joomla</name>",
         "min_len": 30},
        # Language XML file — specific to Joomla l10n structure
        {"path": "/language/en-GB/en-GB.xml",
         "body_re": r"<name>\s*en-GB\s*</name>.*Joomla",
         "min_len": 50},
    ],

    "PrestaShop": [
        # Real PS cookie format is always "PrestaShop-{32_hex}" — the hyphen is mandatory.
        # Forks (BWBS, etc.) may set "PrestaShop_session" or similar without a hyphen,
        # so we require the hyphen to avoid matching OpenCart-derived stores.
        {"path": "/",
         "cookie": "prestashop-",
         "min_len": 0},
        # PS module URL structure — controller+step combo is PS-specific
        {"path": "/index.php?controller=order&step=1",
         "body_re": r"prestashop|ps_checkout|prestashop\.com",
         "min_len": 500},
        # PS REST API module (PS 1.7+) — path only exists on real PS installs
        {"path": "/api/",
         "body_re": r"<prestashop\b|<ps_version\b",
         "min_len": 30},
    ],

    "OpenCart": [
        # OCSESSID cookie is hardcoded in core OpenCart session handler.
        # Some forks (BWBS/Bestup) rename it — catch both.
        {"path": "/",
         "cookie": "OCSESSID",
         "min_len": 0},
        # OC asset paths are hardcoded by the template engine into every page.
        # /catalog/view/javascript/ and /catalog/view/theme/ only exist in OC trees.
        {"path": "/",
         "body_re": r'catalog/view/(javascript|theme)/',
         "min_len": 500},
        # OC routing: internal links produced by the URL helper always use route=
        {"path": "/index.php?route=common/home",
         "body_re": r"route=(common/cart|account/login|checkout/cart)",
         "min_len": 500},
    ],

    "Shopify": [
        # Shopify sets X-ShopId on every response — definitive header
        {"path": "/",
         "header": "X-ShopId",
         "min_len": 0},
        # Products JSON: must start with the exact key (rules out custom /products.json)
        {"path": "/products.json",
         "body_re": r'^\s*\{\s*"products"\s*:\s*\[',
         "min_len": 15},
    ],

    "VTEX": [
        # VTEX catalog API returns a JSON array; combine with VTEX-specific header
        {"path": "/api/catalog_system/pub/products/search",
         "header": "X-Vtex-Cache-Status-Janus-Apicache",
         "min_len": 0},
        # Fallback: response body must be a JSON array (not object) + has VTEX product fields
        {"path": "/api/catalog_system/pub/products/search",
         "body_re": r'^\s*\[.*"productId"',
         "min_len": 20},
    ],

    "Moodle": [
        # MoodleSession cookie is hardcoded in Moodle's session library
        {"path": "/login/",
         "cookie": "MoodleSession",
         "min_len": 0},
        # Upgrade notes always contain the version string
        {"path": "/lib/upgrade.txt",
         "body_re": r"Moodle\s+\d+\.\d+",
         "min_len": 50},
    ],

    "Umbraco": [
        # X-Umbraco-Version header — exposed by default on Umbraco responses
        {"path": "/",
         "header": "X-Umbraco-Version",
         "min_len": 0},
        # Umbraco backoffice login has a very specific <title> and CSS class structure.
        # A generic SPA catch-all won't contain these strings.
        {"path": "/umbraco/",
         "body_re": r'<title[^>]*>\s*Umbraco\s*</title>|umb-login|class="umb-|umbracoIsBackOffice',
         "min_len": 500},
    ],

    "Sitecore": [
        # SC_ANALYTICS_GLOBAL_COOKIE is injected by Sitecore's analytics module
        {"path": "/",
         "cookie": "SC_ANALYTICS_GLOBAL_COOKIE",
         "min_len": 0},
    ],

    "Craft CMS": [
        # X-Powered-By: Craft CMS — set by default, unique string
        {"path": "/",
         "header": "X-Powered-By",
         "header_val": "Craft CMS",
         "min_len": 0},
        # Admin login page contains craftcms in the JS bundle path
        {"path": "/admin/login",
         "body_re": r"craftcms|Craft\s+CMS",
         "min_len": 200},
    ],

    "Strapi": [
        # X-Powered-By: Strapi — set by default in Strapi's middleware
        {"path": "/",
         "header": "X-Powered-By",
         "header_val": "Strapi",
         "min_len": 0},
        # Strapi admin returns a minimal HTML that loads the React app
        {"path": "/admin/",
         "body_re": r'window\.StrapiApp|"strapi"',
         "min_len": 200},
    ],

    "Ghost": [
        # Ghost Admin API returns 401 (not a redirect) when unauthenticated.
        # Other apps (Grafana, etc.) redirect to their own /login — their final
        # status after redirect-follow is 200, which doesn't match (401,).
        # Ghost's 401 body always contains the UnauthorizedError type string.
        {"path": "/ghost/api/v4/admin/site/",
         "statuses": (401,),
         "body_re": r'"type"\s*:\s*"UnauthorizedError"',
         "resp_ct": "application/json",
         "min_len": 20},
        # Ghost frontend meta generator tag — injected into every public page
        {"path": "/",
         "body_re": r'<meta name="generator" content="Ghost\s+\d|ghost-sdk\.js|ghost\.js',
         "min_len": 300},
    ],

    "AEM": [
        # Sling login-status endpoint — only present on Apache Sling / AEM.
        # Must return application/json (rules out SPA catch-alls that serve HTML
        # for every path and may contain "authenticated" in inline JS state).
        {"path": "/system/sling/loginstatus.json",
         "body_re": r'"authenticated"\s*:\s*(true|false)',
         "resp_ct": "application/json",
         "min_len": 20},
        # Granite login page has an AEM-specific meta generator or CSS class
        {"path": "/libs/granite/core/content/login.html",
         "body_re": r'content="Adobe\s+Experience\s+Manager|class="[^"]*granite|<title[^>]*>AEM',
         "min_len": 200},
    ],

    "Salesforce CC": [
        # Demandware session cookies have this prefix — always set on first visit
        {"path": "/",
         "cookie": "dwanonymous_",
         "min_len": 0},
        # x-dw-request-count header is injected by Demandware's CDN/AppServer
        {"path": "/",
         "header": "x-dw-request-count",
         "min_len": 0},
    ],

    "Kentico": [
        # Kentico CSRF cookie is set on every page
        {"path": "/",
         "cookie": "CMSCsrfCookie",
         "min_len": 0},
    ],

    # ── Network / Firewall / Infra ────────────────────────────────────────────

    "FortiGate": [
        # FortiGate SSL-VPN login — unique JS variable fgt_lang only exists on FG
        {"path": "/remote/login",
         "body_re": r"fgt_lang|FortiGate|fortigate\.js",
         "min_len": 200},
        # Management UI — combo of title + cookie
        {"path": "/login",
         "body_re": r"FortiGate|<title[^>]*>FortiGate",
         "min_len": 200},
    ],

    "FortiMail": [
        {"path": "/admin/",
         "body_re": r"FortiMail|fortimail|<title[^>]*>FortiMail",
         "min_len": 200},
        {"path": "/login",
         "body_re": r"FortiMail|fortinet.*mail",
         "min_len": 200},
    ],

    "FortiClient EMS": [
        # /api/v1/system/version returns JSON with version info on EMS
        {"path": "/api/v1/system/version",
         "body_re": r'"version"\s*:\s*"\d+\.\d+|"product"\s*:\s*"FortiClient',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 10},
    ],

    "Citrix NetScaler": [
        # NITRO API returns JSON error on unauth — unique to NetScaler
        {"path": "/nitro/v1/config/nsversion",
         "body_re": r'"errorcode"\s*:|"version"\s*:',
         "statuses": (200, 401),
         "min_len": 10},
        # Gateway login page has nssbx or Citrix Gateway in title
        {"path": "/vpn/index.html",
         "body_re": r"NetScaler|Citrix\s+Gateway|nssbx\.js|CitrixAGBasic",
         "min_len": 200},
    ],

    "Cisco FMC": [
        # Platform info endpoint returns JSON — unauthenticated on older FMC
        {"path": "/api/fmc_platform/v1/info/serverversion",
         "body_re": r'"serverVersion"|"type"\s*:\s*"ServerVersion"',
         "statuses": (200, 401),
         "min_len": 10},
        # Login page has Cisco Firepower in title
        {"path": "/",
         "body_re": r"Firepower Management Center|Cisco FMC|<title[^>]*>Firepower",
         "min_len": 200},
    ],

    "Checkpoint": [
        {"path": "/login",
         "body_re": r"Check\s*Point|checkpoint|cpvpn|Check_Point",
         "min_len": 200},
        {"path": "/",
         "body_re": r"Check\s*Point|<title[^>]*>Check Point",
         "min_len": 200},
    ],

    "pfSense": [
        {"path": "/",
         "body_re": r"<title[^>]*>pfSense|pfSense\.org|pfsense",
         "min_len": 200},
        {"path": "/index.php",
         "body_re": r"pfSense|csrf_magic|pfsense",
         "min_len": 200},
    ],

    "F5 BIG-IP": [
        # TMUI login is the definitive BIG-IP indicator
        {"path": "/tmui/login.jsp",
         "body_re": r"BIG-IP|F5\s+Networks|tmui|iControl",
         "min_len": 200},
        # X-WA-Info header is injected by BIG-IP ASM/WAF on some configs
        {"path": "/",
         "header": "X-WA-Info",
         "min_len": 0},
    ],

    "Palo Alto": [
        {"path": "/global-protect/login.esp",
         "body_re": r"GlobalProtect|Palo\s*Alto|PAN-OS",
         "min_len": 200},
        {"path": "/php/login.php",
         "body_re": r"Palo\s*Alto|pan_form|PAN-OS",
         "min_len": 200},
    ],

    # ── AI / ML / Automation Platforms ────────────────────────────────────────

    "Flowise": [
        # Chatflows endpoint returns JSON array without auth (pre-auth versions)
        {"path": "/api/v1/chatflows",
         "body_re": r'"id"\s*:\s*"[0-9a-f-]{36}|"flowData"\s*:|^\s*\[',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 5},
        {"path": "/",
         "body_re": r"Flowise|flowise",
         "min_len": 200},
    ],

    "n8n": [
        # /rest/settings exposes versionCli — no auth on some deployments
        {"path": "/rest/settings",
         "body_re": r'"versionCli"\s*:|"n8nMetadata"\s*:',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 10},
        {"path": "/",
         "body_re": r"<title[^>]*>n8n|window\.n8nBaseUrl|n8n\.io",
         "min_len": 100},
    ],

    "Langflow": [
        # /health is always unauthenticated; /api/v1/flows requires auth
        {"path": "/health",
         "body_re": r'"status"\s*:\s*"ok"',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 5},
        {"path": "/api/v1/flows",
         "body_re": r'"id"\s*:\s*"[0-9a-f-]{36}|^\s*\[',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 5},
    ],

    "Metabase": [
        # /api/session/properties leaks setup-token if not configured
        {"path": "/api/session/properties",
         "body_re": r'"setup-token"\s*:|"version"\s*:.*"tag"\s*:',
         "resp_ct": "application/json",
         "min_len": 10},
    ],

    "Gogs": [
        {"path": "/api/v1/version",
         "body_re": r'"version"\s*:\s*"',
         "resp_ct": "application/json",
         "min_len": 5},
        {"path": "/",
         "body_re": r"Gogs|<title[^>]*>Gogs|gogs\.io",
         "min_len": 200},
    ],

    "Gitea": [
        {"path": "/api/v1/version",
         "body_re": r'"version"\s*:\s*"',
         "resp_ct": "application/json",
         "min_len": 5},
        {"path": "/",
         "body_re": r"Gitea|<title[^>]*>Gitea|gitea\.io",
         "min_len": 200},
    ],

    # ── Databases, Middleware & DevOps ────────────────────────────────────────

    "ActiveMQ": [
        # Jolokia REST bridge bundled with ActiveMQ — unique MBean path
        {"path": "/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerName",
         "body_re": r'"value"\s*:\s*"[^"]+"|"status"\s*:\s*200',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        # Web admin console
        {"path": "/admin/",
         "body_re": r"ActiveMQ|activemq",
         "min_len": 100},
    ],

    "Elasticsearch": [
        # Root returns cluster info + unique tagline
        {"path": "/",
         "body_re": r'"cluster_name"\s*:|"tagline"\s*:\s*"You Know, for Search"',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 20},
        # Cluster health endpoint — present even on unpatched deploys
        {"path": "/_cluster/health",
         "body_re": r'"cluster_name"\s*:|"status"\s*:\s*"(?:green|yellow|red)"',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 20},
    ],

    "Kibana": [
        # Status API — always unauthenticated by design
        {"path": "/api/status",
         "body_re": r'"name"\s*:\s*"kibana"|"version"\s*:.*"number"',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 20},
        {"path": "/",
         "body_re": r"<title[^>]*>Kibana|kbn-injected-metadata|loadKibanaScreen",
         "min_len": 100},
    ],

    "WebLogic": [
        # Admin console login JSP — unique path to WebLogic
        {"path": "/console/login/LoginForm.jsp",
         "body_re": r"WebLogic\s+Server\s+Administration\s+Console|weblogic\.jar",
         "min_len": 200},
        # /console redirects to login JSP; body on 302 may still contain vendor strings
        {"path": "/console/",
         "body_re": r"Oracle\s+WebLogic|WebLogic\s+Administration",
         "statuses": (200, 302, 403),
         "min_len": 50},
    ],

    "GlassFish": [
        {"path": "/common/index.jsf",
         "body_re": r"GlassFish\s+Server|Payara\s+Server|glassfish",
         "statuses": (200, 302),
         "min_len": 100},
        # X-Powered-By header set by GlassFish/Payara on every response
        {"path": "/",
         "header": "X-Powered-By",
         "header_val": "GlassFish",
         "min_len": 0},
        {"path": "/",
         "header": "X-Powered-By",
         "header_val": "Payara",
         "min_len": 0},
    ],

    "Jupyter": [
        # Older/misconfigured deployments expose kernel list without auth
        {"path": "/api/kernels",
         "body_re": r'^\s*\[',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 2},
        # Jupyter Server API version endpoint
        {"path": "/api/",
         "body_re": r'"version"\s*:\s*"\d+\.\d+',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        {"path": "/",
         "body_re": r"<title[^>]*>Jupyter|jupyter-notebook|jupyter-lab|JupyterLab",
         "min_len": 100},
    ],

    "Prometheus": [
        # Health check — unique response string
        {"path": "/-/healthy",
         "body_re": r"Prometheus(?:\s+Server)?\s+is\s+Healthy",
         "statuses": (200,),
         "min_len": 5},
        # Config status API
        {"path": "/api/v1/status/config",
         "body_re": r'"status"\s*:\s*"success"',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        {"path": "/",
         "body_re": r"<title[^>]*>Prometheus|prometheus_build_info|/static/vendor\.bundle\.js",
         "min_len": 100},
    ],

    "Apache Solr": [
        # System info JSON — version fields unique to Solr
        {"path": "/solr/admin/info/system?wt=json",
         "body_re": r'"solr-spec-version"\s*:|"lucene-spec-version"\s*:',
         "resp_ct": "application/json",
         "statuses": (200, 401),
         "min_len": 20},
        # Admin UI
        {"path": "/solr/",
         "body_re": r"<title[^>]*>Solr\s+Admin|Apache\s+Solr",
         "min_len": 100},
    ],

    "Consul": [
        # Raft leader endpoint returns a plain JSON string with IP:port
        {"path": "/v1/status/leader",
         "body_re": r'"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+"',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 5},
        # Service catalog always includes the built-in "consul" service entry
        {"path": "/v1/catalog/services",
         "body_re": r'"consul"\s*:\s*\[',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        {"path": "/ui/",
         "body_re": r"<title[^>]*>Consul|consul-ui|window\.__CONSUL",
         "min_len": 100},
    ],

    "Odoo": [
        {"path": "/web/database/manager",
         "body_re": r"Odoo|OpenERP|<title[^>]*>Database\s+Manager",
         "min_len": 100},
        {"path": "/web/login",
         "body_re": r"Odoo|odoo\.com|<title[^>]*>Odoo",
         "min_len": 100},
    ],

    "Portainer": [
        # /api/status always unauthenticated — returns version + auth mode
        {"path": "/api/status",
         "body_re": r'"Version"\s*:\s*"[^"]+"|"Authentication"\s*:\s*(?:true|false)',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        {"path": "/",
         "body_re": r"<title[^>]*>Portainer|portainer\.io|ng-app.*portainer",
         "min_len": 100},
    ],

    "etcd": [
        # /version always unauthenticated — exposes server + cluster version
        {"path": "/version",
         "body_re": r'"etcdserver"\s*:\s*"\d+\.\d+|"etcdcluster"\s*:\s*"',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 10},
        {"path": "/health",
         "body_re": r'"health"\s*:\s*"true"',
         "resp_ct": "application/json",
         "statuses": (200,),
         "min_len": 5},
    ],

    "Cockpit": [
        {"path": "/cockpit/login",
         "body_re": r"<title[^>]*>Cockpit|cockpit\.js|cockpit-components",
         "min_len": 100},
        {"path": "/",
         "body_re": r"<title[^>]*>Cockpit|cockpit\.js",
         "min_len": 100},
    ],

    "MinIO": [
        # Console login page — default on port 9001
        {"path": "/login",
         "body_re": r"<title[^>]*>MinIO|minio-ui|__MINIO_BROWSER|MinIO\s+Console",
         "min_len": 100},
        {"path": "/",
         "body_re": r"<title[^>]*>MinIO|MinIO\s+Browser|minio-ui",
         "min_len": 100},
    ],

    "cPanel": [
        {"path": "/",
         "body_re": r"<title[^>]*>cPanel|cPanel.*Log\s+In|cpsess",
         "statuses": (200, 302),
         "min_len": 100},
    ],

    "WHM": [
        {"path": "/",
         "body_re": r"<title[^>]*>WHM|WebHost\s+Manager|Web\s+Host\s+Manager",
         "statuses": (200, 302),
         "min_len": 100},
    ],
}

# CMS that carry significant CVE surface — highlighted in output
_SECURITY_CMS = {
    "Magento", "Magento 1", "WordPress", "WooCommerce", "Drupal", "Joomla",
    "PrestaShop", "OpenCart", "TYPO3", "Ghost", "VTEX", "Moodle",
    "AEM", "Sitecore", "Strapi", "Kentico", "Umbraco", "Craft CMS",
    "Salesforce CC", "SAP Hybris",
    # Network / Firewall / Infra
    "FortiGate", "FortiMail", "FortiClient EMS", "Citrix NetScaler",
    "Cisco FMC", "Cisco ASA", "Checkpoint", "pfSense", "F5 BIG-IP", "Palo Alto",
    # AI / ML / Automation (high CVE surface in 2025-2026)
    "Flowise", "n8n", "Langflow", "Metabase", "Gogs", "Gitea",
    # Databases, Middleware & DevOps
    "ActiveMQ", "Elasticsearch", "Kibana", "WebLogic", "GlassFish",
    "Jupyter", "Prometheus", "Cockpit", "Apache Solr", "Consul", "Odoo",
    "Portainer", "etcd", "MinIO", "cPanel", "WHM",
}

# ─── ANSI Colors ──────────────────────────────────────────────────────────────

class C:
    R   = "\033[91m"
    G   = "\033[92m"
    Y   = "\033[93m"
    B   = "\033[94m"
    M   = "\033[95m"
    CY  = "\033[96m"
    W   = "\033[97m"
    BD  = "\033[1m"
    DM  = "\033[2m"
    RS  = "\033[0m"

def _c(col, t): return f"{col}{t}{C.RS}"
def bold(t):    return _c(C.BD, t)
def red(t):     return _c(C.R, t)
def green(t):   return _c(C.G, t)
def yellow(t):  return _c(C.Y, t)
def cyan(t):    return _c(C.CY, t)
def dim(t):     return _c(C.DM, t)

_lock = threading.Lock()

def info(msg):
    with _lock: print(f"{C.CY}[*]{C.RS} {msg}")

def ok(msg):
    with _lock: print(f"{C.G}[+]{C.RS} {msg}")

def warn(msg):
    with _lock: print(f"{C.Y}[!]{C.RS} {msg}")

def err(msg):
    with _lock: print(f"{C.R}[-]{C.RS} {msg}", file=sys.stderr)

def phase_header(n, title):
    with _lock:
        print(f"\n{C.BD}{C.B}{'─'*64}{C.RS}")
        print(f"{C.BD}{C.B}  [{n}] {title}{C.RS}")
        print(f"{C.BD}{C.B}{'─'*64}{C.RS}")

# ─── Utilities ────────────────────────────────────────────────────────────────

def _source_bashrc():
    """
    Parse shell rc files for `export KEY=VALUE` lines and inject missing/empty
    vars into os.environ.

    Why not `source ~/.bashrc`?  Ubuntu's default .bashrc starts with
    `[ -z "$PS1" ] && return` which exits immediately in non-interactive
    subshells, so subprocess + source never reaches the export lines.
    Direct regex parsing bypasses that guard entirely.
    """
    import re
    rc_files = [
        Path.home() / ".bashrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".zshrc",
    ]
    # Matches:  export KEY=value   export KEY="value"   export KEY='value'
    _pat = re.compile(
        r"""^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\n]*)["']?\s*$""",
        re.MULTILINE,
    )
    for rc in rc_files:
        if not rc.exists():
            continue
        try:
            for m in _pat.finditer(rc.read_text()):
                key, val = m.group(1), m.group(2).strip()
                if key and not os.environ.get(key):
                    os.environ[key] = val
        except Exception:
            pass

def which(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0

def run(cmd, *, timeout=600, env_extra=None, stdin_data=None, shell=False):
    """
    Run cmd (list or str). Returns (rc, stdout, stderr).
    stdout/stderr are strings. Errors are returned, not raised.
    """
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        if shell:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env, shell=True
            )
        else:
            if isinstance(cmd, str):
                cmd = cmd.split()
            if stdin_data is not None:
                proc = subprocess.run(
                    cmd, input=stdin_data, capture_output=True, text=True,
                    timeout=timeout, env=env
                )
            else:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout, env=env
                )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        warn(f"  timeout: {cmd[0] if isinstance(cmd, list) else str(cmd)[:40]}")
        return 1, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as e:
        return 1, "", str(e)

def merge_files(files, dest: Path, dedup=True) -> int:
    """Merge text files into dest, optionally deduplicating. Returns line count."""
    lines = set() if dedup else []
    for f in files:
        p = Path(f)
        if p.exists() and p.stat().st_size > 0:
            for line in p.read_text().splitlines():
                line = line.strip()
                if line:
                    if dedup:
                        lines.add(line)
                    else:
                        lines.append(line)
    if dedup:
        lines = sorted(lines)
    dest.write_text("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)

def count_lines(p) -> int:
    p = Path(p)
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln.strip())

def write_lines(dest: Path, lines):
    dest.write_text("\n".join(sorted(set(ln.strip() for ln in lines if ln.strip()))) + "\n")

def _url_in_scope(url: str, domain: str) -> bool:
    """True if the URL's hostname is exactly domain or a subdomain of domain."""
    try:
        host = urlparse(url).netloc.split(":")[0].strip().lower()
        return host == domain or host.endswith(f".{domain}")
    except Exception:
        return False

def _filter_urls_to_scope(urls_file: Path, domain: str) -> tuple:
    """Rewrite urls_file keeping only in-scope URLs. Returns (kept, total)."""
    if not urls_file.exists():
        return 0, 0
    lines = [l.strip() for l in urls_file.read_text(errors="replace").splitlines() if l.strip()]
    total = len(lines)
    kept  = [u for u in lines if _url_in_scope(u, domain)]
    urls_file.write_text("\n".join(kept) + ("\n" if kept else ""))
    return len(kept), total

# ─── Phase 1 · Subdomain Enumeration ─────────────────────────────────────────

def _enum_crtsh(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_crtsh.txt"
    if not HAS_REQUESTS:
        warn("  crt.sh skipped (pip install requests)")
        return
    info("  crt.sh ...")
    last_err = None
    for attempt in range(3):
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=45, proxies=proxies, headers={"User-Agent": "recon.py"}
            )
            if r.status_code >= 500:
                last_err = f"HTTP {r.status_code}"
                import time; time.sleep(5 * (attempt + 1))
                continue
            r.raise_for_status()
            subs = set()
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
            write_lines(out, subs)
            ok(f"  crt.sh: {len(subs)}")
            return
        except Exception as e:
            last_err = str(e)
            import time; time.sleep(5 * (attempt + 1))
    warn(f"  crt.sh failed after 3 attempts: {last_err} — trying certspotter fallback")
    # certspotter fallback when crt.sh is unavailable
    _enum_certspotter(domain, outdir, proxies, _label="crt.sh→certspotter")

def _enum_certspotter(domain: str, outdir: Path, proxies=None, _label="certspotter"):
    out = outdir / "raw_certspotter.txt"
    if not HAS_REQUESTS:
        return
    info(f"  {_label} ...")
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=(10, 30), proxies=proxies, headers={"User-Agent": "recon.py"},
        )
        if r.status_code == 429:
            warn(f"  {_label}: rate limited (100 req/hr without token)")
            return
        r.raise_for_status()
        subs = set()
        for entry in r.json():
            for name in entry.get("dns_names", []):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        if subs:
            # merge into existing file if it exists (from crt.sh fallback path)
            existing = set()
            if out.exists():
                existing = set(out.read_text().splitlines())
            write_lines(out, subs | existing)
            ok(f"  {_label}: {len(subs)}")
        else:
            warn(f"  {_label}: no results")
    except Exception as e:
        warn(f"  {_label} failed: {e}")


def _enum_hackertarget(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_hackertarget.txt"
    if not HAS_REQUESTS:
        warn("  hackertarget skipped (pip install requests)")
        return
    info("  hackertarget ...")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=(10, 30), proxies=proxies, headers={"User-Agent": "recon.py"},
        )
        r.raise_for_status()
        if "error" in r.text.lower()[:50]:
            warn(f"  hackertarget: {r.text.strip()[:80]}")
            return
        subs = set()
        for line in r.text.splitlines():
            if "," in line:
                hostname = line.split(",")[0].strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
        if subs:
            write_lines(out, subs)
            ok(f"  hackertarget: {len(subs)}")
        else:
            warn("  hackertarget: no results")
    except Exception as e:
        warn(f"  hackertarget failed: {e}")


def _enum_chaos(domain: str, outdir: Path, key=None):
    out = outdir / "raw_chaos.txt"
    if not which("chaos"):
        warn("  chaos not found")
        return
    info("  chaos ...")
    env = {}
    resolved_key = key or os.environ.get("CHAOS_KEY", "")
    if resolved_key:
        env["CHAOS_KEY"] = resolved_key
    else:
        warn("  chaos: CHAOS_KEY not set, skipping")
        return
    rc, stdout, _ = run(["chaos", "-d", domain, "-silent"], env_extra=env or None, timeout=120)
    if rc == 0 and stdout.strip():
        lines = [l.strip().lower() for l in stdout.splitlines() if l.strip()]
        write_lines(out, lines)
        ok(f"  chaos: {len(lines)}")
    else:
        warn("  chaos: no results")

def _enum_github_subdomains(domain: str, outdir: Path, token=None):
    out = outdir / "raw_github_subdomains.txt"
    if not which("github-subdomains"):
        warn("  github-subdomains not found")
        return
    tok = token or os.environ.get("GITHUB_TOKEN", "")
    if not tok:
        warn("  github-subdomains: GITHUB_TOKEN not set, skipping")
        return
    info("  github-subdomains ...")
    rc, stdout, _ = run(
        ["github-subdomains", "-d", domain, "-t", tok, "-o", str(out)],
        timeout=120
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  github-subdomains: {count_lines(out)}")
    else:
        warn("  github-subdomains: no results")

def _enum_assetfinder(domain: str, outdir: Path):
    out = outdir / "raw_assetfinder.txt"
    if not which("assetfinder"):
        warn("  assetfinder not found")
        return
    info("  assetfinder ...")
    rc, stdout, _ = run(["assetfinder", "--subs-only", domain], timeout=120)
    if rc == 0 and stdout.strip():
        lines = [l.strip().lower() for l in stdout.splitlines()
                 if l.strip() and (domain in l)]
        write_lines(out, lines)
        ok(f"  assetfinder: {len(lines)}")
    else:
        warn("  assetfinder: no results")

def _enum_subfinder(domain: str, outdir: Path):
    out = outdir / "raw_subfinder.txt"
    if not which("subfinder"):
        warn("  subfinder not found")
        return
    info("  subfinder ...")
    rc, stdout, stderr = run(
        ["subfinder", "-d", domain, "-silent", "-o", str(out)],
        timeout=300
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  subfinder: {count_lines(out)}")
    else:
        warn("  subfinder: no results")

def _enum_amass(domain: str, outdir: Path):
    out = outdir / "raw_amass.txt"
    if not which("amass"):
        warn("  amass not found")
        return
    info("  amass (passive) ...")
    rc, stdout, stderr = run(
        ["amass", "enum", "-passive", "-d", domain, "-o", str(out)],
        timeout=600,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  amass: {count_lines(out)}")
    else:
        warn("  amass: no results")

def _enum_findomain(domain: str, outdir: Path):
    out = outdir / "raw_findomain.txt"
    if not which("findomain"):
        warn("  findomain not found")
        return
    info("  findomain ...")
    rc, stdout, _ = run(
        ["findomain", "-t", domain, "-u", str(out), "--quiet"],
        timeout=90,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  findomain: {count_lines(out)}")
    else:
        warn("  findomain: no results")

def _enum_shodanx(domain: str, outdir: Path):
    out = outdir / "raw_shodanx.txt"
    if not which("shodanx"):
        warn("  shodanx not found")
        return
    info("  shodanx ...")
    rc, stdout, stderr = run(
        ["shodanx", "subdomain", "-d", domain, "-o", str(out)],
        timeout=120,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  shodanx: {count_lines(out)}")
    else:
        warn("  shodanx: no results")


def _enum_subcat(domain: str, outdir: Path):
    out = outdir / "raw_subcat.txt"
    subcat_path = Path("/home/guilherme/kali/subcat/subcat/subcat.py")
    if not subcat_path.exists():
        warn("  subcat not found  (expected /home/guilherme/kali/subcat/subcat/subcat.py)")
        return
    info("  subcat ...")
    rc, stdout, stderr = run(
        ["python3", str(subcat_path), "-d", domain, "-o", str(out)],
        timeout=180,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  subcat: {count_lines(out)}")
    else:
        warn("  subcat: no results")


def _enum_alienvault(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_alienvault.txt"
    if not HAS_REQUESTS:
        warn("  alienvault skipped (pip install requests)")
        return
    info("  alienvault OTX ...")
    import time as _time
    last_err = None
    for attempt in range(2):
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns",
                timeout=(10, 30), proxies=proxies, headers={"User-Agent": "recon.py"},
            )
            r.raise_for_status()
            subs = set()
            for entry in r.json().get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
            if subs:
                write_lines(out, subs)
                ok(f"  alienvault: {len(subs)}")
            else:
                warn("  alienvault: no results")
            return
        except Exception as e:
            last_err = str(e)
            _time.sleep(3)
    warn(f"  alienvault failed: {last_err}")


def _enum_webarchive_subs(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_webarchive_subs.txt"
    if not HAS_REQUESTS:
        warn("  webarchive subs skipped (pip install requests)")
        return
    info("  webarchive (subdomains) ...")
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&collapse=urlkey",
            timeout=(30, 120), proxies=proxies, headers={"User-Agent": "recon.py"},
        )
        r.raise_for_status()
        subs = set()
        for row in r.json()[1:]:
            if row and len(row) > 2:
                try:
                    host = urlparse(row[2]).netloc.split(":")[0].lower()
                    if host and (host.endswith(f".{domain}") or host == domain):
                        subs.add(host)
                except Exception:
                    pass
        if subs:
            write_lines(out, subs)
            ok(f"  webarchive: {len(subs)}")
        else:
            warn("  webarchive: no results")
    except Exception as e:
        warn(f"  webarchive subs failed: {e}")


def _enum_urlscan(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_urlscan.txt"
    if not HAS_REQUESTS:
        warn("  urlscan skipped (pip install requests)")
        return
    info("  urlscan.io ...")
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=10000",
            timeout=(10, 30), proxies=proxies, headers={"User-Agent": "recon.py"},
        )
        if r.status_code == 429:
            warn("  urlscan: rate limited (no API key)")
            return
        r.raise_for_status()
        subs = set()
        for result in r.json().get("results", []):
            d = result.get("page", {}).get("domain", "").lower()
            if d and (d.endswith(f".{domain}") or d == domain):
                subs.add(d)
            # also extract host from full URL
            url = result.get("page", {}).get("url", "")
            if url:
                try:
                    h = urlparse(url).netloc.split(":")[0].lower()
                    if h and (h.endswith(f".{domain}") or h == domain):
                        subs.add(h)
                except Exception:
                    pass
        if subs:
            write_lines(out, subs)
            ok(f"  urlscan: {len(subs)}")
        else:
            warn("  urlscan: no results")
    except Exception as e:
        warn(f"  urlscan failed: {e}")


def phase_enum(domain: str, base: Path, args, proxies=None) -> Path:
    phase_header(1, "Subdomain Enumeration")
    outdir = base / "subdomains"
    outdir.mkdir(parents=True, exist_ok=True)

    fns = [
        (_enum_crtsh,              (domain, outdir, proxies),           {}),
        (_enum_chaos,              (domain, outdir, args.chaos_key),    {}),
        (_enum_github_subdomains,  (domain, outdir, args.github_token), {}),
        (_enum_assetfinder,        (domain, outdir),                    {}),
        (_enum_subfinder,          (domain, outdir),                    {}),
        (_enum_amass,              (domain, outdir),                    {}),
        (_enum_findomain,          (domain, outdir),                    {}),
        (_enum_shodanx,            (domain, outdir),                    {}),
        (_enum_subcat,             (domain, outdir),                    {}),
        (_enum_alienvault,         (domain, outdir, proxies),           {}),
        (_enum_webarchive_subs,    (domain, outdir, proxies),           {}),
        (_enum_urlscan,            (domain, outdir, proxies),           {}),
        (_enum_certspotter,        (domain, outdir, proxies),           {}),
        (_enum_hackertarget,       (domain, outdir, proxies),           {}),
    ]

    with ThreadPoolExecutor(max_workers=14) as ex:
        futures = {ex.submit(fn, *a, **kw): fn.__name__ for fn, a, kw in fns}
        try:
            for f in as_completed(futures, timeout=660):
                try:
                    f.result()
                except Exception as e:
                    warn(f"  enum error: {e}")
        except Exception:
            stragglers = [name for fut, name in futures.items() if not fut.done()]
            if stragglers:
                warn(f"  enum timeout — skipping: {', '.join(stragglers)}")

    merged = outdir / "all_subdomains.txt"
    n = merge_files(list(outdir.glob("raw_*.txt")), merged)
    ok(f"Total unique subdomains: {bold(str(n))}")
    return merged

# ─── Phase 2 · httpx Validation ───────────────────────────────────────────────

def phase_httpx(subdomains_file: Path, base: Path) -> tuple:
    """
    Returns (jsonl_path, live_urls_path).
    live_urls_path contains full URLs (with scheme) — used by active crawlers.
    """
    phase_header(2, "Host Validation (httpx)")
    outdir = base / "httpx"
    outdir.mkdir(parents=True, exist_ok=True)

    if not which("httpx"):
        err("httpx not found — cannot validate")
        return None, None

    n_input = count_lines(subdomains_file)
    if n_input == 0:
        err("No subdomains to validate")
        return None, None

    info(f"Validating {n_input} subdomains...")

    jsonl_out = outdir / "httpx_results.jsonl"
    live_txt  = outdir / "httpx_live.txt"

    rc, stdout, stderr = run(
        [
            "httpx",
            "-l", str(subdomains_file),
            "-silent",
            "-json",
            "-ip",
            "-title",
            "-status-code",
            "-tech-detect",
            "-o", str(jsonl_out),
            "-threads", "50",
            "-timeout", "10",
            "-retries", "1",
        ],
        timeout=1200,
    )

    live_urls = []
    if jsonl_out.exists():
        for line in jsonl_out.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                if url:
                    live_urls.append(url)
            except json.JSONDecodeError:
                pass
        live_txt.write_text("\n".join(sorted(set(live_urls))) + "\n")
        ok(f"Live hosts: {bold(str(len(live_urls)))}")
    else:
        warn("httpx produced no output")

    return jsonl_out, live_txt

# ─── Phase 2b · Extract Hosts / IPs ─────────────────────────────────────────

def phase_extract(httpx_jsonl: Path, base: Path):
    """
    hosts/live_hosts.txt  — bare hostnames, no scheme, no duplicates
    ips/unique_ips.txt    — resolved IPv4/IPv6, no duplicates, sorted
    """
    hosts_dir = base / "hosts"
    ips_dir   = base / "ips"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    ips_dir.mkdir(parents=True, exist_ok=True)

    if not httpx_jsonl or not Path(httpx_jsonl).exists():
        warn("No httpx JSONL — skipping host/IP extraction")
        return

    hosts = set()
    ips   = set()

    for line in Path(httpx_jsonl).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            url = entry.get("url", "")
            if url:
                parsed = urlparse(url)
                netloc = parsed.netloc or ""
                bare = netloc.split(":")[0]
                if bare:
                    try:
                        ipaddress.ip_address(bare)
                        ips.add(bare)
                    except ValueError:
                        hosts.add(bare.lower())
            for ip in entry.get("a", []) + entry.get("aaaa", []):
                try:
                    ipaddress.ip_address(ip)
                    ips.add(ip)
                except ValueError:
                    pass
        except json.JSONDecodeError:
            pass

    hosts_file = hosts_dir / "live_hosts.txt"
    ips_file   = ips_dir   / "unique_ips.txt"

    hosts_file.write_text("\n".join(sorted(hosts)) + "\n")
    try:
        ips_file.write_text(
            "\n".join(str(ip) for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x))) + "\n"
        )
    except Exception:
        ips_file.write_text("\n".join(sorted(ips)) + "\n")

    ok(f"Unique hosts (no scheme): {bold(str(len(hosts)))}  →  {hosts_file}")
    ok(f"Unique IPs:               {bold(str(len(ips)))}  →  {ips_file}")

# ─── Phase 2b · Multi-Port HTTP/S Scan ───────────────────────────────────────

def phase_port_scan(hosts_file: Path, base: Path) -> Path:
    """
    Phase 2b — Multi-port httpx sweep against bare hostnames.
    Input : hosts/live_hosts.txt   (domains only, no IPs, no scheme)
    Output: hosts/alive.txt        (full URLs that responded on any port)
    """
    phase_header("2b", "Multi-Port HTTP/S Scan (httpx)")
    hosts_dir = base / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)

    alive_txt = hosts_dir / "alive.txt"

    if not which("httpx"):
        err("httpx not found — skipping port scan")
        return alive_txt

    n_input = count_lines(hosts_file)
    if n_input == 0:
        warn("No hosts for port scan")
        return alive_txt

    port_count = len(HTTPX_PORTS.split(","))
    info(f"Scanning {n_input} hosts across {port_count} ports ...")

    rc, stdout, stderr = run(
        [
            "httpx",
            "-l",       str(hosts_file),
            "-ports",   HTTPX_PORTS,
            "-threads", "80",
            "-silent",
            "-o",       str(alive_txt),
        ],
        timeout=1800,
    )

    n_alive = count_lines(alive_txt) if alive_txt.exists() else 0
    if n_alive:
        ok(f"Alive (multi-port): {bold(str(n_alive))}  →  {alive_txt}")
    else:
        warn("No alive hosts found on extended ports")

    return alive_txt


# ─── Phase 2c · Technology Fingerprinting ────────────────────────────────────

def _run_probe(resp, probe: dict) -> bool:
    """
    Evaluate a single probe dict against an HTTP response.
    Returns True only when EVERY check specified in the probe passes.
    """
    # Status check
    if resp.status_code not in probe.get("statuses", (200,)):
        return False

    body = resp.text

    # Body length gate — rejects empty catch-all pages (CDN, WAF, custom 200 errors)
    min_len = probe.get("min_len", 200)
    if len(body) < min_len:
        return False

    # Body substring (case-insensitive)
    body_sub = probe.get("body", "")
    if body_sub and body_sub.lower() not in body.lower():
        return False

    # Body regex
    body_pat = probe.get("body_re", "")
    if body_pat and not re.search(body_pat, body, re.IGNORECASE | re.MULTILINE | re.DOTALL):
        return False

    # Response header presence + optional value substring
    hdr_name = probe.get("header", "")
    if hdr_name:
        actual_hdr = resp.headers.get(hdr_name, "")
        if not actual_hdr:
            return False
        hdr_val = probe.get("header_val", "")
        if hdr_val and hdr_val.lower() not in actual_hdr.lower():
            return False

    # Response Content-Type check (e.g. require "application/json" to exclude SPA catch-alls)
    resp_ct = probe.get("resp_ct", "")
    if resp_ct:
        actual_ct = resp.headers.get("content-type", "")
        if resp_ct.lower() not in actual_ct.lower():
            return False

    # Cookie name prefix in Set-Cookie header or parsed cookie jar
    cookie_prefix = probe.get("cookie", "")
    if cookie_prefix:
        prefix_lower = cookie_prefix.lower()
        set_cookie_hdr = resp.headers.get("set-cookie", "").lower()
        parsed_names   = {c.name.lower() for c in resp.cookies}
        found_in_hdr    = prefix_lower in set_cookie_hdr
        found_in_parsed = any(c.startswith(prefix_lower) for c in parsed_names)
        if not found_in_hdr and not found_in_parsed:
            return False

    return True


def _probe_cms_active(url: str, cms: str, proxies=None) -> bool:
    """
    Fire all registered probes for cms against url.
    Returns True the moment any single probe passes all its checks.
    """
    if not HAS_REQUESTS:
        return False

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    base = url.rstrip("/")

    for probe in _ACTIVE_PROBES.get(cms, []):
        try:
            resp = requests.get(
                base + probe["path"],
                timeout=6,
                proxies=proxies,
                allow_redirects=not probe.get("no_redirect", False),
                verify=False,
                headers={"User-Agent": DEFAULT_UA},
            )
        except Exception:
            continue

        if _run_probe(resp, probe):
            return True

    return False


def phase_fingerprint(
    httpx_jsonl: Path,
    base: Path,
    proxies=None,
    active: bool = True,
) -> dict:
    """
    Phase 2c — Technology / CMS fingerprinting.

    Passive: parses httpx JSONL (technologies[] field from -tech-detect).
    Active:  probes undetected hosts with CMS-specific paths (threaded, 5s timeout).
    Output:  fingerprint/tech_summary.json  +  fingerprint/cms_<name>.txt
    """
    phase_header("2c", "Technology Fingerprinting")
    outdir = base / "fingerprint"
    outdir.mkdir(parents=True, exist_ok=True)

    host_data: dict = {}  # url → {url, techs, cms, title, status, source}

    # ── Passive: httpx -tech-detect ──────────────────────────────────────────
    if httpx_jsonl and Path(httpx_jsonl).exists():
        for raw in Path(httpx_jsonl).read_text().splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            url = entry.get("url", "")
            if not url:
                continue
            # httpx v1 used "technologies", v2+ uses "tech" — accept both
            techs = entry.get("tech") or entry.get("technologies") or []
            lower_techs = [t.lower() for t in techs]
            matched = [
                cms for cms, patterns in _CMS_PATTERNS.items()
                if any(p in lt for lt in lower_techs for p in patterns)
            ]
            host_data[url] = {
                "url":    url,
                "techs":  techs,
                "cms":    matched,
                "title":  entry.get("title", ""),
                "status": entry.get("status-code", 0),
                "source": "passive",
            }

    passive_count = sum(1 for d in host_data.values() if d["cms"])
    info(f"  Passive (httpx tech-detect): {passive_count}/{len(host_data)} hosts with CMS identified")

    # ── Active: probe hosts without a passive CMS match ───────────────────────
    if active and HAS_REQUESTS:
        undetected = [u for u, d in host_data.items() if not d["cms"]]
        if undetected:
            info(f"  Active probes: {len(undetected)} hosts × {len(_ACTIVE_PROBES)} CMS checks ...")

            def _probe(url):
                found = [cms for cms in _ACTIVE_PROBES if _probe_cms_active(url, cms, proxies)]
                return url, found

            with ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(_probe, u): u for u in undetected}
                for fut in as_completed(futs):
                    url, found = fut.result()
                    if found:
                        host_data[url]["cms"]    = found
                        host_data[url]["source"] = "active"

            active_count = sum(1 for d in host_data.values() if d["source"] == "active" and d["cms"])
            if active_count:
                ok(f"  Active probes: {active_count} additional host(s) fingerprinted")
    elif active and not HAS_REQUESTS:
        warn("  Active probes skipped — pip install requests")

    # ── Aggregate per-CMS ────────────────────────────────────────────────────
    cms_map: dict = {}
    for url, d in host_data.items():
        for cms in d["cms"]:
            cms_map.setdefault(cms, []).append(url)

    # ── Write outputs ────────────────────────────────────────────────────────
    for cms, urls in cms_map.items():
        safe = cms.lower().replace(" ", "_").replace("/", "_").replace(".", "")
        (outdir / f"cms_{safe}.txt").write_text("\n".join(sorted(set(urls))) + "\n")

    summary = {
        "total_hosts":   len(host_data),
        "cms_breakdown": {k: len(v) for k, v in sorted(cms_map.items(), key=lambda x: -len(x[1]))},
        "hosts":         list(host_data.values()),
    }
    (outdir / "tech_summary.json").write_text(json.dumps(summary, indent=2))

    # ── Print ─────────────────────────────────────────────────────────────────
    if cms_map:
        ok(f"Frameworks/CMS detected ({len(host_data)} hosts scanned):")
        for cms, urls in sorted(cms_map.items(), key=lambda x: -len(x[1])):
            marker = yellow("⚑") if cms in _SECURITY_CMS else cyan("·")
            print(f"    {marker}  {bold(cms):<30}  {green(str(len(urls)).rjust(4))} host(s)")
        risky = [c for c in cms_map if c in _SECURITY_CMS]
        if risky:
            print()
            for cms in risky:
                warn(f"  {cms} detected — check CVE list for recent critical vulnerabilities")
    else:
        warn("No CMS/framework detected (passive + active probes)")
        warn("  tip: manually check headers / JS for framework hints")

    return summary


# ─── Phase 3 · URL Collection ─────────────────────────────────────────────────

def _collect_gau(domain: str, outdir: Path):
    out = outdir / "raw_gau.txt"
    if not which("gau"):
        warn("  gau not found")
        return
    info("  gau ...")
    rc, stdout, _ = run(["gau", "--subs", domain], timeout=7200)
    if rc == 0 and stdout.strip():
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        write_lines(out, lines)
        ok(f"  gau: {len(lines)}")
    else:
        warn("  gau: no results")

def _collect_waybackurls(domain: str, outdir: Path):
    out = outdir / "raw_waybackurls.txt"
    if not which("waybackurls"):
        warn("  waybackurls not found")
        return
    info("  waybackurls ...")
    rc, stdout, _ = run(["waybackurls", domain], timeout=7200)
    if rc == 0 and stdout.strip():
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        write_lines(out, lines)
        ok(f"  waybackurls: {len(lines)}")
    else:
        warn("  waybackurls: no results")

def _collect_wayback_api(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_wayback_api.txt"
    if not HAS_REQUESTS:
        warn("  wayback-api skipped (pip install requests)")
        return
    info("  wayback API ...")
    try:
        urls = set()
        for pattern in [domain, f"*.{domain}"]:
            api_url = (
                "http://web.archive.org/cdx/search/cdx"
                f"?url={pattern}&output=json&fl=original&collapse=urlkey&limit=100000"
            )
            # (connect_timeout, read_timeout=None) — large responses take minutes, never cut read
            r = requests.get(api_url, timeout=(30, None), proxies=proxies,
                             headers={"User-Agent": "recon.py"})
            r.raise_for_status()
            data = r.json()
            for row in data[1:]:
                if row and row[0]:
                    urls.add(row[0])
        write_lines(out, urls)
        ok(f"  wayback-api: {len(urls)}")
    except Exception as e:
        warn(f"  wayback-api failed: {e}")

def _collect_commoncrawl(domain: str, outdir: Path, proxies=None):
    out = outdir / "raw_commoncrawl.txt"
    if not HAS_REQUESTS:
        warn("  commoncrawl skipped (pip install requests)")
        return
    info("  commoncrawl ...")
    try:
        # collinfo is small — short timeout is fine
        r = requests.get("https://index.commoncrawl.org/collinfo.json",
                         timeout=(30, 30), proxies=proxies)
        r.raise_for_status()
        latest = r.json()[0]["id"]

        api_url = f"https://index.commoncrawl.org/{latest}-index"
        params = {"url": f"*.{domain}", "output": "json", "limit": "50000", "fl": "url"}
        # (connect_timeout, read_timeout=None) — index query can return megabytes, never cut read
        r2 = requests.get(api_url, params=params, timeout=(30, None), proxies=proxies)

        urls = set()
        for line in r2.text.splitlines():
            line = line.strip()
            if line:
                try:
                    urls.add(json.loads(line)["url"])
                except (json.JSONDecodeError, KeyError):
                    pass
        write_lines(out, urls)
        ok(f"  commoncrawl: {len(urls)}")
    except Exception as e:
        warn(f"  commoncrawl failed: {e}")

def _collect_katana(live_urls_file: Path, outdir: Path, proxy_env=None):
    out = outdir / "raw_katana.txt"
    if not which("katana"):
        warn("  katana not found")
        return
    if count_lines(live_urls_file) == 0:
        warn("  katana: no live hosts")
        return
    info(f"  katana → {count_lines(live_urls_file)} live hosts ...")
    rc, stdout, _ = run(
        ["katana", "-list", str(live_urls_file), "-silent",
         "-d", "3", "-kf", "all",
         "-c", "5", "-p", "5", "-rl", "150", "-timeout", "10",
         "-o", str(out)],
        env_extra=proxy_env, timeout=600,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  katana: {count_lines(out)}")
    else:
        warn("  katana: no results")

def _collect_hakrawler(live_urls_file: Path, outdir: Path, proxy_env=None):
    out = outdir / "raw_hakrawler.txt"
    if not which("hakrawler"):
        warn("  hakrawler not found")
        return
    if count_lines(live_urls_file) == 0:
        warn("  hakrawler: no live hosts")
        return
    info(f"  hakrawler → {count_lines(live_urls_file)} live hosts ...")
    stdin_data = Path(live_urls_file).read_text().strip()
    rc, stdout, _ = run(
        ["hakrawler", "-subs", "-d", "3"],
        stdin_data=stdin_data, env_extra=proxy_env, timeout=600,
    )
    if rc == 0 and stdout.strip():
        lines = [l.strip() for l in stdout.splitlines()
                 if l.strip() and l.strip().startswith("http")]
        write_lines(out, lines)
        ok(f"  hakrawler: {len(lines)}")
    else:
        warn("  hakrawler: no results")

def _collect_gospider(live_urls_file: Path, outdir: Path, proxy_env=None):
    out = outdir / "raw_gospider.txt"
    if not which("gospider"):
        warn("  gospider not found")
        return
    if count_lines(live_urls_file) == 0:
        warn("  gospider: no live hosts")
        return
    info(f"  gospider → {count_lines(live_urls_file)} live hosts ...")
    rc, stdout, _ = run(
        ["gospider", "-S", str(live_urls_file), "-c", "5", "-d", "3",
         "-t", "3", "--include-subs"],
        env_extra=proxy_env, timeout=600,
    )
    if rc == 0 and stdout.strip():
        urls = set()
        for line in stdout.splitlines():
            m = re.search(r'https?://\S+', line)
            if m:
                urls.add(m.group(0).rstrip('"').rstrip("'"))
        write_lines(out, urls)
        ok(f"  gospider: {len(urls)}")
    else:
        warn("  gospider: no results")

def _collect_waymore(domain: str, outdir: Path, proxy_env=None):
    out = outdir / "raw_waymore.txt"
    if not which("waymore"):
        warn("  waymore not found  (pip install waymore)")
        return
    info("  waymore ...")
    rc, stdout, _ = run(
        ["waymore", "-i", domain, "-mode", "U", "-oU", str(out)],
        env_extra=proxy_env, timeout=3600,
    )
    if out.exists() and out.stat().st_size > 0:
        ok(f"  waymore: {count_lines(out)}")
    else:
        warn("  waymore: no results")

def _collect_paramspider(domain: str, outdir: Path, proxy_env=None):
    out = outdir / "raw_paramspider.txt"
    if not which("paramspider"):
        warn("  paramspider not found  (pip install paramspider)")
        return
    info("  paramspider ...")
    rc, stdout, _ = run(
        ["paramspider", "-d", domain, "--output", str(out)],
        env_extra=proxy_env, timeout=600,
    )
    # paramspider writes to --output path; older versions fall back to results/<domain>.txt
    if out.exists() and out.stat().st_size > 0:
        ok(f"  paramspider: {count_lines(out)}")
        return
    # older paramspider ignores --output and writes relative to CWD
    default_out = Path(f"results/{domain}.txt")
    if default_out.exists() and default_out.stat().st_size > 0:
        import shutil; shutil.copy(default_out, out)
        ok(f"  paramspider: {count_lines(out)}")
        return
    # fallback: parse stdout if the results/ file isn't there
    if rc == 0 and stdout.strip():
        lines = [l.strip() for l in stdout.splitlines()
                 if l.strip() and l.strip().startswith("http")]
        if lines:
            write_lines(out, lines)
            ok(f"  paramspider: {len(lines)}")
            return
    warn("  paramspider: no results")

def phase_urls(domain: str, live_urls_file, base: Path, args, proxies=None, proxy_env=None) -> Path:
    phase_header(3, "URL Collection")
    outdir = base / "urls"
    outdir.mkdir(parents=True, exist_ok=True)

    # Passive sources (domain only, no live hosts needed)
    passive = [
        (_collect_gau,          (domain, outdir),              {}),
        (_collect_waybackurls,  (domain, outdir),              {}),
        (_collect_wayback_api,  (domain, outdir, proxies),     {}),
        (_collect_commoncrawl,  (domain, outdir, proxies),     {}),
        (_collect_waymore,      (domain, outdir, proxy_env),   {}),
        (_collect_paramspider,  (domain, outdir, proxy_env),   {}),
    ]
    # Active crawlers (need live hosts from httpx)
    active = [
        (_collect_katana,    (live_urls_file, outdir, proxy_env), {}),
        (_collect_hakrawler, (live_urls_file, outdir, proxy_env), {}),
        (_collect_gospider,  (live_urls_file, outdir, proxy_env), {}),
    ]

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(fn, *a, **kw) for fn, a, kw in passive]
        for f in as_completed(futures):
            try: f.result()
            except Exception as e: warn(f"  url collector error: {e}")

    with ThreadPoolExecutor(max_workers=1) as ex:
        futures = [ex.submit(fn, *a, **kw) for fn, a, kw in active]
        for f in as_completed(futures):
            try: f.result()
            except Exception as e: warn(f"  url crawler error: {e}")

    merged = outdir / "all_urls.txt"
    n = merge_files(list(outdir.glob("raw_*.txt")), merged)
    kept, _ = _filter_urls_to_scope(merged, domain)
    dropped = n - kept
    msg = f"Total unique URLs: {bold(str(n))} raw → {bold(str(kept))} in-scope"
    if dropped:
        msg += f"  ({dropped} out-of-scope removed)"
    ok(msg)
    return merged

# ─── Phase 4 · GF Pattern Matching ───────────────────────────────────────────

def _gf_pattern_exists(pattern: str) -> bool:
    return (Path.home() / ".gf" / f"{pattern}.json").exists()

def _run_gf_pattern(pattern: str, urls_file: Path, outdir: Path) -> int:
    if not _gf_pattern_exists(pattern):
        warn(f"  gf {pattern:<14}: skipped (no ~/.gf/{pattern}.json)")
        return 0
    out = outdir / f"gf_{pattern}.txt"
    if not Path(urls_file).exists():
        out.write_text("")
        return 0
    try:
        # Stream file via OS pipe — never loads into Python heap.
        # Each thread opens its own fd; concurrent reads are safe (read-only).
        with open(urls_file, "r", errors="replace") as fh:
            proc = subprocess.run(
                ["gf", pattern],
                stdin=fh,
                capture_output=True,
                text=True,
                timeout=120,
            )
        if proc.returncode == 0 and proc.stdout.strip():
            lines = sorted(set(l.strip() for l in proc.stdout.splitlines() if l.strip()))
            out.write_text("\n".join(lines) + "\n")
            ok(f"  gf {pattern:<14}: {len(lines)}")
            return len(lines)
        else:
            out.write_text("")
            info(f"  gf {pattern:<14}: 0")
            return 0
    except subprocess.TimeoutExpired:
        warn(f"  gf {pattern:<14}: timeout")
        out.write_text("")
        return 0
    except Exception as e:
        warn(f"  gf {pattern:<14}: error — {e}")
        return 0

def phase_gf(urls_file: Path, base: Path) -> Path:
    phase_header(4, "GF Pattern Matching")
    outdir = base / "gf"
    outdir.mkdir(parents=True, exist_ok=True)

    if not which("gf"):
        err("gf not found — install: go install github.com/tomnomnom/gf@latest")
        return outdir

    n = count_lines(urls_file)
    if n == 0:
        warn("No URLs to pattern-match")
        return outdir

    nuclei_pats  = [p for p in GF_PATTERNS      if _gf_pattern_exists(p)]
    infoonly_pats = [p for p in GF_ONLY_PATTERNS if _gf_pattern_exists(p)]
    all_pats      = nuclei_pats + infoonly_pats

    if not all_pats:
        warn("No GF patterns installed — skipping")
        return outdir

    # Cap parallelism by URL volume: each worker reads the file via OS pipe,
    # but regex matching still burns CPU. At 100k+ URLs one gf call already
    # saturates a core, so extra workers just fight for the same CPUs.
    if n > 100_000:
        workers = 4
    elif n > 10_000:
        workers = 8
    else:
        workers = min(len(all_pats), 16)

    info(f"Scanning {n} URLs — {len(nuclei_pats)} → nuclei, {len(infoonly_pats)} informational  (workers={workers})")

    missing_nuclei = [p for p in GF_PATTERNS if not _gf_pattern_exists(p)]
    if missing_nuclei:
        warn(f"  Missing nuclei patterns: {', '.join(missing_nuclei)}")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_run_gf_pattern, pat, urls_file, outdir): pat
                   for pat in all_pats}
        for f in as_completed(futures):
            try: f.result()
            except Exception as e: warn(f"  gf error: {e}")

    hits = [(p, count_lines(outdir / f"gf_{p}.txt")) for p in all_pats]
    hits = sorted([(p, c) for p, c in hits if c > 0], key=lambda x: -x[1])
    if hits:
        print()
        info("GF hits summary:")
        for pat, cnt in hits:
            tag = "" if pat in nuclei_pats else "  [info]"
            print(f"    {str(cnt).rjust(5)}  {pat}{tag}")

    return outdir

# ─── Phase 2d · WAF Detection ────────────────────────────────────────────────

def phase_waf(live_urls_file: Path, base: Path, proxy_env=None) -> Path:
    """Phase 2d: WAF detection on live hosts using wafw00f."""
    phase_header("2d", "WAF Detection")
    outdir = base / "waf"
    outdir.mkdir(parents=True, exist_ok=True)

    n = count_lines(live_urls_file) if live_urls_file and live_urls_file.exists() else 0
    if n == 0:
        warn("No live URLs — skipping WAF detection")
        return outdir

    if not which("wafw00f"):
        warn("wafw00f not found  (pip install wafw00f)")
        return outdir

    out_json = outdir / "wafw00f_results.json"
    info(f"Targets  : {n} URLs")

    rc, stdout, _ = run(
        ["wafw00f", "-i", str(live_urls_file), "-o", str(out_json), "-f", "json", "-a"],
        env_extra=proxy_env, timeout=1800,
    )

    if out_json.exists() and out_json.stat().st_size > 0:
        try:
            data = json.loads(out_json.read_text())
            if not isinstance(data, list):
                data = []
            detected   = [e for e in data if e.get("detected")]
            no_waf     = [e for e in data if not e.get("detected")]
            if detected:
                ok(f"WAF detected on {bold(str(len(detected)))} host(s)  (of {n} checked):")
                for e in detected:
                    fw  = yellow(e.get("firewall", "?"))
                    mfr = dim(f"[{e.get('manufacturer', '?')}]")
                    print(f"    {cyan(e.get('url','?')):<60}  {fw}  {mfr}")
            else:
                info(f"No WAF detected  ({len(data)} hosts checked)")
        except Exception:
            # wafw00f JSON format varies — fall back to stdout line parsing
            waf_lines = [l for l in stdout.splitlines()
                         if "is behind" in l.lower() or "waf" in l.lower()]
            if waf_lines:
                ok(f"WAF lines from stdout:")
                for l in waf_lines:
                    print(f"    {l.strip()}")
    else:
        info("wafw00f: no results")

    return outdir


# ─── Phase 3.5 · JS Endpoint Extraction ──────────────────────────────────────

_JS_EP_PATTERNS = [
    re.compile(r'''["`'](/(?:api|v\d+|graphql|rest|gql|rpc|ws|socket)[a-zA-Z0-9/_\-.?=&%:@#]{2,200})["`' \t]'''),
    re.compile(r'''(?:url|endpoint|path|href|action)\s*[:=]\s*["`']([a-zA-Z0-9/_\-.?=&%:@#]{5,200})["`']''', re.I),
    re.compile(r'''fetch\(\s*["`']([^"`'\s]{5,200})["`']'''),
    re.compile(r'''(?:axios|xhr|http)\.[a-z]+\(\s*["`']([^"`'\s]{5,200})["`']''', re.I),
]

_JS_NOISE = frozenset({
    "jquery", "bootstrap", "analytics.js", "gtag", "fbevents", "hotjar",
    "recaptcha", "google-analytics", "doubleclick", "googletagmanager",
    "cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com", "min.js",
})


def _extract_js_endpoints(js_url: str, session, domain: str) -> list:
    """Fetch one JS file and return in-scope endpoint strings."""
    try:
        r = session.get(js_url, timeout=(5, 10), allow_redirects=True)
        if r.status_code != 200 or not r.text:
            return []
        content = r.text
        endpoints = set()
        parsed_js = urlparse(js_url)
        js_base   = f"{parsed_js.scheme}://{parsed_js.netloc}"

        for pat in _JS_EP_PATTERNS:
            for m in pat.finditer(content):
                ep = m.group(1).strip()
                if len(ep) < 3:
                    continue
                if ep.startswith("http"):
                    if domain in ep:
                        endpoints.add(ep)
                elif ep.startswith("/"):
                    endpoints.add(js_base + ep)
    except Exception:
        return []
    return list(endpoints)


def phase_js_endpoints(
    all_urls_file: Path,
    base: Path,
    domain: str,
    proxies=None,
) -> Path:
    """Phase 3.5: Fetch JS files and extract API endpoints via regex + linkfinder."""
    phase_header("3.5", "JS Endpoint Extraction")
    outdir = base / "js_endpoints"
    outdir.mkdir(parents=True, exist_ok=True)

    if not all_urls_file.exists() or count_lines(all_urls_file) == 0:
        warn("No URLs — skipping JS extraction")
        return outdir

    js_urls = []
    for line in all_urls_file.read_text().splitlines():
        u = line.strip()
        if not u:
            continue
        low = u.lower()
        if ".js" not in low:
            continue
        if any(n in low for n in _JS_NOISE):
            continue
        js_urls.append(u)
    js_urls = list(dict.fromkeys(js_urls))

    if not js_urls:
        info("No JS files found in URL list")
        return outdir

    info(f"JS files : {len(js_urls)}")

    if not HAS_REQUESTS:
        warn("requests not installed — cannot fetch JS files")
        return outdir

    import urllib3
    urllib3.disable_warnings()
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = DEFAULT_UA
    if proxies:
        session.proxies = proxies

    all_endpoints: set = set()
    lock = threading.Lock()

    def _worker(u):
        eps = _extract_js_endpoints(u, session, domain)
        if eps:
            with lock:
                all_endpoints.update(eps)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(_worker, u): u for u in js_urls}
        done = 0
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
            done += 1
            if done % 25 == 0:
                info(f"  {done}/{len(js_urls)} processed  ({len(all_endpoints)} endpoints so far)")

    # linkfinder pass if available
    if which("linkfinder"):
        info("  linkfinder pass ...")
        lf_endpoints: set = set()
        for u in js_urls[:100]:
            rc, stdout, _ = run(["linkfinder", "-i", u, "-o", "cli"], timeout=30)
            if rc == 0 and stdout.strip():
                for line in stdout.splitlines():
                    ep = line.strip()
                    if ep.startswith("/") or ep.startswith("http"):
                        lf_endpoints.add(ep)
        if lf_endpoints:
            (outdir / "linkfinder_raw.txt").write_text("\n".join(sorted(lf_endpoints)) + "\n")
            ok(f"  linkfinder: {len(lf_endpoints)} additional endpoints")
            all_endpoints.update(lf_endpoints)

    if all_endpoints:
        write_lines(outdir / "all_js_endpoints.txt", all_endpoints)
        ok(f"JS endpoints : {bold(str(len(all_endpoints)))}  → js_endpoints/all_js_endpoints.txt")
        # Append new endpoints to all_urls.txt so GF/nuclei can pick them up
        try:
            existing = set(all_urls_file.read_text().splitlines())
            new_eps  = all_endpoints - existing
            if new_eps:
                with open(all_urls_file, "a") as fh:
                    fh.write("\n".join(sorted(new_eps)) + "\n")
                info(f"  {len(new_eps)} new endpoints appended to all_urls.txt")
        except Exception as e:
            warn(f"  Could not append to all_urls.txt: {e}")
    else:
        info("No endpoints extracted from JS files")

    return outdir


# ─── Phase 1.5 · DNS Brute Force ─────────────────────────────────────────────

DEFAULT_BRUTEFORCE_WORDLIST = Path(
    "/home/guilherme/kali/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt"
)

def phase_bruteforce(domain: str, base: Path, wordlist: Path) -> Path:
    """
    DNS brute force with puredns → dnsx → massdns fallback.
    Results are merged back into all_subdomains.txt.
    Only runs when --brute-force is passed.
    """
    phase_header("1.5", "DNS Brute Force")
    outdir = base / "subdomains"
    outdir.mkdir(parents=True, exist_ok=True)

    if not wordlist.exists():
        err(f"Wordlist not found: {wordlist}")
        return outdir / "all_subdomains.txt"

    n_words = count_lines(wordlist)
    info(f"Wordlist : {wordlist}")
    info(f"Entries  : {n_words:,}")

    out = outdir / "raw_bruteforce.txt"

    if which("puredns"):
        info("Tool: puredns")
        run(
            ["puredns", "bruteforce", str(wordlist), domain,
             "--write", str(out), "-q"],
            timeout=14400,
        )
    elif which("dnsx"):
        info("Tool: dnsx  (generating candidate list…)")
        cands = outdir / "_bf_cands.txt"
        lines = [
            f"{w.strip()}.{domain}"
            for w in wordlist.read_text().splitlines()
            if w.strip() and not w.startswith("#")
        ]
        cands.write_text("\n".join(lines) + "\n")
        run(
            ["dnsx", "-l", str(cands), "-silent",
             "-a", "-resp-only", "-o", str(out), "-t", "100"],
            timeout=14400,
        )
        cands.unlink(missing_ok=True)
    elif which("massdns"):
        info("Tool: massdns  (generating candidate list…)")
        cands     = outdir / "_bf_cands.txt"
        resolvers = outdir / "_resolvers.txt"
        lines = [
            f"{w.strip()}.{domain}"
            for w in wordlist.read_text().splitlines()
            if w.strip() and not w.startswith("#")
        ]
        cands.write_text("\n".join(lines) + "\n")
        resolvers.write_text(
            "1.1.1.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n208.67.222.222\n"
        )
        rc, stdout, _ = run(
            ["massdns", "-r", str(resolvers), "-t", "A", "-o", "S", str(cands)],
            timeout=14400,
        )
        if rc == 0 and stdout.strip():
            resolved = set()
            for line in stdout.splitlines():
                parts = line.split()
                if parts:
                    host = parts[0].rstrip(".").lower()
                    if host.endswith(f".{domain}") or host == domain:
                        resolved.add(host)
            out.write_text("\n".join(sorted(resolved)) + "\n")
        cands.unlink(missing_ok=True)
        resolvers.unlink(missing_ok=True)
    else:
        err("No DNS brute force tool found — install puredns, dnsx, or massdns")
        return outdir / "all_subdomains.txt"

    if out.exists() and out.stat().st_size > 0:
        ok(f"Brute force new subdomains: {bold(str(count_lines(out)))}")
    else:
        warn("Brute force: no results")

    merged = outdir / "all_subdomains.txt"
    if merged.exists():
        n = merge_files([merged, out], merged, dedup=True)
        ok(f"Total after brute force: {bold(str(n))} subdomains")

    return merged

# ─── Phase 6 · Cloud Bucket Discovery ────────────────────────────────────────

BUCKET_SUFFIXES = [
    # Web / assets
    "assets", "static", "media", "files", "uploads", "images", "img",
    "cdn", "resources", "content", "public", "web", "site",
    # App tiers
    "app", "api", "frontend", "backend", "mobile",
    "dev", "development", "prod", "production", "staging", "stage",
    "test", "qa", "homolog", "hml", "sandbox", "uat",
    # Storage / infra
    "storage", "bucket", "s3", "gcs", "blob", "store",
    "archive", "archives", "bak",
    # Data / BI
    "data", "database", "db", "datalake", "lake", "warehouse", "dwh",
    "analytics", "reports", "export", "exports", "dump", "dumps",
    "logs", "log", "audit", "monitoring",
    # Backups
    "backup", "backups", "restore", "snapshot", "snapshots",
    # Docs / downloads
    "docs", "documents", "downloads", "attachments", "invoices",
    "notas", "nfe", "boletos", "contratos",
    # Private / secrets
    "private", "internal", "secrets", "config", "configs", "env",
    "credentials", "certs", "certificates", "keys",
    # Cloud-specific
    "terraform", "infra", "infrastructure", "deploy", "deployments",
    "builds", "artifacts", "releases", "packages",
    # BR/PT variants
    "arquivos", "imagens", "fotos", "videos", "relatorios",
    "clientes", "usuarios", "pedidos", "vendas", "financeiro",
    "fiscal", "contabil", "rh", "juridico",
    # Common suffixes
    "2023", "2024", "2025", "2026",
]

AZURE_CONTAINERS = [
    "$web", "public", "assets", "media", "files", "images", "uploads",
    "static", "content", "data", "backup", "docs", "downloads", "private",
    "web", "api", "app", "cdn", "storage", "archive", "logs",
    "dev", "prod", "staging", "test", "qa",
    "database", "db", "export", "dump", "reports",
    "invoices", "notas", "contratos", "boletos",
]

def _gen_bucket_names(domain: str) -> list:
    parts   = domain.split(".")
    base    = parts[0]                   # sysmo
    dashed  = domain.replace(".", "-")   # sysmo-com-br
    tld_stripped = ".".join(parts[:-1]) if len(parts) > 2 else base  # sysmo.com

    names = set()

    stems = [base, dashed]
    # also try without common BR TLD noise: empresa.com.br → empresa + empresa-web
    if len(parts) >= 3 and parts[-1] == "br":
        stems.append(".".join(parts[:-2]))       # sysmo.com → sysmo-com
        stems.append(parts[0])                   # already have base

    for stem in stems:
        names.add(stem)
        for suf in BUCKET_SUFFIXES:
            names.add(f"{stem}-{suf}")
            names.add(f"{suf}-{stem}")
            names.add(f"{stem}{suf}")   # sysmoweb, sysmobackup

    # Filter: S3/GCS bucket names — 3-63 chars, lowercase alphanumeric/hyphen/dot
    valid = set()
    for n in names:
        n = n.lower()
        if 3 <= len(n) <= 63 and re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", n):
            valid.add(n)
    return sorted(valid)

# Common sensitive object names — tried against any bucket even without listing
COMMON_OBJECTS = [
    # SQL dumps — generic
    "backup.sql", "backup.sql.gz", "backup.zip", "backup.tar.gz", "backup.tar",
    "dump.sql", "dump.sql.gz", "database.sql", "database.sql.gz",
    "db.sql", "db.sql.gz", "db.tar.gz", "db_backup.sql",
    "data.sql", "export.sql", "full_backup.sql",

    # Cloud SQL export pattern (GCP — what we just found)
    "cloudsql_export.sql", "cloud_sql_export.sql",

    # Archives
    "backup.tar.bz2", "site.zip", "www.zip", "htdocs.zip", "html.zip",
    "source.zip", "code.zip", "app.zip",

    # CSV/JSON data exports
    "users.csv", "users.json", "clientes.csv", "clientes.json",
    "clients.csv", "clients.json", "customers.csv", "customers.json",
    "pedidos.csv", "pedidos.json", "vendas.csv", "vendas.json",
    "export.csv", "export.json", "export.zip",
    "relatorio.csv", "relatorio.xlsx", "data.csv", "data.json", "data.zip",
    "emails.csv", "emails.txt", "cpfs.csv", "cpfs.txt",

    # Config / secrets
    ".env", ".env.production", ".env.prod", ".env.local", ".env.staging",
    ".env.development", ".env.dev", ".env.example",
    "config.json", "config.yml", "config.yaml", "configuration.json",
    "settings.json", "settings.py", "local_settings.py",
    "secrets.json", "secrets.yml", "secrets.yaml",
    "keys.json", "key.json", "keys.txt", "api_keys.txt",
    "credentials.json", "credentials.txt", "creds.json", "creds.txt",
    "service-account.json", "service_account.json", "sa.json",
    "gcp-credentials.json", "firebase-adminsdk.json",

    # Passwords
    "passwords.txt", "pass.txt", "password.txt", "senhas.txt",

    # SSH / TLS
    "private.pem", "private.key", "id_rsa", "id_rsa.pub",
    "server.key", "server.pem", "cert.pem", "ca.pem",

    # Cloud infra
    "aws_credentials", ".aws/credentials",
    "terraform.tfstate", "terraform.tfstate.backup", "terraform.tfvars",
    ".terraform/terraform.tfstate",

    # Docker / CI
    "docker-compose.yml", "docker-compose.yaml",
    ".github/workflows/deploy.yml",
    "Dockerfile", ".dockerenv",

    # App config leaks
    "wp-config.php", "wp-config.php.bak",
    "application.properties", "application.yml",
    "appsettings.json", "web.config",
    "database.yml", "database.json",

    # NF-e / fiscal BR
    "nfe.xml", "nfe.zip", "notas.zip", "notas.xml",
    "danfe.pdf", "boleto.pdf",

    # Log files
    "access.log", "error.log", "app.log", "debug.log",
    "logs.zip", "logs.tar.gz",
]

def _probe_objects(base_url: str, session) -> list:
    """HEAD each common sensitive filename in parallel. Returns list of readable objects."""
    hits = []
    lock = threading.Lock()

    def _head(obj):
        try:
            r = session.head(f"{base_url}/{obj}", timeout=(3, 5), allow_redirects=True)
            if r.status_code == 200:
                with lock:
                    hits.append({
                        "key":          obj,
                        "size":         r.headers.get("Content-Length", "?"),
                        "content_type": r.headers.get("Content-Type", ""),
                        "url":          f"{base_url}/{obj}",
                    })
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_head, COMMON_OBJECTS))

    return hits

def _probe_write(base_url: str, session, probe_key=".raptor-probe-bb",
                 extra_headers=None) -> bool | None:
    """PUT probe. Returns True/False/None."""
    headers = {"Content-Type": "text/plain"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = session.put(f"{base_url}/{probe_key}", data=b"raptor-bb-probe",
                        headers=headers, timeout=(5, 8))
        if r.status_code in (200, 201, 204):
            try:
                session.delete(f"{base_url}/{probe_key}", timeout=(5, 8))
            except Exception:
                pass
            return True
        if r.status_code == 403:
            return False
    except Exception:
        pass
    return None

def _probe_delete(base_url: str, session, extra_headers=None) -> bool | None:
    """DELETE probe on a nonexistent key. 204/200 = delete allowed."""
    headers = extra_headers or {}
    try:
        r = session.delete(f"{base_url}/.raptor-delete-probe-nonexistent",
                           headers=headers, timeout=(5, 8))
        if r.status_code in (200, 204):
            return True
        if r.status_code == 403:
            return False
    except Exception:
        pass
    return None

def _parse_xml_listing(xml_body: str) -> dict:
    """Parse S3/GCS/Azure XML object listing. Returns stats dict."""
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return {"count": 0, "truncated": False, "file_types": {}, "sample_keys": []}

    keys    = []
    trunc   = False

    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "Key" and el.text:
            keys.append(el.text)
        elif tag == "Name" and el.text and ("." in el.text or "/" in el.text):
            keys.append(el.text)
        elif tag == "IsTruncated" and el.text:
            trunc = el.text.strip().lower() == "true"

    exts = Counter(Path(k).suffix.lower() or "(no ext)" for k in keys)
    return {
        "count":       len(keys),
        "truncated":   trunc,
        "file_types":  dict(exts.most_common(15)),
        "sample_keys": keys[:15],
    }

def _check_s3(name: str, session, probe_objects: bool = True) -> dict | None:
    """Check S3 bucket. Returns finding or None."""
    urls_to_try = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]

    found_url = None
    readable  = False
    listing   = None

    for url in urls_to_try:
        try:
            r = session.get(url, timeout=(8, 15), allow_redirects=False)
            # Follow region redirect
            if r.status_code in (301, 307):
                loc = r.headers.get("Location", "")
                if loc:
                    try:
                        r = session.get(loc, timeout=(8, 15))
                    except Exception:
                        pass
            if r.status_code == 200 and "ListBucketResult" in r.text:
                found_url = url
                readable  = True
                listing   = _parse_xml_listing(r.text)
                break
            elif r.status_code == 403:
                found_url = url
                readable  = False
                break
            # 404 = doesn't exist, try next pattern
        except Exception:
            continue

    if not found_url:
        return None

    base_url = f"https://{name}.s3.amazonaws.com"

    result = {
        "provider":    "S3",
        "bucket":      name,
        "url":         found_url,
        "readable":    readable,
        "writable":    None,
        "deletable":   None,
        "listing":     listing,
        "acl":         None,
        "policy":      None,
        "cors":        None,
        "versioning":  None,
        "website":     None,
        "object_hits": [],
    }

    # ACL
    try:
        r = session.get(f"{base_url}/?acl", timeout=(5, 8))
        if r.status_code == 200:
            result["acl"] = r.text[:800]
    except Exception:
        pass

    # Bucket policy
    try:
        r = session.get(f"{base_url}/?policy", timeout=(5, 8))
        if r.status_code == 200:
            result["policy"] = r.text[:800]
    except Exception:
        pass

    # CORS — wildcard AllowedOrigin = cross-origin read (MEDIUM)
    try:
        r = session.get(f"{base_url}/?cors", timeout=(5, 8))
        if r.status_code == 200:
            result["cors"] = r.text[:600]
    except Exception:
        pass

    # Versioning — enabled means deleted objects accessible via ?versions
    try:
        r = session.get(f"{base_url}/?versioning", timeout=(5, 8))
        if r.status_code == 200 and "Enabled" in r.text:
            rv = session.get(f"{base_url}/?versions", timeout=(5, 10))
            result["versioning"] = (rv.text if rv.status_code == 200 else r.text)[:1000]
    except Exception:
        pass

    # Static website hosting — if writable too = stored XSS / phishing
    try:
        r = session.get(f"{base_url}/?website", timeout=(5, 8))
        if r.status_code == 200:
            result["website"] = r.text[:400]
    except Exception:
        pass

    result["writable"]    = _probe_write(base_url, session)
    result["deletable"]   = _probe_delete(base_url, session)
    result["object_hits"] = _probe_objects(base_url, session) if probe_objects else []

    return result

def _check_gcs(name: str, session, probe_objects: bool = True) -> dict | None:
    """Check GCS bucket — listing, IAM, CORS, write, delete, object enum."""
    found_url = None
    readable  = False
    listing   = None

    for url in [
        f"https://storage.googleapis.com/{name}",
        f"https://{name}.storage.googleapis.com",
        f"https://storage.googleapis.com/storage/v1/b/{name}/o",
    ]:
        try:
            r = session.get(url, timeout=(8, 15))
            ct = r.headers.get("content-type", "")
            if r.status_code == 200:
                if "xml" in ct or "ListBucketResult" in r.text:
                    listing = _parse_xml_listing(r.text)
                elif "json" in ct:
                    try:
                        data  = r.json()
                        items = data.get("items", [])
                        keys  = [i.get("name", "") for i in items]
                        exts  = Counter(Path(k).suffix.lower() or "(no ext)" for k in keys)
                        listing = {
                            "count":       len(items),
                            "truncated":   "nextPageToken" in data,
                            "file_types":  dict(exts.most_common(15)),
                            "sample_keys": keys[:15],
                        }
                    except Exception:
                        pass
                found_url = url
                readable  = True
                break
            elif r.status_code == 403:
                found_url = url
                readable  = False
                break
        except Exception:
            continue

    if not found_url:
        return None

    base_url = f"https://storage.googleapis.com/{name}"
    api_url  = f"https://storage.googleapis.com/storage/v1/b/{name}"

    result = {
        "provider":    "GCS",
        "bucket":      name,
        "url":         found_url,
        "readable":    readable,
        "writable":    None,
        "deletable":   None,
        "listing":     listing,
        "acl":         None,
        "policy":      None,
        "cors":        None,
        "versioning":  None,
        "website":     None,
        "object_hits": [],
    }

    # IAM policy — allUsers with roles/storage.objectViewer = public read
    try:
        r = session.get(f"{api_url}/iam", timeout=(5, 8))
        if r.status_code == 200:
            result["acl"] = r.text[:800]
    except Exception:
        pass

    # Bucket metadata via JSON API — includes CORS and website config
    try:
        r = session.get(api_url, timeout=(5, 8))
        if r.status_code == 200:
            data = r.json()
            if data.get("cors"):
                result["cors"] = json.dumps(data["cors"])[:600]
            if data.get("website"):
                result["website"] = json.dumps(data["website"])[:400]
            if data.get("defaultObjectAcl"):
                result["policy"] = json.dumps(data["defaultObjectAcl"])[:600]
    except Exception:
        pass

    # Write probe — GCS uses same REST as S3 for XML API
    result["writable"]    = _probe_write(base_url, session)
    result["deletable"]   = _probe_delete(base_url, session)
    result["object_hits"] = _probe_objects(base_url, session) if probe_objects else []

    return result

def _check_azure(name: str, session, probe_objects: bool = True) -> list:
    """
    Check Azure Blob Storage — list, ACL, CORS, write, delete, object enum.
    Tries common container names + static website endpoint.
    """
    az = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
    if len(az) < 3:
        return []

    blob_base = f"https://{az}.blob.core.windows.net"

    # Fast existence probe — catches DNS failures before we try 24+ containers
    try:
        session.head(f"{blob_base}/", timeout=(2, 3))
    except Exception:
        return []  # DNS failure or connection refused = account doesn't exist

    results   = []

    for container in AZURE_CONTAINERS:
        list_url = f"{blob_base}/{container}?restype=container&comp=list"
        cont_url = f"{blob_base}/{container}"
        try:
            r = session.get(list_url, timeout=(6, 10))
        except Exception:
            continue

        if r.status_code not in (200, 403):
            continue

        readable = r.status_code == 200
        listing  = _parse_xml_listing(r.text) if readable else None

        entry = {
            "provider":    "Azure",
            "bucket":      f"{az}/{container}",
            "url":         cont_url,
            "readable":    readable,
            "writable":    None,
            "deletable":   None,
            "listing":     listing,
            "acl":         None,
            "policy":      None,
            "cors":        None,
            "versioning":  None,
            "website":     None,
            "object_hits": [],
        }

        # Container ACL (public access level)
        try:
            r = session.get(f"{cont_url}?restype=container&comp=acl", timeout=(5, 8))
            if r.status_code == 200:
                entry["acl"] = r.text[:600]
        except Exception:
            pass

        # Container properties — x-ms-blob-public-access header
        try:
            r = session.head(f"{cont_url}?restype=container", timeout=(5, 8))
            if r.status_code == 200:
                pub = r.headers.get("x-ms-blob-public-access", "")
                if pub:
                    entry["policy"] = f"x-ms-blob-public-access: {pub}"
        except Exception:
            pass

        # Write — Azure requires x-ms-blob-type header
        entry["writable"] = _probe_write(
            cont_url, session,
            extra_headers={"x-ms-blob-type": "BlockBlob",
                           "x-ms-version":   "2020-10-02"},
        )
        entry["deletable"]   = _probe_delete(cont_url, session)
        entry["object_hits"] = _probe_objects(cont_url, session) if probe_objects else []

        results.append(entry)

    # Static website endpoint (try common zones)
    for zone in ["z13", "z6", "z22", "z1"]:
        web_url = f"https://{az}.{zone}.web.core.windows.net"
        try:
            r = session.get(web_url + "/", timeout=(5, 8))
            if r.status_code == 200 and "StorageErrorCode" not in r.text:
                results.append({
                    "provider":    "Azure",
                    "bucket":      f"{az} [static website {zone}]",
                    "url":         web_url,
                    "readable":    True,
                    "writable":    _probe_write(web_url, session,
                                               extra_headers={"x-ms-blob-type": "BlockBlob"}),
                    "deletable":   None,
                    "listing":     None,
                    "acl":         None,
                    "policy":      None,
                    "cors":        None,
                    "versioning":  None,
                    "website":     web_url,
                    "object_hits": _probe_objects(web_url, session),
                })
                break
        except Exception:
            pass

    return results

def _print_bucket(r: dict):
    perm_parts = []
    if r.get("readable"):
        perm_parts.append(green("LIST"))
    else:
        perm_parts.append(dim("no-list"))
    if r.get("writable") is True:
        perm_parts.append(red("WRITE"))
    if r.get("deletable") is True:
        perm_parts.append(red("DELETE"))
    if r.get("cors"):
        perm_parts.append(yellow("CORS"))
    if r.get("versioning"):
        perm_parts.append(yellow("VERSIONING"))
    if r.get("website"):
        perm_parts.append(yellow("WEBSITE"))
    if r.get("object_hits"):
        perm_parts.append(red(f"OBJECTS({len(r['object_hits'])})"))
    perms = " ".join(perm_parts)

    with _lock:
        print(f"\n  {bold(r['provider'])}  {cyan(r['bucket'])}  [{perms}]")
        print(f"    URL: {r['url']}")

        lst = r.get("listing") or {}
        cnt = lst.get("count", 0)
        if cnt:
            trunc = " (truncated)" if lst.get("truncated") else ""
            print(f"    Objects : {cnt}{trunc}")
            if lst.get("file_types"):
                types_str = "  ".join(
                    f"{ext}({n})"
                    for ext, n in sorted(lst["file_types"].items(), key=lambda x: -x[1])[:10]
                )
                print(f"    Types   : {types_str}")
            for k in lst.get("sample_keys", [])[:6]:
                print(f"      → {k}")

        if r.get("acl"):
            print(f"    {yellow('ACL exposed')}    : {r['acl'][:150]}")
        if r.get("policy"):
            print(f"    {yellow('Policy exposed')} : {r['policy'][:150]}")
        if r.get("cors"):
            print(f"    {yellow('CORS policy')}    : {r['cors'][:150]}")
        if r.get("versioning"):
            print(f"    {yellow('Versioning')}     : {r['versioning'][:200]}")
        if r.get("website"):
            print(f"    {yellow('Static website')} : {r['website'][:150]}")
        if r.get("object_hits"):
            print(f"    {red('Readable objects (no listing needed)')}:")
            for obj in r["object_hits"]:
                print(f"      → {obj['url']}  ({obj['size']} bytes)")

def phase_buckets(domain: str, base: Path, proxies: dict | None = None,
                  skip_objects: bool = False) -> list:
    """Phase 6: Cloud bucket discovery + permission + file-type audit (S3, GCS, Azure)."""
    phase_header(6, "Cloud Bucket Discovery")

    if not HAS_REQUESTS:
        warn("requests not installed — skipping bucket scan")
        return []

    import urllib3
    urllib3.disable_warnings()

    session = requests.Session()
    session.verify = False
    if proxies:
        session.proxies = proxies

    names = _gen_bucket_names(domain)
    obj_note = "  [--no-bucket-objects: skipped]" if skip_objects else ""
    info(f"Candidates : {len(names)} bucket names  (S3 · GCS · Azure){obj_note}")

    all_findings: list = []
    lock = threading.Lock()

    probe_objs = not skip_objects

    def probe(name: str):
        local      = []
        local_lock = threading.Lock()

        def _s3():
            r = _check_s3(name, session, probe_objects=probe_objs)
            if r:
                with local_lock: local.append(r)

        def _gcs():
            r = _check_gcs(name, session, probe_objects=probe_objs)
            if r:
                with local_lock: local.append(r)

        def _azure():
            for r in _check_azure(name, session, probe_objects=probe_objs):
                with local_lock: local.append(r)

        with ThreadPoolExecutor(max_workers=3) as _ex:
            futs = [_ex.submit(_s3), _ex.submit(_gcs), _ex.submit(_azure)]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        if local:
            with lock:
                all_findings.extend(local)
                for finding in local:
                    _print_bucket(finding)

    done_count = [0]
    lk = threading.Lock()

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = [ex.submit(probe, n) for n in names]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
            with lk:
                done_count[0] += 1
                if done_count[0] % 25 == 0:
                    info(f"  {done_count[0]}/{len(names)} probed  found: {len(all_findings)}")

    out_dir = base / "buckets"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "bucket_findings.json"
    out_json.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))

    readable  = sum(1 for f in all_findings if f.get("readable"))
    writable  = sum(1 for f in all_findings if f.get("writable") is True)

    if all_findings:
        ok(f"Buckets : {bold(str(len(all_findings)))}  readable={readable}  "
           f"writable={red(str(writable)) if writable else str(writable)}")
        ok(f"Report  : {out_json}")
    else:
        info("No cloud buckets found")

    return all_findings

# ─── Phase 5 · Nuclei ─────────────────────────────────────────────────────────

def _build_nuclei_cmd(
    target_file: Path,
    template_dir: Path,
    out_txt: Path,
    out_jsonl: Path,
    *,
    user_agent: str,
    rate_limit: int,
    concurrency: int,
    extra_flags: str,
) -> list:
    import shlex
    cmd = [
        "nuclei",
        "-l",       str(target_file),
        "-t",       str(template_dir),
        "-dast",                          # REQUIRED for fuzzing-templates/ (fuzz-type)
        "-o",       str(out_txt),         # human-readable findings
        "-jle",     str(out_jsonl),       # structured JSONL findings
        "-silent",
        "-c",       str(concurrency),
        "-rl",      str(rate_limit),
        "-timeout", "10",
        "-retries", "1",
        "-fr",                            # follow redirects
        "-H",       f"User-Agent: {user_agent}",
    ]
    if extra_flags:
        cmd.extend(shlex.split(extra_flags))
    return cmd

def _nuclei_scan(
    label: str,
    target_file: Path,
    template_dir: Path,
    outdir: Path,
    *,
    user_agent: str,
    rate_limit: int,
    concurrency: int,
    extra_flags: str,
):
    if not target_file.exists() or count_lines(target_file) == 0:
        info(f"  nuclei [{label}]: skip — no targets")
        return

    if not template_dir.exists():
        warn(f"  nuclei [{label}]: template dir missing → {template_dir}")
        return

    n        = count_lines(target_file)
    out_txt  = outdir / f"nuclei_{label}.txt"
    out_jsonl = outdir / f"nuclei_{label}.jsonl"

    info(f"  nuclei [{label:<8}] → {n:>5} targets  template: {template_dir.name}/")

    cmd = _build_nuclei_cmd(
        target_file, template_dir, out_txt, out_jsonl,
        user_agent=user_agent, rate_limit=rate_limit,
        concurrency=concurrency, extra_flags=extra_flags,
    )
    rc, stdout, stderr = run(cmd, timeout=3600)

    hits = count_lines(out_txt) if out_txt.exists() else 0
    if hits:
        ok(f"  nuclei [{label}]: {hits} findings  →  {out_txt.name}")
    else:
        info(f"  nuclei [{label}]: no findings")

def phase_nuclei(
    gf_dir: Path,
    all_urls_file: Path,
    base: Path,
    patterns=None,
    user_agent=DEFAULT_UA,
    rate_limit=150,
    concurrency=25,
    extra_flags="",
):
    phase_header(5, "Nuclei Fuzzing")
    outdir = base / "nuclei"
    outdir.mkdir(parents=True, exist_ok=True)

    if not which("nuclei"):
        err("nuclei not found")
        return

    if patterns is None:
        patterns = ALL_PATTERNS

    gf_patterns   = [p for p in patterns if p in GF_NUCLEI_MAP]
    host_patterns = [p for p in patterns if p in HOST_NUCLEI_MAP]

    info(f"Templates : {NUCLEI_TEMPLATES_BASE}")
    info(f"UA        : {user_agent[:60]}{'…' if len(user_agent) > 60 else ''}")
    info(f"Rate      : {rate_limit} req/s   Concurrency: {concurrency}")

    if gf_patterns:
        info(f"GF-filtered  ({len(gf_patterns)}): {', '.join(gf_patterns)}")
    if host_patterns:
        info(f"Direct-URLs  ({len(host_patterns)}): {', '.join(host_patterns)}")

    kwargs = dict(
        user_agent=user_agent, rate_limit=rate_limit,
        concurrency=concurrency, extra_flags=extra_flags,
    )

    # GF-filtered patterns: target = gf/gf_<pattern>.txt
    for pat in gf_patterns:
        _nuclei_scan(
            pat,
            gf_dir / f"gf_{pat}.txt",
            GF_NUCLEI_MAP[pat],
            outdir,
            **kwargs,
        )

    # Host-based patterns: target = all collected URLs (no GF pre-filter)
    for pat in host_patterns:
        _nuclei_scan(
            pat,
            all_urls_file,
            HOST_NUCLEI_MAP[pat],
            outdir,
            **kwargs,
        )

# ─── Banner ───────────────────────────────────────────────────────────────────

# ─── Phase 2.5 · Subdomain Takeover Detection ────────────────────────────────

_TAKEOVER_SAFE_CODES = frozenset(range(200, 210)) | frozenset(range(300, 310))


def _extract_takeover_candidates(
    httpx_jsonl, subdomains_file: Path, outdir: Path
) -> tuple:
    """
    Builds takeover/candidates.txt: hosts with non-2xx/3xx status + no-response subdomains.
    Returns (candidates_file, n_non2xx, n_dead).

    Non-2xx/3xx hosts include 4xx (dangling CNAME → unclaimed service) and 5xx.
    No-response = in all_subdomains.txt but httpx found nothing → NXDOMAIN / conn-refused.
    Both categories are classic subdomain takeover preconditions.
    """
    live_hosts: set = set()
    non2xx: set = set()

    if httpx_jsonl and Path(httpx_jsonl).exists():
        for line in Path(httpx_jsonl).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry  = json.loads(line)
                url    = entry.get("url", "")
                status = entry.get("status_code", 0)
                if url:
                    host = urlparse(url).netloc.split(":")[0].lower()
                    if host:
                        live_hosts.add(host)
                        if status not in _TAKEOVER_SAFE_CODES:
                            non2xx.add(host)
            except json.JSONDecodeError:
                pass

    dead: set = set()
    if subdomains_file.exists():
        for sub in subdomains_file.read_text().splitlines():
            sub = sub.strip().lower()
            if sub and sub not in live_hosts:
                dead.add(sub)

    candidates = non2xx | dead
    candidates_file = outdir / "candidates.txt"
    write_lines(candidates_file, candidates)
    return candidates_file, len(non2xx), len(dead)


def _takeover_dnsx_cname(candidates_file: Path, outdir: Path):
    """dnsx CNAME resolution on candidates — dangling CNAME confirms takeover vector."""
    out = outdir / "cname_dangling.txt"
    if not which("dnsx"):
        warn("  dnsx not found — skipping CNAME check")
        return
    if count_lines(candidates_file) == 0:
        return
    info("  dnsx CNAME check ...")
    rc, stdout, _ = run(
        ["dnsx", "-l", str(candidates_file), "-cname",
         "-silent", "-t", "100"],
        timeout=300,
    )
    if rc == 0 and stdout.strip():
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        out.write_text("\n".join(lines) + "\n")
        ok(f"  dnsx CNAME: {len(lines)} dangling CNAME(s)")
    else:
        info("  dnsx CNAME: none found")


def _takeover_subjack(candidates_file: Path, outdir: Path, proxy_env=None):
    """subjack: fingerprint-based subdomain takeover detection (50+ services)."""
    out = outdir / "subjack_results.txt"
    if not which("subjack"):
        warn("  subjack not found  (go install github.com/haccer/subjack@latest)")
        return
    if count_lines(candidates_file) == 0:
        return
    info("  subjack ...")
    rc, stdout, stderr = run(
        ["subjack", "-w", str(candidates_file), "-t", "50",
         "-timeout", "30", "-o", str(out), "-ssl"],
        env_extra=proxy_env, timeout=600,
    )
    if out.exists() and out.stat().st_size > 0:
        all_lines = [l for l in out.read_text().splitlines() if l.strip()]
        suspicious = [l for l in all_lines if "[Not Vulnerable]" not in l]
        if suspicious:
            ok(f"  subjack: {len(suspicious)} potential takeover(s)  (of {len(all_lines)} checked)")
        else:
            info(f"  subjack: no findings  ({len(all_lines)} checked)")
    else:
        info("  subjack: no findings")


def _takeover_subzy(candidates_file: Path, outdir: Path, proxy_env=None):
    """subzy: modern takeover checker supporting 50+ services."""
    out = outdir / "subzy_results.txt"
    if not which("subzy"):
        warn("  subzy not found  (go install github.com/PentestPad/subzy@latest)")
        return
    if count_lines(candidates_file) == 0:
        return
    info("  subzy ...")
    rc, stdout, _ = run(
        ["subzy", "run", "--targets", str(candidates_file),
         "--concurrency", "50", "--hide-fails"],
        env_extra=proxy_env, timeout=600,
    )
    if rc == 0 and stdout.strip():
        findings = [
            l.strip() for l in stdout.splitlines()
            if "VULNERABLE" in l.upper() or ("[" in l and l.strip())
        ]
        if findings:
            out.write_text("\n".join(findings) + "\n")
            ok(f"  subzy: {len(findings)} potential takeover(s)")
            return
    info("  subzy: no findings")


def _takeover_nuclei(
    target_file: Path,
    outdir: Path,
    label: str,
    *,
    user_agent: str,
    rate_limit: int,
    concurrency: int,
    extra_flags: str,
):
    """Run nuclei takeover templates against target_file."""
    # Search common nuclei template locations in order
    _tmpl_candidates = [
        Path("/root/nuclei-templates/http/takeovers"),
        Path.home() / "nuclei-templates/http/takeovers",
        Path.home() / ".config/nuclei/templates/http/takeovers",
    ]
    tmpl = next((p for p in _tmpl_candidates if p.exists()), None)
    if tmpl is None:
        warn(f"  nuclei takeover: template dir not found (tried {[str(p) for p in _tmpl_candidates]})")
        return
    if count_lines(target_file) == 0:
        info(f"  nuclei takeover [{label}]: skip — no targets")
        return

    out_txt   = outdir / f"nuclei_takeover_{label}.txt"
    out_jsonl = outdir / f"nuclei_takeover_{label}.jsonl"
    n = count_lines(target_file)
    info(f"  nuclei takeover [{label}] → {n} targets  template: takeovers/")

    cmd = _build_nuclei_cmd(
        target_file, tmpl, out_txt, out_jsonl,
        user_agent=user_agent, rate_limit=rate_limit,
        concurrency=concurrency, extra_flags=extra_flags,
    )
    run(cmd, timeout=3600)

    hits = count_lines(out_txt) if out_txt.exists() else 0
    if hits:
        ok(f"  nuclei takeover [{label}]: {hits} finding(s)  →  {out_txt.name}")
    else:
        info(f"  nuclei takeover [{label}]: no findings")


def phase_takeover(
    subdomains_file: Path,
    httpx_jsonl,
    base: Path,
    *,
    user_agent: str = DEFAULT_UA,
    rate_limit: int = 150,
    concurrency: int = 25,
    extra_flags: str = "",
    proxy_env=None,
):
    """
    Phase 2.5 — Subdomain takeover detection.

    Candidates = subdomains returning non-2xx/3xx codes + subdomains that got
    no httpx response at all.  Tools run against candidates:
      • dnsx  — CNAME chain resolution (dangling CNAME confirmation)
      • subjack — fingerprint-based, 50+ services
      • subzy  — modern alternative, 50+ services
      • nuclei takeover templates — candidates pass (priority)
      • nuclei takeover templates — full subdomain list pass
        (some services return HTTP 200 even when unclaimed, e.g. GitHub Pages)
    """
    phase_header("2.5", "Subdomain Takeover Detection")
    outdir = base / "takeover"
    outdir.mkdir(parents=True, exist_ok=True)

    candidates_file, n_non2xx, n_dead = _extract_takeover_candidates(
        httpx_jsonl, subdomains_file, outdir
    )
    n_cands = count_lines(candidates_file)
    info(f"Candidates : {n_cands}  (non-2xx/3xx={n_non2xx}  no-response={n_dead})")

    if n_cands == 0:
        info("No takeover candidates — skipping tools")
        return

    # Specialized tools run in parallel against candidates
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = [
            ex.submit(_takeover_dnsx_cname, candidates_file, outdir),
            ex.submit(_takeover_subjack, candidates_file, outdir, proxy_env),
            ex.submit(_takeover_subzy, candidates_file, outdir, proxy_env),
        ]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                warn(f"  takeover tool error: {e}")

    # Nuclei: two passes — candidates first, then all subdomains
    if not which("nuclei"):
        warn("  nuclei not found — skipping nuclei takeover scan")
        return

    nuclei_kwargs = dict(
        user_agent=user_agent, rate_limit=rate_limit,
        concurrency=concurrency, extra_flags=extra_flags,
    )
    _takeover_nuclei(candidates_file, outdir, "candidates", **nuclei_kwargs)
    if subdomains_file.exists() and count_lines(subdomains_file) > 0:
        _takeover_nuclei(subdomains_file, outdir, "all", **nuclei_kwargs)


BANNER = f"""{C.CY}{C.BD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RS}
{C.DM}  subdomain → httpx → urls → gf → nuclei → buckets   v1.3{C.RS}
"""

# ─── Summary ──────────────────────────────────────────────────────────────────

def print_summary(base: Path):
    phase_header("✓", "Complete")
    print(f"\n{bold('Output:')} {base}\n")

    layout = [
        ("subdomains/all_subdomains.txt",   "All unique subdomains"),
        ("httpx/httpx_live.txt",            "Live hosts (full URL)"),
        ("hosts/live_hosts.txt",            "Live hostnames — domains only, no scheme"),
        ("hosts/alive.txt",                 "Alive hosts — multi-port scan"),
        ("ips/unique_ips.txt",              "Unique resolved IPs"),
        ("urls/all_urls.txt",               "All collected URLs"),
    ]
    for rel, label in layout:
        p = base / rel
        n = count_lines(p) if p.exists() else 0
        tag = green(str(n).rjust(6)) if n > 0 else dim("     0")
        print(f"  {tag}  {cyan(rel.split('/')[0]+'/'):15}  {dim(label)}")

    # Fingerprint / CMS
    fp_dir = base / "fingerprint"
    fp_summary = fp_dir / "tech_summary.json"
    if fp_summary.exists():
        try:
            fp = json.loads(fp_summary.read_text())
            breakdown = fp.get("cms_breakdown", {})
            if breakdown:
                print(f"\n  {cyan('fingerprint/')}  CMS/framework breakdown:")
                for cms, count in sorted(breakdown.items(), key=lambda x: -x[1]):
                    marker = yellow("⚑") if cms in _SECURITY_CMS else " "
                    tag = red(str(count).rjust(6)) if cms in _SECURITY_CMS else green(str(count).rjust(6))
                    print(f"    {tag}  {marker} {cms}")
            else:
                print(f"\n  {dim('       0')}  {cyan('fingerprint/'):15}  {dim('no CMS detected')}")
        except Exception:
            pass

    # Buckets
    buckets_file = base / "buckets" / "bucket_findings.json"
    if buckets_file.exists():
        try:
            buckets = json.loads(buckets_file.read_text())
            nb = len(buckets)
            nr = sum(1 for b in buckets if b.get("readable"))
            nw = sum(1 for b in buckets if b.get("writable") is True)
            tag = red(str(nb).rjust(6)) if nb > 0 else dim("     0")
            print(f"  {tag}  {cyan('buckets/'):15}  {dim(f'found={nb} readable={nr} writable={nw}')}")
        except Exception:
            pass

    print()
    print(f"  {cyan('gf/')}  GF matches (pre-filter for nuclei):")
    for pat in GF_PATTERNS:
        p = base / "gf" / f"gf_{pat}.txt"
        n = count_lines(p) if p.exists() else 0
        tag = green(str(n).rjust(6)) if n > 0 else dim("     0")
        print(f"    {tag}  {pat}")

    # Takeover
    takeover_dir = base / "takeover"
    if takeover_dir.exists():
        cands = takeover_dir / "candidates.txt"
        n_cands = count_lines(cands) if cands.exists() else 0
        tag = yellow(str(n_cands).rjust(6)) if n_cands > 0 else dim("     0")
        print(f"  {tag}  {cyan('takeover/'):15}  {dim('candidates (non-2xx/3xx + dead)')}")
        for fname, label in [
            ("cname_dangling.txt",              "dnsx CNAME dangling"),
            ("subzy_results.txt",               "subzy findings"),
            ("nuclei_takeover_candidates.txt",  "nuclei/candidates"),
            ("nuclei_takeover_all.txt",         "nuclei/all-subs"),
        ]:
            p = takeover_dir / fname
            n = count_lines(p) if p.exists() else 0
            if n > 0:
                print(f"    {red(str(n).rjust(8))}  {dim(label)}")
        # subjack: count only non-"[Not Vulnerable]" lines
        sp = takeover_dir / "subjack_results.txt"
        if sp.exists() and sp.stat().st_size > 0:
            all_sj = [l for l in sp.read_text().splitlines() if l.strip()]
            hits_sj = [l for l in all_sj if "[Not Vulnerable]" not in l]
            if hits_sj:
                print(f"    {red(str(len(hits_sj)).rjust(8))}  {dim(f'subjack findings  (of {len(all_sj)} checked)')}")
            else:
                print(f"    {dim('       0')}  {dim(f'subjack findings  ({len(all_sj)} checked, none vulnerable)')}")

    print()
    print(f"  {cyan('nuclei/')}  Findings  (.txt human · .jsonl structured):")
    for pat in ALL_PATTERNS:
        p = base / "nuclei" / f"nuclei_{pat}.txt"
        n = count_lines(p) if p.exists() else 0
        tag = (red if n > 0 else dim)(str(n).rjust(6))
        source = dim("(gf)  ") if pat in GF_PATTERNS else dim("(url) ")
        print(f"    {tag}  {source}{pat}")
    print()

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Full recon pipeline: subdomain → httpx → urls → gf → nuclei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 recon.py example.com
  python3 recon.py example.com --tor -o /tmp/recon
  python3 recon.py example.com --skip-nuclei
  python3 recon.py example.com --nuclei-patterns xss sqli crlf xxe
  python3 recon.py example.com --user-agent "Mozilla/5.0 (compatible; pentest)"
  python3 recon.py example.com --rate-limit 50 --concurrency 10
  python3 recon.py example.com --nuclei-flags '-H "Authorization: Bearer TOKEN" -proxy http://127.0.0.1:8080'
  python3 recon.py example.com --subdomains-file subs.txt --skip-enum
        """,
    )

    p.add_argument("domain", help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", default="./recon_output",
                   help="Base output directory (default: ./recon_output)")

    # API keys / tokens
    g = p.add_argument_group("tokens")
    g.add_argument("--chaos-key",     default=os.environ.get("CHAOS_KEY"),
                   help="ProjectDiscovery CHAOS API key (or set $CHAOS_KEY)")
    g.add_argument("--github-token",  default=os.environ.get("GITHUB_TOKEN"),
                   help="GitHub PAT for github-subdomains (or set $GITHUB_TOKEN)")

    # TOR
    g2 = p.add_argument_group("proxy")
    g2.add_argument("--tor", action="store_true",
                    help="Route Python HTTP calls through TOR (socks5h://127.0.0.1:9050)")

    # Resume / override
    g3 = p.add_argument_group("input override")
    g3.add_argument("--subdomains-file",
                    help="Use existing subdomains file (implies --skip-enum)")

    # DNS brute force (off by default)
    g_bf = p.add_argument_group("dns brute force  [off by default]")
    g_bf.add_argument("--brute-force", action="store_true",
                      help="Enable DNS brute force (Phase 1.5) — runs after passive enum")
    g_bf.add_argument("--brute-wordlist",
                      default=str(DEFAULT_BRUTEFORCE_WORDLIST),
                      metavar="FILE",
                      help=f"Wordlist for brute force (default: {DEFAULT_BRUTEFORCE_WORDLIST.name})")

    # Skip flags
    g4 = p.add_argument_group("skip phases")
    g4.add_argument("--skip-enum",          action="store_true", help="Skip subdomain enumeration")
    g4.add_argument("--skip-httpx",         action="store_true", help="Skip httpx validation")
    g4.add_argument("--skip-fingerprint",   action="store_true", help="Skip technology/CMS fingerprinting (Phase 2c)")
    g4.add_argument("--skip-waf",           action="store_true", help="Skip WAF detection (Phase 2d)")
    g4.add_argument("--skip-takeover",      action="store_true", help="Skip subdomain takeover detection (Phase 2.5)")
    g4.add_argument("--skip-urls",          action="store_true", help="Skip URL collection")
    g4.add_argument("--skip-js-endpoints",  action="store_true", help="Skip JS endpoint extraction (Phase 3.5)")
    g4.add_argument("--skip-gf",            action="store_true", help="Skip GF pattern matching")
    g4.add_argument("--skip-nuclei",        action="store_true", help="Skip nuclei scanning")
    g4.add_argument("--skip-buckets",       action="store_true", help="Skip cloud bucket discovery")
    g4.add_argument("--buckets-only",       action="store_true",
                    help="Run only the bucket discovery phase — skip all other phases")
    g4.add_argument("--no-bucket-objects",  action="store_true",
                    help="Skip sensitive object enumeration in bucket scan (faster)")

    # Nuclei options
    g5 = p.add_argument_group("nuclei")
    g5.add_argument("--nuclei-patterns", nargs="+", choices=ALL_PATTERNS, default=ALL_PATTERNS,
                    metavar="PATTERN",
                    help=(
                        f"Patterns to scan (default: all). "
                        f"GF-filtered: {', '.join(GF_PATTERNS)}. "
                        f"Direct-URL (no GF): {', '.join(HOST_PATTERNS)}"
                    ))
    g5.add_argument("--user-agent", default=DEFAULT_UA,
                    metavar="UA",
                    help="User-Agent header sent by nuclei (default: Chrome/124 desktop)")
    g5.add_argument("--rate-limit", type=int, default=150, metavar="N",
                    help="Nuclei max requests/second (default: 150)")
    g5.add_argument("--concurrency", type=int, default=25, metavar="N",
                    help="Nuclei template concurrency (default: 25)")
    g5.add_argument("--nuclei-flags", default="",
                    help="Extra raw flags forwarded verbatim to every nuclei call")

    return p

def main():
    # Source ~/.bashrc before argparse so --chaos-key / --github-token
    # defaults from os.environ already reflect the .bashrc exports.
    _source_bashrc()

    args = build_parser().parse_args()
    print(BANNER)

    # ── Proxies ──────────────────────────────────────────────────────────────
    proxies   = None
    proxy_env = None
    if args.tor:
        tor = "socks5h://127.0.0.1:9050"
        proxies   = {"http": tor, "https": tor}
        proxy_env = {"HTTP_PROXY": tor, "HTTPS_PROXY": tor,
                     "http_proxy": tor, "https_proxy": tor}
        info(f"TOR proxy: {tor}")
        if not HAS_REQUESTS:
            warn("requests not installed — TOR proxy won't apply to Python HTTP calls")

    # ── Output directory ──────────────────────────────────────────────────────
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(args.output) / f"{args.domain}_{ts}"
    base.mkdir(parents=True, exist_ok=True)

    info(f"Target : {bold(args.domain)}")
    info(f"Output : {bold(str(base))}")

    # ── Buckets-only shortcut ─────────────────────────────────────────────────
    if args.buckets_only:
        info("Mode: --buckets-only  (all other phases skipped)")
        phase_buckets(args.domain, base, proxies=proxies if args.tor else None)
        sys.exit(0)

    # ── Phase 1 · Subdomain Enumeration ──────────────────────────────────────
    if args.subdomains_file:
        subdomains_file = Path(args.subdomains_file)
        if not subdomains_file.exists():
            err(f"Subdomains file not found: {subdomains_file}")
            sys.exit(1)
        ok(f"Using provided file: {subdomains_file} ({count_lines(subdomains_file)} entries)")
    elif args.skip_enum:
        subdomains_file = base / "subdomains" / "all_subdomains.txt"
        warn("Subdomain enumeration skipped")
    else:
        subdomains_file = phase_enum(args.domain, base, args, proxies)

    # ── Phase 1.5 · DNS Brute Force (opt-in) ─────────────────────────────────
    if args.brute_force:
        subdomains_file = phase_bruteforce(
            args.domain, base, Path(args.brute_wordlist)
        )
    else:
        info("DNS brute force skipped  (pass --brute-force to enable)")

    # ── Phase 2 · httpx Validation + host/IP extraction ──────────────────────
    if args.skip_httpx:
        warn("httpx validation skipped")
        httpx_jsonl   = base / "httpx" / "httpx_results.jsonl"
        live_urls_file = base / "httpx" / "httpx_live.txt"
    else:
        httpx_jsonl, live_urls_file = phase_httpx(subdomains_file, base)
        if httpx_jsonl:
            phase_extract(httpx_jsonl, base)
            hosts_file = base / "hosts" / "live_hosts.txt"
            if hosts_file.exists() and count_lines(hosts_file) > 0:
                phase_port_scan(hosts_file, base)

    # ── Phase 2c · Technology Fingerprinting ─────────────────────────────────
    if not args.skip_fingerprint:
        phase_fingerprint(
            httpx_jsonl,
            base,
            proxies=proxies if args.tor else None,
        )
    else:
        warn("Fingerprinting skipped  (--skip-fingerprint)")

    # ── Phase 2d · WAF Detection ──────────────────────────────────────────────
    if not args.skip_waf:
        _waf_input = live_urls_file if (live_urls_file and live_urls_file.exists()) else None
        if _waf_input:
            phase_waf(_waf_input, base, proxy_env=proxy_env)
        else:
            warn("WAF detection skipped — no live URLs available")
    else:
        warn("WAF detection skipped  (--skip-waf)")

    # ── Phase 2.5 · Subdomain Takeover Detection ──────────────────────────────
    if not args.skip_takeover:
        phase_takeover(
            subdomains_file,
            httpx_jsonl,
            base,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            extra_flags=args.nuclei_flags,
            proxy_env=proxy_env,
        )
    else:
        warn("Takeover detection skipped  (--skip-takeover)")

    # Fallback: if no live hosts, use subdomains as crawl input
    if not live_urls_file or not live_urls_file.exists() or count_lines(live_urls_file) == 0:
        live_urls_file = subdomains_file

    # ── Phase 3 · URL Collection ──────────────────────────────────────────────
    if args.skip_urls:
        warn("URL collection skipped")
        all_urls_file = base / "urls" / "all_urls.txt"
    else:
        all_urls_file = phase_urls(
            args.domain, live_urls_file, base, args, proxies, proxy_env
        )

    # ── Phase 3.5 · JS Endpoint Extraction ───────────────────────────────────
    if not args.skip_js_endpoints:
        phase_js_endpoints(
            all_urls_file,
            base,
            domain=args.domain,
            proxies=proxies if args.tor else None,
        )
    else:
        warn("JS endpoint extraction skipped  (--skip-js-endpoints)")

    # ── Phase 4 · GF Pattern Matching ─────────────────────────────────────────
    if args.skip_gf:
        warn("GF pattern matching skipped")
        gf_dir = base / "gf"
    else:
        gf_dir = phase_gf(all_urls_file, base)

    # ── Phase 5 · Nuclei ──────────────────────────────────────────────────────
    if not args.skip_nuclei:
        phase_nuclei(
            gf_dir,
            all_urls_file,
            base,
            patterns=args.nuclei_patterns,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            extra_flags=args.nuclei_flags,
        )
    else:
        warn("Nuclei scanning skipped")

    # ── Phase 6 · Cloud Bucket Discovery ─────────────────────────────────────
    if not args.skip_buckets:
        phase_buckets(
            args.domain, base,
            proxies=proxies if args.tor else None,
            skip_objects=args.no_bucket_objects,
        )
    else:
        warn("Bucket discovery skipped  (--skip-buckets)")

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(base)


if __name__ == "__main__":
    main()
