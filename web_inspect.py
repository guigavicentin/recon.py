#!/usr/bin/env python3
"""
web_inspect.py — Deep web surface analysis  v1.0

Phases:
  0   Header Audit    GET each live host → missing security headers · info disclosure
  1   CSP Analysis    Content-Security-Policy directive-level bypass classification
  2   Cookie Audit    Set-Cookie flags (Secure · HttpOnly · SameSite)
  3   DNS Security    SPF · DMARC · DKIM · AXFR · CAA · MX
  4   Tech → CVE      httpx tech-detect field → local DB + optional NVD API
  5   Favicon Hash    MurmurHash3 → known product fingerprint database
  6   Content Recon   robots.txt · sitemap.xml · /.well-known/
  7   ASN / Reverse   CIDR ranges owned by target + co-hosted domains
  8   TLS / SAN       Certificate SAN → hidden hostnames · TLS config
  9   GraphQL         Introspection query → full schema dump
  10  OpenAPI/Swagger Spec discovery + endpoint/auth extraction
  11  403 Bypass      4xx paths → header · path · method bypass techniques
  12  Cache Probe     Unkeyed header injection (X-Forwarded-Host · X-Original-URL)
  13  WebSocket       ws:// wss:// extraction + open-auth probe
  14  CI/CD Exposure  Jenkins · Spring Actuator · phpinfo · Laravel Telescope · Adminer
  15  Next.js Probe   BUILD_ID → /_next/data/ JSON endpoint harvest
  16  Exploit Mapper  CVEs detectados → tools/cve/<CVE-ID>/ (exploits locais)

Input (auto-detected from --recon-dir):
  httpx/httpx_results.jsonl    → tech + status codes (for phases 4, 9, 15)
  httpx/httpx_live.txt         → live host URLs for active probing
  ips/unique_ips.txt           → IPs for ASN / reverse lookups
  urls/all_urls.txt            → URL pool for WebSocket extraction
  [secret-dir]/js/             → downloaded JS files for WebSocket extraction

Usage:
  python3 web_inspect.py --recon-dir recon_output/example.com_20260922/ --domain example.com
  python3 web_inspect.py --recon-dir . --tor --skip-dns --skip-nvd
  python3 web_inspect.py --hosts hosts.txt --ips ips.txt --domain example.com -o ./out
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Constants ────────────────────────────────────────────────────────────────

RAPTOR_DIR    = Path(os.environ.get("RAPTOR_DIR", Path(__file__).resolve().parent.parent))
RAPTOR_CVE_DIR = RAPTOR_DIR / "tools" / "cve"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ─── Security Header Definitions ──────────────────────────────────────────────

REQUIRED_HEADERS = [
    {
        "name":    "Strict-Transport-Security",
        "sev":     "medium",
        "missing": "HSTS absent — allows HTTP downgrade / MITM",
        "check":   lambda v: "max-age" in v.lower(),
        "bad":     "HSTS present but max-age missing",
    },
    {
        "name":    "Content-Security-Policy",
        "sev":     "medium",
        "missing": "CSP absent — inline XSS fully browser-dependent",
        "check":   None,  # analyzed separately
    },
    {
        "name":    "X-Frame-Options",
        "sev":     "medium",
        "missing": "X-Frame-Options absent — clickjacking possible (unless frame-ancestors in CSP)",
        "check":   lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "bad":     "X-Frame-Options is ALLOWALL",
    },
    {
        "name":    "X-Content-Type-Options",
        "sev":     "low",
        "missing": "X-Content-Type-Options absent — MIME sniffing enabled",
        "check":   lambda v: v.lower() == "nosniff",
        "bad":     "X-Content-Type-Options is not 'nosniff'",
    },
    {
        "name":    "Referrer-Policy",
        "sev":     "low",
        "missing": "Referrer-Policy absent — full URL sent in Referer header to third parties",
        "check":   lambda v: v.lower() not in ("unsafe-url", ""),
    },
    {
        "name":    "Permissions-Policy",
        "sev":     "low",
        "missing": "Permissions-Policy absent — camera, microphone, geolocation APIs unrestricted",
        "check":   None,
    },
    {
        "name":    "Cross-Origin-Opener-Policy",
        "sev":     "low",
        "missing": "COOP absent — cross-origin window access possible (Spectre side-channel)",
        "check":   lambda v: v.lower() in ("same-origin", "same-origin-allow-popups"),
        "bad":     "COOP set but not same-origin",
    },
]

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
    "X-Application-Context",
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-CF-Powered-By",
    "X-Backend-Server",
    "X-OWA-Version",
    "X-Cluster-Client-IP",
    "Via",
]

CORS_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"]

# ─── CSP Bypass Database ──────────────────────────────────────────────────────

# Domains in script-src with known JSONP / callback bypass endpoints
CSP_BYPASS_DOMAINS = {
    "ajax.googleapis.com":       "AngularJS CDN → XSS via ng-csp bypass",
    "accounts.google.com":       "JSONP /o/oauth2/revoke?token=payload",
    "maps.googleapis.com":       "JSONP /maps/api/js?callback=payload",
    "cdn.jsdelivr.net":          "AngularJS / RequireJS JSONP via npm packages",
    "unpkg.com":                 "AngularJS / RequireJS JSONP via npm packages",
    "cdnjs.cloudflare.com":      "AngularJS / RequireJS JSONP",
    "www.google-analytics.com":  "Redirect chain endpoint",
    "www.googletagmanager.com":  "Multiple redirect endpoints",
    "*.googleapis.com":          "Multiple JSONP / callback endpoints",
}

CSP_BAD_DIRECTIVES = {
    "'unsafe-inline'": ("high",   "unsafe-inline in script-src → inline XSS fully allowed"),
    "'unsafe-eval'":   ("high",   "unsafe-eval in script-src → eval() / Function() XSS allowed"),
    "data:":           ("high",   "data: URI in script-src → XSS via data:text/html payloads"),
    "'*'":             ("high",   "Wildcard * in CSP directive → protection fully bypassed"),
    "http:":           ("medium", "http: scheme in script-src → scripts loadable over cleartext"),
}

# ─── Favicon Fingerprint Database ─────────────────────────────────────────────
# Key = str(signed_murmur3_hash) ; Val = (product, severity)

FAVICON_HASHES = {
    "116323821":    ("Fortinet FortiGate",          "high"),
    "-1627843870":  ("Cisco IOS",                   "medium"),
    "999357577":    ("pfSense",                     "medium"),
    "-1350449751":  ("VMware ESXi",                 "high"),
    "1781835534":   ("VMware vSphere",              "high"),
    "1265477421":   ("Jenkins",                     "high"),
    "-663851537":   ("Grafana",                     "medium"),
    "1086690706":   ("Grafana",                     "medium"),
    "1278323757":   ("GitLab",                      "medium"),
    "-1507694618":  ("GitLab",                      "medium"),
    "2143727925":   ("Jira",                        "medium"),
    "-305678735":   ("Confluence",                  "medium"),
    "1609024786":   ("Jupyter Notebook",            "high"),
    "-1806754512":  ("Kubernetes Dashboard",        "critical"),
    "-1529491764":  ("MinIO",                       "high"),
    "1263449440":   ("pgAdmin",                     "high"),
    "1148909500":   ("Adminer",                     "high"),
    "-356895933":   ("OpenVPN",                     "medium"),
    "3264751924":   ("Nagios",                      "medium"),
    "1688958483":   ("Zabbix",                      "medium"),
    "1498866209":   ("Prometheus",                  "medium"),
    "-1545528305":  ("Kibana",                      "medium"),
    "1042203457":   ("Sonatype Nexus",              "high"),
    "-1043558498":  ("JFrog Artifactory",           "high"),
    "-1357473756":  ("SonarQube",                   "medium"),
    "-505078995":   ("Apache Tomcat",               "medium"),
    "-1150455604":  ("Spring Boot",                 "medium"),
    "1031877440":   ("Traefik",                     "medium"),
    "-1185047666":  ("Portainer",                   "high"),
    "16417437":     ("RabbitMQ",                    "high"),
    "1604688047":   ("IIS Default Page",            "low"),
    "-1438924180":  ("Nginx Default Page",          "low"),
    "-1389251270":  ("Apache Default Page",         "low"),
    "1398660507":   ("phpMyAdmin",                  "high"),
    "-1306506025":  ("Plesk",                       "medium"),
    "1087263781":   ("cPanel",                      "medium"),
    "-2126920351":  ("Roundcube Webmail",           "medium"),
    "774876477":    ("Webmin",                      "high"),
    "-1043552951":  ("Hashicorp Vault",             "high"),
    "-1356292421":  ("Harbor Registry",             "high"),
    "1627538783":   ("Rancher",                     "high"),
}

# ─── GraphQL ──────────────────────────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2", "/query", "/gql",
    "/graphiql", "/playground", "/api/v1/graphql", "/api/v2/graphql",
    "/graphql/api", "/api/graph", "/graphql-api",
]

GRAPHQL_INTROSPECTION = (
    '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}'
    'types{name kind description fields(includeDeprecated:true)'
    '{name description type{name kind ofType{name kind}}}}}}"}'
)

# ─── OpenAPI / Swagger ────────────────────────────────────────────────────────

SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/docs/swagger.json", "/docs/openapi.json",
    "/.well-known/openapi.json", "/redoc.json",
    "/swagger-ui.html", "/swagger-ui/",
    "/api/swagger-ui.html", "/actuator/openapi",
]

# ─── 403 Bypass ───────────────────────────────────────────────────────────────

BYPASS_HEADER_SETS = [
    {"X-Original-URL":            None},      # path value injected at runtime
    {"X-Rewrite-URL":             None},
    {"X-Forwarded-For":           "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP":          "127.0.0.1"},
    {"X-Remote-IP":               "127.0.0.1"},
    {"X-Client-IP":               "127.0.0.1"},
    {"X-Real-IP":                 "127.0.0.1"},
    {"X-Host":                    "localhost"},
    {"Forwarded":                  "for=127.0.0.1"},
]

BYPASS_PATH_TRANSFORMS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: p.replace("/", "//", 1),
    lambda p: "/" + p.lstrip("/").replace("/", "/%2f", 1),
    lambda p: "/." + p.lstrip("/"),
    lambda p: p + "%20",
    lambda p: p.upper(),
    lambda p: p.rstrip("/") + "..;/",          # nginx alias + Tomcat bypass
    lambda p: p.replace("/", "%252f", 1),       # double URL-encode (WAF bypass)
]

# Patterns that indicate a generic application/server error page rather than
# real protected content. Bypass responses matching these are real (path rewrite
# works) but low-impact — nothing useful is exposed.
_BYPASS_ERROR_PATTERNS = [
    "an error has occurred",
    "has been logged by our system",
    "application error",
    "sorry, something went wrong",
    "an unexpected error",
    "the page cannot be displayed",
    "500 internal server error",
    "service unavailable",
    "bad gateway",
    # Salesforce Marketing Cloud / ExactTarget
    "the page you have requested is unavailable",
    "problem loading page",
    "content for this link may no longer be available",
    # Generic platform errors
    "this page isn't working",
    "access denied",
    "403 forbidden",
    "page not found",
    "404 not found",
]

# ─── Cache Poison Probe ───────────────────────────────────────────────────────

CACHE_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Forwarded-For",
]

CACHE_CANARY = "cache-probe-raptor-xcheck.invalid"

# ─── CI/CD / Admin Paths ──────────────────────────────────────────────────────

# Canary path used to detect catch-all / SPA hosts (must never exist on a real server)
_CICD_CANARY = "/_raptor_nonexistent_canary_a1b2c3d4e5"

# Paths whose real responses must be application/json; text/html = SPA catch-all or error
_CICD_JSON_PATHS = {
    "/jenkins/api/json",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/configprops", "/actuator/httptrace",
    "/actuator/threaddump", "/actuator/heapdump",
    "/_cat/indices", "/_cluster/health", "/_nodes",
    "/consul/v1/catalog/services", "/consul/v1/status/leader",
    "/api/v1/namespaces",
}

# Keywords that must appear in the body for certain high-value HTML paths
_CICD_BODY_SIGNATURES = {
    "/jenkins/":        ["dashboard", "hudson", "jenkins"],
    "/.jenkins/":       ["hudson", "jenkins"],
    "/adminer.php":     ["adminer", "login", "database"],
    "/adminer":         ["adminer", "login", "database"],
    "/phpmyadmin/":     ["phpmyadmin", "pma_", "mysql"],
    "/phpMyAdmin/":     ["phpmyadmin", "pma_", "mysql"],
    "/pma/":            ["phpmyadmin", "pma_", "mysql"],
    "/phpinfo.php":     ["php version", "phpinfo"],
    "/info.php":        ["php version", "phpinfo"],
    "/.git/config":     ["[core]", "[remote"],
    "/.git/HEAD":       ["ref:", "master", "main"],
    "/web.config":      ["<configuration>", "system.web"],
    "/wp-login.php":    ["wp-login", "wordpress", "log in"],
    "/wp-admin/":       ["wordpress", "dashboard", "admin"],
    "/kibana/":         ["kibana"],
    "/app/kibana":      ["kibana"],
    "/minio/":          ["minio", "buckets"],
}

CICD_PATHS = [
    ("/jenkins/",                        "Jenkins",                "critical"),
    ("/jenkins/api/json",                "Jenkins API",            "critical"),
    ("/.jenkins/",                       "Jenkins config dir",     "critical"),
    ("/actuator",                        "Spring Actuator root",   "high"),
    ("/actuator/env",                    "Spring Actuator /env",   "critical"),
    ("/actuator/health",                 "Spring Actuator health", "medium"),
    ("/actuator/mappings",               "Spring Actuator map",    "high"),
    ("/actuator/beans",                  "Spring Actuator beans",  "high"),
    ("/actuator/configprops",            "Spring Actuator config", "critical"),
    ("/actuator/httptrace",              "Spring HTTP trace",      "high"),
    ("/actuator/threaddump",             "Spring thread dump",     "medium"),
    ("/actuator/heapdump",               "Spring heap dump",       "critical"),
    ("/_profiler",                       "Symfony profiler",       "high"),
    ("/_profiler/phpinfo",               "Symfony phpinfo",        "high"),
    ("/telescope",                       "Laravel Telescope",      "high"),
    ("/telescope/api/requests",          "Laravel Telescope API",  "high"),
    ("/horizon",                         "Laravel Horizon",        "high"),
    ("/_debugbar/open",                  "PHP Debugbar",           "high"),
    ("/phpinfo.php",                     "phpinfo()",              "high"),
    ("/info.php",                        "phpinfo()",              "high"),
    ("/test.php",                        "PHP test file",          "medium"),
    ("/adminer.php",                     "Adminer DB UI",          "critical"),
    ("/adminer",                         "Adminer DB UI",          "critical"),
    ("/phpmyadmin/",                     "phpMyAdmin",             "critical"),
    ("/phpMyAdmin/",                     "phpMyAdmin",             "critical"),
    ("/pma/",                            "phpMyAdmin",             "critical"),
    ("/server-status",                   "Apache mod_status",      "medium"),
    ("/server-info",                     "Apache mod_info",        "medium"),
    ("/nginx_status",                    "Nginx status",           "low"),
    ("/.gitlab-ci.yml",                  "GitLab CI config",       "medium"),
    ("/Jenkinsfile",                     "Jenkinsfile",            "medium"),
    ("/.travis.yml",                     "Travis CI config",       "medium"),
    ("/.circleci/config.yml",            "CircleCI config",        "medium"),
    ("/bitbucket-pipelines.yml",         "Bitbucket CI config",    "medium"),
    ("/sonar-project.properties",        "SonarQube config",       "low"),
    ("/wp-cron.php",                     "WordPress cron",         "low"),
    ("/xmlrpc.php",                      "WordPress XMLRPC",       "medium"),
    ("/.git/config",                     "Git config exposed",     "high"),
    ("/.git/HEAD",                       "Git HEAD exposed",       "high"),
    ("/web.config",                      "IIS web.config",         "high"),
    ("/.DS_Store",                       "macOS .DS_Store",        "low"),
    ("/crossdomain.xml",                 "Flash crossdomain",      "low"),
    ("/clientaccesspolicy.xml",          "Silverlight policy",     "low"),
    # WordPress
    ("/wp-login.php",                    "WordPress Login",        "medium"),
    ("/wp-admin/",                       "WordPress Admin",        "high"),
    # Elasticsearch
    ("/_cat/indices",                    "Elasticsearch indices",  "critical"),
    ("/_cluster/health",                 "Elasticsearch health",   "high"),
    ("/_nodes",                          "Elasticsearch nodes",    "high"),
    # Kibana
    ("/kibana/",                         "Kibana Dashboard",       "high"),
    ("/app/kibana",                      "Kibana App",             "high"),
    # MinIO
    ("/minio/",                          "MinIO Console",          "high"),
    ("/minio/health/live",               "MinIO health",           "medium"),
    # HashiCorp Consul
    ("/consul/v1/catalog/services",      "Consul service catalog", "critical"),
    ("/consul/v1/status/leader",         "Consul status",          "high"),
    # Kubernetes API (sometimes exposed on 80/443)
    ("/api/v1/namespaces",               "Kubernetes API",         "critical"),
    ("/readyz",                          "K8s readiness probe",    "medium"),
]

# ─── DNS DKIM Selectors ───────────────────────────────────────────────────────

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2", "k3",
    "selector1", "selector2", "email", "smtp", "mta", "s1", "s2",
    "sendgrid", "mailchimp", "mandrill", "ses", "postmark", "sparkpost",
    "2024", "2025", "2026", "20230101", "20240101",
]

# ─── Local Tech → CVE Database ────────────────────────────────────────────────
# Format: tech_name_lower → list of (check_expr, cve_or_None, cvss, description)
# check_expr: "startswith:X" | "eq:X" | "lt:X.Y.Z" | "contains:X"

TECH_CVE_LOCAL = {
    "php": [
        ("startswith:5.",    None,              8.0, "PHP 5.x EOL — no security patches since 2019"),
        ("startswith:7.0",   None,              7.5, "PHP 7.0 EOL since December 2019"),
        ("startswith:7.1",   None,              7.5, "PHP 7.1 EOL since December 2019"),
        ("startswith:7.2",   None,              7.5, "PHP 7.2 EOL since November 2020"),
        ("startswith:7.3",   None,              7.5, "PHP 7.3 EOL since December 2021"),
        ("eq:8.1.0",         "CVE-2022-31626",  8.8, "password_hash() buffer overflow → potential RCE"),
    ],
    "jquery": [
        ("lt:3.5.0",         "CVE-2020-11022",  6.1, "XSS via .html()/.load()/.append()"),
        ("lt:3.5.0",         "CVE-2020-11023",  6.1, "XSS via .html() passing <option> elements"),
        ("lt:1.12.4",        "CVE-2015-9251",   6.1, "XSS via selector in jQuery.htmlPrefilter"),
    ],
    "wordpress": [
        ("lt:6.4.3",         "CVE-2023-51374",  6.4, "Stored XSS in WordPress core"),
        ("lt:6.3.2",         "CVE-2023-2745",   6.4, "Directory traversal in WP_Theme"),
    ],
    "drupal": [
        ("lt:10.1.5",        "CVE-2023-31251",  8.1, "RCE via deserialization"),
        ("startswith:7.",    None,              9.8, "Drupal 7 EOL — Drupalgeddon-class RCE exposure"),
    ],
    "joomla!": [
        ("lt:5.0.3",         "CVE-2024-21726",  9.8, "XSS → RCE via com_fields component"),
        ("lt:4.4.3",         "CVE-2023-23752",  5.3, "Unauthenticated info disclosure via API"),
    ],
    "apache tomcat": [
        ("startswith:8.0",   None,              8.0, "Tomcat 8.0 EOL — unfixed security issues"),
        ("startswith:7.",    None,              9.0, "Tomcat 7 EOL — CVE-2020-9484 deserialization RCE"),
    ],
    "spring": [
        ("eq:5.3.18",        "CVE-2022-22965",  9.8, "Spring4Shell — RCE via DataBinder"),
        ("eq:5.3.17",        "CVE-2022-22965",  9.8, "Spring4Shell — RCE via DataBinder"),
        ("lt:5.3.20",        "CVE-2022-22965",  9.8, "Spring4Shell (verify exact version)"),
    ],
    "log4j": [
        ("lt:2.17.1",        "CVE-2021-44228", 10.0, "Log4Shell — JNDI LDAP RCE (CRITICAL)"),
    ],
    "openssl": [
        ("eq:3.0.4",         "CVE-2022-2274",   9.8, "RSA heap overflow → potential RCE"),
        ("startswith:1.0",   None,              8.0, "OpenSSL 1.0.x EOL — Heartbleed + others"),
    ],
    "iis": [
        ("startswith:7.",    None,              7.5, "IIS 7.x EOL — multiple unfixed issues"),
        ("startswith:8.",    None,              7.5, "IIS 8.x EOL"),
    ],
    "struts": [
        ("lt:2.5.33",        "CVE-2023-50164",  9.8, "Struts2 RCE via file upload param manipulation"),
    ],
    "telerik": [
        ("lt:2020.1.114",    "CVE-2019-18935", 10.0, "Telerik UI RadAsyncUpload deserialization RCE"),
    ],

    # ── Network / Infra ──────────────────────────────────────────────────────
    "netscaler": [
        (None,               "CVE-2026-88771",  9.8, "RCE via log poisoning unauth — script de manutenção parseia logs sem sanitização (KEV CISA, exploração massiva)"),
        (None,               "CVE-2026-88772",  8.1, "NetScaler ADC/Gateway — mesma família CVE-2026-88771 (par de exploração)"),
    ],
    "citrix adc": [
        (None,               "CVE-2026-88771",  9.8, "RCE via log poisoning unauth (KEV CISA, exploração massiva)"),
    ],
    "forticlient ems": [
        (None,               "CVE-2026-35616",  9.1, "Pre-auth bypass via X-SSL-CLIENT-VERIFY header spoofing → forjar cert FortiGate → acesso completo"),
    ],
    "fortimail": [
        (None,               "CVE-2026-104286", 9.8, "Path traversal + null byte → arbitrary file write → backdoor (KEV CISA, sem patch em dez/2026)"),
    ],
    "cisco fmc": [
        (None,               "CVE-2026-20079", 10.0, "RCE root unauth via boot process flaw — sem workaround disponível"),
    ],

    # ── Web Servers ───────────────────────────────────────────────────────────
    "nginx": [
        ("lt:1.20.1",        "CVE-2021-23017",  7.7, "1-byte memory overwrite via DNS resolver"),
        ("lt:1.22.1",        "CVE-2022-41741",  7.1, "Memory corruption in MP4 module"),
        ("lt:1.30.1",        "CVE-2026-42945",  9.8, "NGINX Rift — heap overflow em rewrite module (size/write-pass mismatch) → DoS/RCE (ASLR disabled)"),
    ],
    "nginx-ui": [
        (None,               "CVE-2026-27944",  9.8, "Backup endpoint unauth retorna AES key em plaintext → decrypt backup"),
        (None,               "CVE-2026-33032",  9.8, "Auth bypass em /mcp_message → controle total nginx (chain com CVE-2026-27944)"),
    ],
    "apache httpd": [
        ("eq:2.4.49",        "CVE-2021-41773",  9.8, "Path traversal + optional RCE via mod_cgi (actively exploited)"),
        ("eq:2.4.50",        "CVE-2021-42013",  9.8, "Path traversal bypass → RCE"),
        ("startswith:2.2",   None,              8.0, "Apache 2.2 EOL — multiple unfixed CVEs"),
        ("eq:2.4.66",        "CVE-2026-23918",  8.8, "HTTP/2 double-free em mod_http2 → DoS/RCE (Debian + Docker)"),
        ("lt:2.4.67",        "CVE-2026-28780",  9.8, "mod_proxy_ajp heap buffer overflow → RCE"),
    ],

    # ── Runtime / Platform ────────────────────────────────────────────────────
    "redis": [
        ("lt:8.2.2",         "CVE-2025-49844", 10.0, "RediShell — Lua UAF de 13 anos → escape sandbox → RCE no host (EVAL autenticado)"),
    ],
    "erlang": [
        (None,               "CVE-2025-32433", 10.0, "SSH processa mensagens de conexão antes de auth completa → RCE unauth (KEV CISA)"),
    ],
    "otp": [
        (None,               "CVE-2025-32433", 10.0, "Erlang/OTP SSH RCE unauth — processa msgs pré-auth (KEV CISA)"),
    ],

    # ── JS Frameworks ─────────────────────────────────────────────────────────
    "next.js": [
        ("lt:15.5.16",       "CVE-2026-44578",  8.6, "SSRF via WebSocket upgrade handler — GET porta 80 only, self-hosted, IMDSv2 não explorável"),
        ("lt:16.2.5",        "CVE-2026-44572",  8.1, "Next.js 16.2.4 batch — middleware bypass, connection exhaustion, routing mismatch"),
    ],

    # ── AI / ML / Automation Platforms ────────────────────────────────────────
    "metabase": [
        (None,               "CVE-2026-72898", 10.0, "SQLi via POST /api/session/reset_password → admin RCE (KEV CISA, exploração ativa)"),
    ],
    "langflow": [
        (None,               "CVE-2026-33017",  9.8, "exec() sem sandbox em flows públicos → RCE unauth"),
        (None,               "CVE-2026-0770",   9.8, "exec_globals no endpoint /validate → RCE"),
        (None,               "CVE-2026-5027",   9.8, "Path traversal /api/v2/files → cron injection → RCE"),
        (None,               "CVE-2026-55450",  9.8, "Langflow RCE chain variant 4"),
    ],
    "n8n": [
        ("lt:1.70.0",        "CVE-2025-26776",  9.9, "Expression injection via this.process.mainModule → RCE (unauth em versões antigas)"),
    ],
    "flowise": [
        (None,               "CVE-2025-64446",  9.8, "RCE unauth via /api/v1/node-load-method/customMCP listActions"),
        (None,               "CVE-2025-13315",  9.8, "Flowise RCE — forgot-password token leak → Function() exec"),
    ],
    "gogs": [
        (None,               "CVE-2025-8110",   9.8, "CSRF → RCE via symlink write (explorado em HTB Silentium)"),
    ],

    # ── Grafana ───────────────────────────────────────────────────────────────
    "grafana": [
        ("lt:8.0.7",         "CVE-2021-43798",  9.8, "Plugin path traversal → leitura arbitrária de arquivos (35+ plugins, grafana.db em plaintext)"),
        (None,               "CVE-2025-4123",  10.0, "Ghost — path traversal + open redirect XSS (versão recente)"),
        (None,               "CVE-2024-9264",   9.1, "DuckDB SQLi via query field (requer DuckDB plugin)"),
        ("lt:9.4.13",        "CVE-2023-2183",   8.1, "Auth bypass via API"),
    ],
    # ── Frontend Libraries ────────────────────────────────────────────────────
    "vue": [
        ("startswith:2.",    None,              7.5, "Vue 2 EOL since December 2023 — no security patches"),
    ],
    "angularjs": [
        ("startswith:1.",    None,              8.0, "AngularJS 1.x EOL since December 2021 — prototype pollution + XSS"),
    ],
    "lodash": [
        ("lt:4.17.19",       "CVE-2020-8203",   7.4, "Prototype pollution via Object.merge()"),
        ("lt:4.17.21",       "CVE-2021-23337",  7.2, "Command injection via template"),
    ],
    "moment": [
        ("lt:2.29.4",        "CVE-2022-31129",  7.5, "ReDoS in date string parsing"),
        (None,               None,              5.0, "moment.js EOL — maintainers recommend migration to date-fns/luxon/dayjs"),
    ],
    "bootstrap": [
        ("lt:3.4.1",         "CVE-2019-8331",   6.1, "XSS via data-template attribute in tooltip/popover"),
        ("lt:4.3.1",         "CVE-2019-8331",   6.1, "XSS via data-template attribute in tooltip/popover"),
    ],
    "handlebars": [
        ("lt:4.7.7",         "CVE-2021-23369",  9.8, "RCE via template injection — prototype pollution to code execution"),
        ("lt:4.7.7",         "CVE-2021-23383",  9.8, "Prototype pollution in compiler"),
    ],
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
def magenta(t): return _c(C.M, t)

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

SEV_COLOR = {
    "critical": lambda t: red(bold(t)),
    "high":     lambda t: red(t),
    "medium":   lambda t: yellow(t),
    "low":      lambda t: dim(t),
    "info":     lambda t: dim(t),
}

def finding_line(f):
    sev = f.get("severity", "info")
    col = SEV_COLOR.get(sev, dim)
    tag = col(f"[{sev.upper()[:4]}]")
    host = f.get("host", "")
    title = f.get("title", f.get("detail", ""))
    with _lock:
        print(f"  {tag} {cyan(host)} → {title}")

# ─── Utilities ────────────────────────────────────────────────────────────────

def _source_bashrc():
    rc_files = [
        Path.home() / ".bashrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".zshrc",
    ]
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

def run(cmd, *, timeout=30, env_extra=None, stdin_data=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        kwargs = dict(capture_output=True, text=True, timeout=timeout, env=env)
        if stdin_data is not None:
            kwargs["input"] = stdin_data
        proc = subprocess.run(cmd, **kwargs)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as e:
        return 1, "", str(e)

# Second-level TLDs that need 3 components to form a registrable domain
# e.g. "multilog.com.br" → take last 3 parts, not last 2
_SECOND_LEVEL_TLDS = {
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "ind.br",
    "art.br", "esp.br", "rec.br", "srv.br", "tmp.br",
    # UK / Commonwealth
    "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "co.nz", "co.za", "co.jp", "co.in", "co.id", "co.il", "co.ke",
    # Latin America
    "com.ar", "com.mx", "com.co", "com.pe", "com.cl", "com.uy",
    "com.ve", "com.ec", "com.bo", "com.py", "com.gt", "com.sv",
    # Asia / Pacific
    "com.au", "com.sg", "com.my", "com.hk", "com.ph", "com.vn",
    "com.tw", "com.cn", "ac.jp", "ne.jp", "or.jp",
    # Other
    "com.tr", "com.sa", "com.eg", "com.ng", "com.gh",
}

def _extract_domain(hostname: str) -> str:
    """Extract registrable domain, handling 3-level ccTLDs like .com.br or .co.uk."""
    parts = hostname.split(".")
    if len(parts) >= 3:
        if ".".join(parts[-2:]) in _SECOND_LEVEL_TLDS:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def count_lines(p) -> int:
    p = Path(p)
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln.strip())

def _ver_lt(a: str, b: str) -> bool:
    def _parse(v):
        return [int(x) for x in re.findall(r"\d+", v)]
    try:
        return _parse(a) < _parse(b)
    except Exception:
        return False

def _version_match(spec: str, version: str) -> bool:
    if not version:
        return False
    op, _, val = spec.partition(":")
    if op == "startswith":  return version.startswith(val)
    if op == "eq":          return version == val
    if op == "lt":          return _ver_lt(version, val)
    if op == "contains":    return val in version
    return False

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 32-bit. Pure Python — Shodan-compatible favicon hash."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    nblocks = length // 4
    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    tl = len(tail)
    if tl >= 3: k1 ^= tail[2] << 16
    if tl >= 2: k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1

def favicon_hash(favicon_bytes: bytes) -> int:
    """Shodan favicon hash: MurmurHash3(base64-encoded-with-newlines)."""
    b64_str = base64.encodebytes(favicon_bytes).decode()
    return _murmur3_32(b64_str.encode("utf-8"))

def _make_session(tor: bool, ua: str) -> "requests.Session":
    s = requests.Session()
    s.headers["User-Agent"] = ua
    if tor:
        s.proxies = {
            "http":  "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }
    return s

def _safe_get(session, url, *, timeout=12, allow_redirects=True, stream=False,
              _err_label=None, **kw):
    try:
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects,
                           stream=stream, verify=False, **kw)
    except Exception as e:
        if _err_label is not None:
            _err_label.append(str(e))
        return None

def _safe_post(session, url, *, data=None, json_data=None, timeout=12, **kw):
    try:
        return session.post(url, timeout=timeout, data=data, json=json_data,
                            verify=False, **kw)
    except Exception:
        return None

def _write_jsonl(path: Path, records: list):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

def _add_finding(findings: list, phase: str, severity: str, ftype: str,
                 host: str, title: str, detail: str = "", evidence=None):
    f = {
        "phase": phase, "severity": severity, "type": ftype,
        "host": host, "title": title, "detail": detail,
        "evidence": evidence,
    }
    findings.append(f)
    finding_line(f)
    return f

# ─── Phase 0 · Header Analysis ────────────────────────────────────────────────

def _analyze_csp(csp_value: str, host: str, findings: list):
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    # Check frame-ancestors before complaining about X-Frame-Options absence
    has_frame_ancestors = "frame-ancestors" in directives

    for directive, values in directives.items():
        if directive not in ("script-src", "default-src", "style-src", "img-src",
                              "connect-src", "font-src", "media-src", "object-src"):
            continue
        val_str = " ".join(values).lower()
        for bad, (sev, msg) in CSP_BAD_DIRECTIVES.items():
            key = bad.strip("'")
            if bad in val_str or key in val_str:
                _add_finding(findings, "csp", sev, f"csp_{key.replace('-','_').replace(' ','_')}",
                             host, f"CSP: {msg}",
                             detail=f"directive={directive} value={val_str[:200]}",
                             evidence=csp_value[:500])
        for domain, bypass in CSP_BYPASS_DOMAINS.items():
            d = domain.lstrip("*.")
            if d in val_str:
                _add_finding(findings, "csp", "medium", "csp_bypass_domain",
                             host, f"CSP bypass via {domain}",
                             detail=bypass, evidence=directive + ": " + val_str[:200])

    if "object-src" not in directives and "default-src" not in directives:
        _add_finding(findings, "csp", "low", "csp_missing_object_src",
                     host, "CSP missing object-src — Flash/plugin injection possible",
                     evidence=csp_value[:200])

    if "base-uri" not in directives:
        _add_finding(findings, "csp", "medium", "csp_missing_base_uri",
                     host, "CSP missing base-uri — <base href=//evil.com> injection possible",
                     evidence=csp_value[:200])

    if "form-action" not in directives and "default-src" not in directives:
        _add_finding(findings, "csp", "low", "csp_missing_form_action",
                     host, "CSP missing form-action — form submission hijacking possible",
                     evidence=csp_value[:200])

    return has_frame_ancestors

def _analyze_cors(headers: dict, host: str, findings: list):
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        _add_finding(findings, "header", "medium", "cors_wildcard",
                     host, "CORS: Access-Control-Allow-Origin: * (wildcard)",
                     detail="Any origin can read responses — low risk unless combined with credentials")
    if acao and acao != "*" and acac == "true":
        _add_finding(findings, "header", "high", "cors_credentials",
                     host, f"CORS with credentials: ACAO={acao} + ACAC=true",
                     detail="Origin reflection with allow-credentials=true → session theft if origin accepted",
                     evidence=f"ACAO: {acao}")

def _probe_cors_active(session, host: str, findings: list):
    """Active CORS probe: send Origin: evil.com and Origin: null, detect reflection."""
    for origin in ("https://evil.com", "null"):
        r = _safe_get(session, host, headers={"Origin": origin}, timeout=8)
        if not r:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == origin:
            sev    = "critical" if acac == "true" else "high"
            detail = f"Origin: {origin!r} → ACAO: {acao}" + (" + ACAC: true" if acac == "true" else "")
            _add_finding(findings, "cors", sev, "cors_reflection",
                         host,
                         f"CORS reflects arbitrary origin {'with credentials' if acac == 'true' else '(no credentials)'}",
                         detail=detail,
                         evidence={"origin_sent": origin, "acao": acao, "acac": acac})
            break  # one finding per host is enough

def phase_headers(live_hosts: list, outdir: Path, session, findings: list, threads: int = 20):
    phase_header("0+1+2", "Header · CSP · Cookie Audit")
    if not live_hosts:
        warn("  No live hosts — skipping header analysis")
        return

    info(f"  Probing {len(live_hosts)} hosts for security headers …")
    out_dir = outdir / "headers"
    out_dir.mkdir(parents=True, exist_ok=True)
    per_host = {}
    _first_err: list = []

    def _probe(host):
        host = host.rstrip("/")
        err_buf: list = []
        r = _safe_get(session, host, timeout=15, _err_label=err_buf)
        if r is None:
            return host, None, err_buf[0] if err_buf else "no response"
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        # urllib3 preserves duplicate Set-Cookie headers; requests merges them into one
        try:
            raw_cookies = list(r.raw.headers.getlist("set-cookie"))
        except Exception:
            raw_cookies = []
        return host, {"status": r.status_code, "headers": hdrs, "url": r.url,
                      "raw_cookies": raw_cookies}, None

    n_ok = 0
    n_fail = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_probe, h): h for h in live_hosts}
        for fut in as_completed(futs):
            host, result, errmsg = fut.result()
            if result is None:
                n_fail += 1
                if errmsg and not _first_err:
                    _first_err.append(errmsg)
                continue
            per_host[host] = result
            n_ok += 1

    if n_fail:
        hint = ""
        if _first_err:
            e = _first_err[0]
            if "SOCKS" in e or "proxy" in e.lower():
                hint = " — TOR proxy error, check if TOR is running"
            elif "timed out" in e.lower() or "timeout" in e.lower():
                hint = " — connections timed out (try --tor or check network)"
            elif "ssl" in e.lower() or "certificate" in e.lower():
                hint = f" — SSL error: {e[:60]}"
            elif "refused" in e.lower():
                hint = " — connection refused (hosts may be behind firewall)"
            else:
                hint = f" — {e[:80]}"
        warn(f"  {n_fail}/{len(live_hosts)} hosts unreachable{hint}")

    host_findings = {}
    for host, data in per_host.items():
        hdrs = data["headers"]
        hf = []

        # Required headers
        has_csp = "content-security-policy" in hdrs
        has_frame_ancestors = False

        for hdef in REQUIRED_HEADERS:
            name = hdef["name"]
            val = hdrs.get(name.lower())

            if name == "Content-Security-Policy":
                if not has_csp:
                    f = _add_finding(findings, "header", hdef["sev"], "missing_csp",
                                     host, hdef["missing"])
                    hf.append(f)
                else:
                    has_frame_ancestors = _analyze_csp(val, host, findings)
                continue

            if val is None:
                # X-Frame-Options absence is OK if CSP has frame-ancestors
                if name == "X-Frame-Options" and has_frame_ancestors:
                    continue
                f = _add_finding(findings, "header", hdef["sev"],
                                 f"missing_{name.lower().replace('-','_')}",
                                 host, hdef["missing"])
                hf.append(f)
            else:
                checker = hdef.get("check")
                if checker and not checker(val):
                    f = _add_finding(findings, "header", hdef["sev"],
                                     f"bad_{name.lower().replace('-','_')}",
                                     host, hdef.get("bad", f"{name} misconfigured"),
                                     evidence=val)
                    hf.append(f)

        # Info disclosure headers
        for h in INFO_DISCLOSURE_HEADERS:
            val = hdrs.get(h.lower())
            if val:
                _add_finding(findings, "header", "low", "info_disclosure",
                             host, f"Server info disclosure via {h}: {val[:80]}",
                             evidence=f"{h}: {val}")

        # CORS — passive (baseline headers) + active probe (reflected origin check)
        _analyze_cors(hdrs, host, findings)
        _probe_cors_active(session, host, findings)

        # Cookie audit — use urllib3 raw headers to handle multiple Set-Cookie values
        set_cookies = data.get("raw_cookies") or []
        if not set_cookies:
            raw_cookie = hdrs.get("set-cookie", "")
            if raw_cookie:
                set_cookies = [raw_cookie]

        for cookie_str in set_cookies:
            name_part = cookie_str.split(";")[0].split("=")[0].strip()
            parts_lower = cookie_str.lower()
            if "secure" not in parts_lower:
                _add_finding(findings, "cookie", "high", "cookie_no_secure",
                             host, f"Cookie '{name_part}' missing Secure flag",
                             evidence=cookie_str[:200])
            if "httponly" not in parts_lower:
                _add_finding(findings, "cookie", "medium", "cookie_no_httponly",
                             host, f"Cookie '{name_part}' missing HttpOnly flag",
                             evidence=cookie_str[:200])
            if "samesite" not in parts_lower:
                _add_finding(findings, "cookie", "medium", "cookie_no_samesite",
                             host, f"Cookie '{name_part}' missing SameSite attribute",
                             evidence=cookie_str[:200])

        host_findings[host] = hf

    (out_dir / "headers.json").write_text(json.dumps(per_host, indent=2))
    ok(f"  Header analysis done — {n_ok}/{len(live_hosts)} hosts probed")

# ─── Phase 3 · DNS Security ───────────────────────────────────────────────────

def _dig(args_list, timeout=8):
    rc, out, _ = run(["dig"] + args_list + ["+short", "+time=4", "+tries=1"],
                     timeout=timeout)
    if rc == 127:
        return None  # dig not installed
    return out.strip()

def _dig_full(args_list, timeout=8):
    rc, out, _ = run(["dig"] + args_list + ["+noall", "+answer", "+time=4", "+tries=1"],
                     timeout=timeout)
    return out.strip() if rc == 0 else ""

def phase_dns(domain: str, outdir: Path, findings: list):
    phase_header("3", f"DNS Security — {domain}")
    if not which("dig"):
        warn("  dig not found — skipping DNS phase")
        return

    out_dir = outdir / "dns"
    out_dir.mkdir(parents=True, exist_ok=True)
    dns_data = {}

    # SPF
    info("  SPF …")
    txt = _dig([domain, "TXT"])
    if txt is not None:
        dns_data["txt"] = txt
        spf_records = [ln for ln in txt.splitlines() if "v=spf1" in ln.lower()]
        if not spf_records:
            _add_finding(findings, "dns", "high", "no_spf", domain,
                         f"No SPF record on {domain} — email spoofing trivial",
                         detail="Add: v=spf1 include:... ~all")
        else:
            spf = spf_records[0]
            if "+all" in spf:
                _add_finding(findings, "dns", "critical", "spf_plus_all", domain,
                             "SPF '+all' allows any server to send — useless protection",
                             evidence=spf)
            elif "?all" in spf:
                _add_finding(findings, "dns", "medium", "spf_neutral", domain,
                             "SPF '?all' neutral — low spoofing protection", evidence=spf)
            else:
                ok(f"  SPF: {spf.strip()[:80]}")

    # DMARC
    info("  DMARC …")
    dmarc_raw = _dig([f"_dmarc.{domain}", "TXT"])
    if dmarc_raw is not None:
        dns_data["dmarc"] = dmarc_raw
        if not dmarc_raw or "v=dmarc1" not in dmarc_raw.lower():
            _add_finding(findings, "dns", "high", "no_dmarc", domain,
                         f"No DMARC record on {domain} — SPF/DKIM bypass → spoofing",
                         detail="Add: _dmarc.domain TXT v=DMARC1; p=reject; ...")
        else:
            if "p=none" in dmarc_raw.lower():
                _add_finding(findings, "dns", "medium", "dmarc_policy_none", domain,
                             "DMARC policy=none — monitoring only, no enforcement",
                             evidence=dmarc_raw[:200])
            elif "p=quarantine" in dmarc_raw.lower():
                ok(f"  DMARC p=quarantine (partial protection)")
            else:
                ok(f"  DMARC p=reject (good)")

    # DKIM (probe common selectors)
    info("  DKIM …")
    dkim_found = []
    for sel in DKIM_SELECTORS[:10]:  # cap at 10 for speed
        result = _dig([f"{sel}._domainkey.{domain}", "TXT"])
        if result and "v=dkim1" in result.lower():
            dkim_found.append(sel)
    dns_data["dkim_selectors"] = dkim_found
    if not dkim_found:
        _add_finding(findings, "dns", "low", "no_dkim", domain,
                     f"No DKIM selector found for {domain} (checked {len(DKIM_SELECTORS[:10])} common selectors)")
    else:
        ok(f"  DKIM selectors found: {', '.join(dkim_found)}")

    # AXFR
    info("  AXFR …")
    ns_raw = _dig([domain, "NS"])
    if ns_raw:
        dns_data["ns"] = ns_raw
        nameservers = [ns.rstrip(".") for ns in ns_raw.splitlines() if ns.strip()]
        for ns in nameservers[:3]:
            axfr_out = _dig_full([f"@{ns}", domain, "AXFR"], timeout=10)
            if axfr_out and axfr_out.count("\n") > 3:
                _add_finding(findings, "dns", "critical", "axfr_allowed", domain,
                             f"Zone transfer (AXFR) allowed via {ns} — full DNS dump possible",
                             detail=f"dig AXFR @{ns} {domain}",
                             evidence=axfr_out[:500])
                (out_dir / f"axfr_{ns}.txt").write_text(axfr_out)

    # CAA
    info("  CAA …")
    caa = _dig([domain, "CAA"])
    dns_data["caa"] = caa or ""
    if not caa:
        _add_finding(findings, "dns", "low", "no_caa", domain,
                     f"No CAA record — any CA can issue certificates for {domain}",
                     detail="Add CAA records to restrict certificate issuance")

    # MX
    info("  MX …")
    mx = _dig([domain, "MX"])
    dns_data["mx"] = mx or ""
    if not mx:
        info(f"  No MX record (may be intentional)")

    (out_dir / "dns_data.json").write_text(json.dumps(dns_data, indent=2))
    ok(f"  DNS analysis done for {domain}")

# ─── Phase 4 · Tech → CVE ─────────────────────────────────────────────────────

def _parse_tech_version(tech_str: str):
    """Parse 'Apache Httpd:2.4.49' → ('apache httpd', '2.4.49')."""
    if ":" in tech_str:
        parts = tech_str.rsplit(":", 1)
        return parts[0].strip().lower(), parts[1].strip()
    return tech_str.strip().lower(), ""

def _nvd_lookup(tech: str, version: str, session, rate_limiter: list) -> list:
    """Query NVD API for CVEs. Returns list of {cve, cvss, description}."""
    query = tech if not version else f"{tech} {version}"
    query = query.replace(" ", "+")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&cvssV3Severity=HIGH"
    # Rate limit: max 1 req/2s without API key
    with _lock:
        now = time.time()
        if rate_limiter and now - rate_limiter[0] < 2.0:
            time.sleep(2.0 - (now - rate_limiter[0]))
        rate_limiter[:] = [time.time()]
    r = _safe_get(session, url, timeout=15)
    if r is None or r.status_code != 200:
        return []
    try:
        data = r.json()
        results = []
        for item in data.get("vulnerabilities", [])[:5]:
            cve_id = item.get("cve", {}).get("id", "")
            metrics = item.get("cve", {}).get("metrics", {})
            cvss = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key, [])
                if m:
                    cvss = m[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            desc_list = item.get("cve", {}).get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            results.append({"cve": cve_id, "cvss": cvss, "description": desc[:200]})
        return results
    except Exception:
        return []

def phase_tech_cve(httpx_jsonl: Path, outdir: Path, session, findings: list, skip_nvd: bool = False):
    phase_header("4", "Tech → CVE")
    if not httpx_jsonl.exists():
        warn("  httpx JSONL not found — skipping tech/CVE phase")
        return

    # Collect unique tech→version pairs across all hosts
    tech_hosts = {}  # tech_str → set of hosts
    host_tech = {}
    for line in httpx_jsonl.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        host = rec.get("url", "")
        # httpx v1 used "technologies", v2+ uses "tech" — accept both
        tech_list = rec.get("tech") or rec.get("technologies") or []
        for t in tech_list:
            tech_hosts.setdefault(t, set()).add(host)
        if tech_list:
            host_tech[host] = tech_list

    if not tech_hosts:
        warn("  No tech-detect data in httpx JSONL (run recon.py with -tech-detect)")
        return

    info(f"  {len(tech_hosts)} unique technologies detected")
    out_dir = outdir / "tech_cve"
    out_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = [0.0]
    cve_results = {}

    for tech_str, hosts in tech_hosts.items():
        name, version = _parse_tech_version(tech_str)
        matched = []

        # Local DB first — exact name match only (prevents "jquery" rules firing on "jquery migrate")
        for db_name, rules in TECH_CVE_LOCAL.items():
            if db_name != name:
                continue
            if not version:
                # Version not fingerprinted — emit one generic finding, don't blast all rules
                matched.append({
                    "source": "local",
                    "cve": "version-unknown",
                    "cvss": 5.0,
                    "description": (
                        f"{tech_str} detected but version not fingerprinted by httpx — "
                        "check manually for EOL / known CVEs"
                    ),
                })
                break
            for spec, cve_id, cvss, desc in rules:
                if _version_match(spec, version):
                    matched.append({
                        "source": "local",
                        "cve": cve_id or "EOL/unfixed",
                        "cvss": cvss,
                        "description": desc,
                    })

        # NVD API for unknown tech with version
        if not matched and version and not skip_nvd:
            nvd = _nvd_lookup(name, version, session, rate_limiter)
            for item in nvd:
                if item["cvss"] >= 7.0:
                    matched.append({"source": "nvd", **item})

        if matched:
            cve_results[tech_str] = {"hosts": list(hosts), "cves": matched}
            for m in matched:
                cvss = m.get("cvss", 0)
                sev = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium"
                for host in hosts:
                    _add_finding(findings, "tech_cve", sev, "tech_cve",
                                 host, f"{tech_str} — {m['cve']} (CVSS:{cvss})",
                                 detail=m["description"],
                                 evidence={"tech": tech_str, "version": version, **m})

    (out_dir / "cve_matches.json").write_text(json.dumps(cve_results, indent=2))
    ok(f"  Tech/CVE done — {len(cve_results)} technologies with findings")

# ─── Phase 5 · Favicon Hash ───────────────────────────────────────────────────

def phase_favicon(live_hosts: list, outdir: Path, session, findings: list, threads: int = 15):
    phase_header("5", "Favicon Hash Fingerprint")
    if not live_hosts:
        return

    out_dir = outdir / "favicons"
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    info(f"  Downloading favicons from {len(live_hosts)} hosts …")

    def _get_favicon(host):
        host = host.rstrip("/")
        for path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
            r = _safe_get(session, host + path, timeout=10)
            if r and r.status_code == 200 and r.content:
                return host, path, r.content
        return host, None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_get_favicon, h): h for h in live_hosts}
        for fut in as_completed(futs):
            host, path, content = fut.result()
            if content is None:
                continue
            h = favicon_hash(content)
            md5 = hashlib.md5(content).hexdigest()
            h_str = str(h)
            results[host] = {"hash": h, "md5": md5, "path": path, "size": len(content)}

            match = FAVICON_HASHES.get(h_str)
            if match:
                product, sev = match
                _add_finding(findings, "favicon", sev, "favicon_fingerprint",
                             host, f"Favicon hash matches {product} (hash={h})",
                             detail=f"MurmurHash3={h} MD5={md5}",
                             evidence={"hash": h, "md5": md5, "product": product})
            else:
                with _lock:
                    print(f"  {dim('[ICON]')} {host}{path} → hash={h} md5={md5[:8]}… (unknown)")
            # Save favicon for manual review
            ico_path = out_dir / f"{host.replace('://', '_').replace('/', '_')}{path.replace('/','_')}"
            try:
                ico_path.write_bytes(content)
            except Exception:
                pass

    (out_dir / "favicons.json").write_text(json.dumps(results, indent=2))
    ok(f"  Favicon phase done — {len(results)} favicons downloaded")

# ─── Phase 6 · Content Recon ─────────────────────────────────────────────────

def phase_content_recon(live_hosts: list, outdir: Path, session, findings: list, threads: int = 15):
    phase_header("6", "Content Recon (robots.txt · sitemap.xml · .well-known)")
    if not live_hosts:
        return

    out_dir = outdir / "content"
    out_dir.mkdir(parents=True, exist_ok=True)
    all_paths = {}
    info(f"  Probing {len(live_hosts)} hosts …")

    def _probe_host(host):
        host = host.rstrip("/")
        result = {"disallowed": [], "sitemap_urls": [], "wellknown": []}

        # robots.txt
        r = _safe_get(session, host + "/robots.txt", timeout=10)
        if r and r.status_code == 200 and "text" in r.headers.get("content-type", ""):
            text = r.text
            disallowed = re.findall(r"(?i)^Disallow:\s*(.+)$", text, re.MULTILINE)
            disallowed = [d.strip() for d in disallowed if d.strip() and d.strip() != "/"]
            result["disallowed"] = disallowed
            sitemaps = re.findall(r"(?i)^Sitemap:\s*(.+)$", text, re.MULTILINE)
            result["sitemap_hints"] = [s.strip() for s in sitemaps]
        # sitemap.xml
        sitemap_urls = set()
        for sm_path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
            r = _safe_get(session, host + sm_path, timeout=10)
            if r and r.status_code == 200:
                try:
                    root = ET.fromstring(r.text)
                    ns = re.match(r"\{[^}]+\}", root.tag)
                    ns = ns.group(0) if ns else ""
                    for loc in root.iter(ns + "loc"):
                        if loc.text:
                            sitemap_urls.add(loc.text.strip())
                except Exception:
                    pass
        result["sitemap_urls"] = list(sitemap_urls)[:200]

        # .well-known
        for wk in ("/.well-known/security.txt", "/security.txt", "/.well-known/change-password"):
            r = _safe_get(session, host + wk.lstrip("/"), timeout=8)
            if r and r.status_code == 200:
                result["wellknown"].append({"path": wk, "body": r.text[:500]})
        return host, result

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_probe_host, h): h for h in live_hosts}
        for fut in as_completed(futs):
            host, result = fut.result()
            all_paths[host] = result
            if result["disallowed"]:
                info(f"  {host} → robots.txt: {len(result['disallowed'])} Disallow entries")
                for path in result["disallowed"][:5]:
                    with _lock:
                        print(f"    {dim('Disallow:')} {path}")
                if len(result["disallowed"]) > 5:
                    with _lock:
                        print(f"    … {len(result['disallowed'])-5} more (see content/content.json)")
            if result["sitemap_urls"]:
                ok(f"  {host} → sitemap: {len(result['sitemap_urls'])} URLs")
            for wk in result.get("wellknown", []):
                ok(f"  {host} → {wk['path']} (200 OK)")

    (out_dir / "content.json").write_text(json.dumps(all_paths, indent=2))

    # Save aggregated disallow paths
    all_disallowed = sorted(set(
        p for r in all_paths.values() for p in r.get("disallowed", [])
    ))
    if all_disallowed:
        (out_dir / "disallowed_paths.txt").write_text("\n".join(all_disallowed) + "\n")
    ok(f"  Content recon done")

# ─── Phase 7 · ASN + Reverse IP ──────────────────────────────────────────────

def phase_asn(ips_file: Path, outdir: Path, session, findings: list):
    phase_header("7", "ASN + Reverse IP")
    if not ips_file.exists():
        warn("  IPs file not found — skipping ASN phase")
        return

    ips = [ln.strip() for ln in ips_file.read_text().splitlines() if ln.strip()]
    if not ips:
        warn("  No IPs found")
        return

    info(f"  Looking up {len(ips)} IPs via ipinfo.io …")
    out_dir = outdir / "asn"
    out_dir.mkdir(parents=True, exist_ok=True)
    asn_data = {}

    seen_orgs = set()

    for ip in ips[:50]:  # cap to avoid excessive API calls
        r = _safe_get(session, f"https://ipinfo.io/{ip}/json", timeout=10)
        if r and r.status_code == 200:
            try:
                d = r.json()
                asn_data[ip] = d
                org = d.get("org", "")
                cidr = d.get("network", "")  # not always present in free tier
                country = d.get("country", "")
                if org and org not in seen_orgs:
                    seen_orgs.add(org)
                    ok(f"  {ip} → {org} / {country}")
            except Exception:
                pass
        time.sleep(0.3)  # gentle rate limiting

    # Reverse IP via hackertarget
    info(f"  Reverse IP lookups via hackertarget.com …")
    cohost_data = {}
    for ip in ips[:20]:  # be conservative
        r = _safe_get(session, f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12)
        if r and r.status_code == 200 and "error" not in r.text.lower():
            hosts = [h.strip() for h in r.text.strip().splitlines() if h.strip()]
            if len(hosts) > 1:  # more than just the target
                cohost_data[ip] = hosts
                ok(f"  {ip} → {len(hosts)} co-hosted domains")
                if len(hosts) <= 5:
                    for h in hosts:
                        with _lock: print(f"    {dim(h)}")
        time.sleep(1.0)  # hackertarget rate limit

    (out_dir / "asn_data.json").write_text(json.dumps(asn_data, indent=2))
    if cohost_data:
        (out_dir / "cohosts.json").write_text(json.dumps(cohost_data, indent=2))
        all_cohosts = sorted(set(h for hs in cohost_data.values() for h in hs))
        (out_dir / "cohosts.txt").write_text("\n".join(all_cohosts) + "\n")
    ok(f"  ASN phase done — {len(asn_data)} IPs, {len(cohost_data)} with co-hosts")

# ─── Phase 8 · TLS / SAN Mining ──────────────────────────────────────────────

def _get_tls_cert(hostname: str, port: int = 443, timeout: int = 8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None

def phase_tls(live_hosts: list, outdir: Path, findings: list, threads: int = 20):
    phase_header("8", "TLS / SAN Mining")
    if not live_hosts:
        return

    out_dir = outdir / "tls"
    out_dir.mkdir(parents=True, exist_ok=True)
    https_hosts = [h for h in live_hosts if h.startswith("https://")]
    info(f"  Extracting TLS certs from {len(https_hosts)} HTTPS hosts …")

    all_sans = {}
    domain_to_hosts = {}

    def _check_host(host):
        parsed = urlparse(host)
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname:
            return host, None
        cert = _get_tls_cert(hostname, port)
        if not cert:
            return host, None
        sans = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(val)
        return host, {"hostname": hostname, "port": port, "san": sans, "cert": cert}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_check_host, h): h for h in https_hosts}
        for fut in as_completed(futs):
            host, data = fut.result()
            if not data:
                continue
            all_sans[host] = data
            sans = data["san"]
            if sans:
                ok(f"  {host} → {len(sans)} SAN entries")
                for san in sans[:5]:
                    with _lock: print(f"    {dim(san)}")
                    domain_to_hosts.setdefault(san, []).append(host)

    # Collect unique new domains from SANs
    known_domains = set()
    for h in live_hosts:
        try:
            known_domains.add(urlparse(h).hostname)
        except Exception:
            pass

    new_domains = sorted(set(
        san for san in domain_to_hosts
        if not any(san == d or san.endswith(f".{d}") for d in known_domains)
    ))
    if new_domains:
        ok(f"  {len(new_domains)} new domains found in TLS SANs:")
        for d in new_domains[:20]:
            with _lock: print(f"    {yellow(d)}")
        (out_dir / "new_san_domains.txt").write_text("\n".join(new_domains) + "\n")
        _add_finding(findings, "tls", "info", "san_new_domains",
                     "all", f"TLS SAN: {len(new_domains)} previously unknown hostnames",
                     detail="See tls/new_san_domains.txt",
                     evidence=new_domains[:20])

    (out_dir / "tls_certs.json").write_text(
        json.dumps({k: {
            "hostname": v["hostname"],
            "port": v["port"],
            "san": v["san"],
        } for k, v in all_sans.items()}, indent=2)
    )
    ok(f"  TLS phase done — {len(all_sans)} certs inspected")

# ─── Phase 9 · GraphQL Introspection ─────────────────────────────────────────

def phase_graphql(live_hosts: list, outdir: Path, session, findings: list, threads: int = 15):
    phase_header("9", "GraphQL Introspection")
    if not live_hosts:
        return

    out_dir = outdir / "graphql"
    out_dir.mkdir(parents=True, exist_ok=True)
    found = {}
    info(f"  Probing {len(live_hosts) * len(GRAPHQL_PATHS)} endpoints …")

    def _probe(host, path):
        host = host.rstrip("/")
        url = host + path
        # Quick check: send GET first
        rg = _safe_get(session, url, timeout=8)
        if not rg or rg.status_code in (404, 410):
            return None
        # Then POST introspection
        try:
            r = session.post(url, data=GRAPHQL_INTROSPECTION,
                             headers={"Content-Type": "application/json"},
                             timeout=10, verify=False)
        except Exception:
            return None
        if r is None or r.status_code not in (200, 400):
            return None
        try:
            data = r.json()
        except Exception:
            return None
        if "__schema" in data.get("data", {}) or "errors" in data:
            return {"url": url, "status": r.status_code, "response": data}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        for host in live_hosts:
            for path in GRAPHQL_PATHS:
                futs[ex.submit(_probe, host, path)] = (host, path)
        for fut in as_completed(futs):
            result = fut.result()
            if not result:
                continue
            url = result["url"]
            data = result["response"]
            schema = data.get("data", {}).get("__schema", {})
            errors = data.get("errors", [])
            if schema:
                types = schema.get("types", [])
                queries = [t for t in types if t.get("kind") == "OBJECT"]
                found[url] = {"schema": schema, "type_count": len(types)}
                _add_finding(findings, "graphql", "medium", "graphql_introspection",
                             url, f"GraphQL introspection enabled — {len(types)} types exposed",
                             detail=f"Query types: {len(queries)}",
                             evidence={"url": url, "type_count": len(types)})
                (out_dir / (url.replace("://", "_").replace("/", "_")[:80] + ".json")).write_text(
                    json.dumps(schema, indent=2)
                )
            elif errors:
                # Introspection disabled but endpoint exists
                ok(f"  GraphQL endpoint found (introspection disabled): {url}")

    ok(f"  GraphQL phase done — {len(found)} endpoints with open introspection")

# ─── Phase 10 · OpenAPI / Swagger ────────────────────────────────────────────

def _parse_openapi(spec: dict, url: str) -> dict:
    """Extract endpoints, servers, and auth from OpenAPI spec."""
    result = {"endpoints": [], "servers": [], "auth_schemes": [], "spec_url": url}

    # OpenAPI 3.x
    if "openapi" in spec:
        result["version"] = spec.get("openapi", "3.x")
        result["servers"] = [s.get("url", "") for s in spec.get("servers", [])]
        components = spec.get("components", {})
        result["auth_schemes"] = list(components.get("securitySchemes", {}).keys())
        for path, methods in spec.get("paths", {}).items():
            for method, detail in methods.items():
                if method in ("get", "post", "put", "patch", "delete", "options"):
                    result["endpoints"].append({
                        "method": method.upper(),
                        "path": path,
                        "summary": detail.get("summary", ""),
                        "security": detail.get("security"),
                    })
    # Swagger 2.0
    elif "swagger" in spec:
        result["version"] = spec.get("swagger", "2.x")
        host = spec.get("host", "")
        if host:
            result["servers"].append(host)
        for path, methods in spec.get("paths", {}).items():
            for method, detail in methods.items():
                if method in ("get", "post", "put", "patch", "delete", "options"):
                    result["endpoints"].append({
                        "method": method.upper(),
                        "path": path,
                        "summary": detail.get("summary", ""),
                        "security": detail.get("security"),
                    })
        defs = spec.get("securityDefinitions", {})
        result["auth_schemes"] = list(defs.keys())
    return result

def phase_openapi(live_hosts: list, outdir: Path, session, findings: list, threads: int = 15):
    phase_header("10", "OpenAPI / Swagger Discovery")
    if not live_hosts:
        return

    out_dir = outdir / "openapi"
    out_dir.mkdir(parents=True, exist_ok=True)
    found = {}
    info(f"  Probing {len(live_hosts) * len(SWAGGER_PATHS)} spec paths …")

    def _probe(host, path):
        host = host.rstrip("/")
        url = host + path
        r = _safe_get(session, url, timeout=8)
        if not r or r.status_code != 200:
            return None
        ct = r.headers.get("content-type", "").lower()
        body = r.text
        # Must look like a spec, not an HTML page
        if "html" in ct and "<html" in body.lower()[:200]:
            return None
        try:
            if "json" in ct or path.endswith(".json"):
                spec = r.json()
            else:
                # Try JSON parse anyway (some servers send wrong CT)
                try:
                    spec = r.json()
                except Exception:
                    return None
        except Exception:
            return None
        if not isinstance(spec, dict):
            return None
        if "openapi" not in spec and "swagger" not in spec and "paths" not in spec:
            return None
        return {"url": url, "spec": spec}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        for host in live_hosts:
            for path in SWAGGER_PATHS:
                futs[ex.submit(_probe, host, path)] = (host, path)
        for fut in as_completed(futs):
            result = fut.result()
            if not result:
                continue
            url = result["url"]
            if url in found:
                continue
            parsed = _parse_openapi(result["spec"], url)
            found[url] = parsed
            n_ep = len(parsed["endpoints"])
            auth = parsed.get("auth_schemes", [])
            # Specs are often intentionally public. Elevate only when no auth schemes are declared
            # and there are endpoints worth auditing.
            spec_sev = "medium" if (not auth and n_ep > 0) else "info"
            _add_finding(findings, "openapi", spec_sev, "openapi_exposed",
                         url, f"OpenAPI/Swagger spec exposed — {n_ep} endpoints mapped",
                         detail=f"auth_schemes={auth} servers={parsed.get('servers',[])}",
                         evidence={"url": url, "endpoints": n_ep, "auth": auth})
            fname = url.replace("://", "_").replace("/", "_")[:80] + ".json"
            (out_dir / fname).write_text(json.dumps(result["spec"], indent=2))
            # Endpoints TXT
            ep_lines = [f"{e['method']} {e['path']}  # {e.get('summary','')}"
                        for e in parsed["endpoints"]]
            (out_dir / fname.replace(".json", "_endpoints.txt")).write_text(
                "\n".join(ep_lines) + "\n"
            )

    ok(f"  OpenAPI phase done — {len(found)} specs found")

# ─── Phase 11 · 403 Bypass ────────────────────────────────────────────────────

def phase_403_bypass(httpx_jsonl: Path, outdir: Path, session, findings: list):
    phase_header("11", "403 Bypass Testing")
    if not httpx_jsonl.exists():
        warn("  httpx JSONL not found — skipping 403 bypass")
        return

    # Collect 403 URLs
    urls_403 = []
    for line in httpx_jsonl.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("status_code") in (401, 403):
            urls_403.append(rec.get("url", ""))
    urls_403 = [u for u in urls_403 if u]

    if not urls_403:
        info("  No 403/401 responses in httpx JSONL — skipping")
        return

    info(f"  Testing bypass techniques on {len(urls_403)} restricted paths …")
    out_dir = outdir / "bypass403"
    out_dir.mkdir(parents=True, exist_ok=True)
    bypass_results = []

    def _classify_bypass(r) -> tuple[str, str]:
        """Returns (severity, note) based on response content."""
        body = r.text[:3000].lower()
        if any(p in body for p in _BYPASS_ERROR_PATTERNS):
            return "low", " (error page — no protected content exposed)"
        return "high", ""

    def _test_bypass(url):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        found_bypasses = []

        # Header-based bypass
        for hset in BYPASS_HEADER_SETS:
            headers_to_send = {}
            for k, v in hset.items():
                if v is None:
                    headers_to_send[k] = path
                else:
                    headers_to_send[k] = v
            r = _safe_get(session, url, headers=headers_to_send, timeout=8)
            if r and r.status_code not in (401, 403, 404, 405) and r.status_code < 500:
                sev, note = _classify_bypass(r)
                found_bypasses.append({
                    "technique": "header",
                    "headers": headers_to_send,
                    "status": r.status_code,
                    "url": url,
                    "severity": sev,
                    "note": note,
                })

        # Path transform bypass
        for transform in BYPASS_PATH_TRANSFORMS:
            try:
                new_path = transform(path)
            except Exception:
                continue
            if new_path == path:
                continue
            new_url = base + new_path
            r = _safe_get(session, new_url, timeout=8)
            if r and r.status_code not in (401, 403, 404, 405) and r.status_code < 500:
                sev, note = _classify_bypass(r)
                found_bypasses.append({
                    "technique": "path",
                    "modified_url": new_url,
                    "status": r.status_code,
                    "url": url,
                    "severity": sev,
                    "note": note,
                })

        return found_bypasses

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(_test_bypass, u): u for u in urls_403[:50]}
        for fut in as_completed(futs):
            result = fut.result()
            bypass_results.extend(result)
            for b in result:
                _add_finding(findings, "bypass_403", b["severity"], "403_bypass",
                             b["url"],
                             f"403 bypass via {b['technique']}: HTTP {b['status']}{b.get('note', '')}",
                             detail=str(b),
                             evidence=b)

    (out_dir / "bypass_results.json").write_text(json.dumps(bypass_results, indent=2))
    ok(f"  403 bypass phase done — {len(bypass_results)} successful bypasses")

# ─── Phase 12 · Cache Poisoning Probe ────────────────────────────────────────

def phase_cache_probe(live_hosts: list, outdir: Path, session, findings: list, threads: int = 10):
    phase_header("12", "Cache Poisoning Probe")
    if not live_hosts:
        return

    out_dir = outdir / "cache"
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    info(f"  Testing unkeyed headers on {len(live_hosts)} hosts …")

    def _probe(host):
        host = host.rstrip("/")
        baseline = _safe_get(session, host, timeout=10)
        if not baseline:
            return []
        baseline_body = baseline.text[:5000]
        baseline_headers = {k.lower(): v for k, v in baseline.headers.items()}

        # Check if response is cacheable
        cc = baseline_headers.get("cache-control", "")
        if "no-store" in cc or "private" in cc:
            return []

        found = []
        for header in CACHE_UNKEYED_HEADERS:
            r = _safe_get(session, host, headers={header: CACHE_CANARY}, timeout=10)
            if not r:
                continue
            if CACHE_CANARY in r.text:
                found.append({
                    "host": host,
                    "header": header,
                    "reflected": True,
                    "cache_control": cc,
                })
            elif r.headers.get("content-type", "") != baseline.headers.get("content-type", ""):
                found.append({
                    "host": host,
                    "header": header,
                    "behavior_change": True,
                    "cache_control": cc,
                })
        return found

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_probe, h): h for h in live_hosts[:30]}
        for fut in as_completed(futs):
            result = fut.result()
            results.extend(result)
            for r in result:
                if r.get("reflected"):
                    _add_finding(findings, "cache", "high", "cache_reflected_header",
                                 r["host"],
                                 f"Unkeyed header {r['header']} reflected in response — cache poison candidate",
                                 detail=f"cache-control={r['cache_control']}",
                                 evidence=r)

    (out_dir / "cache_probe.json").write_text(json.dumps(results, indent=2))
    ok(f"  Cache probe done — {len(results)} potential unkeyed headers")

# ─── Phase 13 · WebSocket Discovery ──────────────────────────────────────────

_WS_RE = re.compile(
    r"""(?:new\s+WebSocket|io\.connect|socket\.io)\s*\(\s*['"]([^'"]{6,})['"]"""
    r"""|["']wss?://([^\s'"<>]{6,})["']""",
    re.IGNORECASE,
)

def phase_websocket(urls_file: Path, js_dir: Path, outdir: Path, session,
                    findings: list):
    phase_header("13", "WebSocket Discovery")
    out_dir = outdir / "websockets"
    out_dir.mkdir(parents=True, exist_ok=True)
    ws_urls = set()

    # Scan all_urls.txt for ws:// links
    if urls_file.exists():
        for line in urls_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(("ws://", "wss://")):
                ws_urls.add(line)

    # Scan downloaded JS files
    js_sources = []
    if js_dir.exists():
        js_sources = list(js_dir.rglob("*.js"))
        info(f"  Scanning {len(js_sources)} JS files for WebSocket URLs …")
        for jf in js_sources:
            try:
                content = jf.read_text(errors="ignore")
                for m in _WS_RE.finditer(content):
                    url = m.group(1) or m.group(2)
                    if url:
                        ws_urls.add(url)
            except Exception:
                pass

    info(f"  Found {len(ws_urls)} WebSocket URLs")

    for ws_url in ws_urls:
        with _lock:
            print(f"  {cyan('[WS]')} {ws_url}")
        _add_finding(findings, "websocket", "info", "websocket_url",
                     ws_url, f"WebSocket endpoint discovered: {ws_url}",
                     evidence=ws_url)

    # Probe open-auth (no cookie / auth header)
    tested = []
    for ws_url in list(ws_urls)[:10]:
        # Try HTTP upgrade check (can't do real WS upgrade easily without extra lib)
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        r = _safe_get(session, http_url, timeout=8)
        if r and r.status_code in (200, 101, 426):
            tested.append({"url": ws_url, "http_status": r.status_code})
            # 400 Bad Request is the EXPECTED response to a plain HTTP GET on a WS endpoint —
            # not a sign of open access. Only 200/101 indicates the endpoint responds without auth.
            if r.status_code in (200, 101):
                _add_finding(findings, "websocket", "low", "websocket_no_auth",
                             ws_url, f"WebSocket endpoint responds without auth (HTTP {r.status_code})",
                             evidence={"url": ws_url, "status": r.status_code})

    if ws_urls:
        (out_dir / "ws_urls.txt").write_text("\n".join(sorted(ws_urls)) + "\n")
    ok(f"  WebSocket phase done — {len(ws_urls)} URLs found")

# ─── Phase 14 · CI/CD Exposure ────────────────────────────────────────────────

def phase_cicd(live_hosts: list, outdir: Path, session, findings: list, threads: int = 15):
    phase_header("14", "CI/CD / Admin Panel Exposure")
    if not live_hosts:
        return

    out_dir = outdir / "cicd"
    out_dir.mkdir(parents=True, exist_ok=True)
    info(f"  Probing {len(live_hosts) * len(CICD_PATHS)} paths …")
    found = []

    # ── Catch-all / SPA detection ────────────────────────────────────────────
    # Probe a canary path that must not exist. A host is catch-all if it returns
    # 200 (SPA) or 301/302 to a fixed destination (redirect catch-all) for it.
    # We record both the status AND the redirect target so _probe can compare.
    catchall_hosts: set = set()        # suppress 200 results
    redirect_catchall: dict = {}       # host → canonical redirect target

    def _check_catchall(host: str):
        url = host.rstrip("/") + _CICD_CANARY
        r = _safe_get(session, url, timeout=6)
        if not r:
            return None, None
        if r.status_code == 200:
            return host, None
        if r.status_code in (301, 302, 303, 307, 308):
            return host, r.headers.get("location", "")
        return None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for host, redirect_target in ex.map(_check_catchall, live_hosts):
            if not host:
                continue
            if redirect_target is None:
                catchall_hosts.add(host)
            else:
                redirect_catchall[host] = redirect_target

    if catchall_hosts or redirect_catchall:
        warn(f"  Catch-all detected on {len(catchall_hosts) + len(redirect_catchall)} host(s) "
             f"({len(catchall_hosts)} SPA, {len(redirect_catchall)} redirect) — suppressing CI/CD false positives")

    def _probe(host, path, label, sev):
        host_clean = host.rstrip("/")
        url = host_clean + path
        r = _safe_get(session, url, timeout=8)
        if not r or r.status_code in (404, 410):
            return None
        if r.status_code not in (200, 201, 301, 302, 401, 403):
            return None

        ct = r.headers.get("content-type", "")

        # Redirect catch-all: skip if host redirects everything to the same target
        if r.status_code in (301, 302, 303, 307, 308) and host in redirect_catchall:
            if r.headers.get("location", "") == redirect_catchall[host]:
                return None

        # For JSON-API paths (Jenkins API, Spring Actuator), a text/html response
        # means the host is a SPA catch-all or returned an error page — not real.
        if r.status_code == 200 and path in _CICD_JSON_PATHS:
            if "application/json" not in ct and "vnd.spring" not in ct:
                return None

        # For HTML-based admin UIs, require at least one known keyword in the body.
        if r.status_code == 200 and path in _CICD_BODY_SIGNATURES:
            body_lower = r.text[:4096].lower()
            if not any(kw in body_lower for kw in _CICD_BODY_SIGNATURES[path]):
                return None

        # Generic catch-all guard: any remaining 200 on a known catch-all host is
        # suppressed (covers paths not in the signature map above).
        if r.status_code == 200 and host in catchall_hosts:
            return None

        return {
            "url": url, "status": r.status_code, "label": label, "severity": sev,
            "size": len(r.content), "ct": ct[:60],
        }

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        for host in live_hosts:
            for path, label, sev in CICD_PATHS:
                futs[ex.submit(_probe, host, path, label, sev)] = (host, path)
        for fut in as_completed(futs):
            result = fut.result()
            if not result:
                continue
            found.append(result)
            _add_finding(findings, "cicd", result["severity"], "cicd_exposed",
                         result["url"],
                         f"{result['label']} accessible (HTTP {result['status']})",
                         detail=f"size={result['size']} ct={result['ct']}",
                         evidence=result)

    (out_dir / "cicd_findings.json").write_text(json.dumps(found, indent=2))
    ok(f"  CI/CD phase done — {len(found)} paths found")

# ─── Phase 15 · Next.js Data Probe ───────────────────────────────────────────

_NEXT_BUILD_RE = re.compile(r'/_next/static/([a-zA-Z0-9_-]{8,})/[^"\']+\.js')
_NEXT_DATA_RE  = re.compile(r'"buildId"\s*:\s*"([a-zA-Z0-9_-]{8,})"')

NEXT_PROBE_PAGES = [
    "/", "/index", "/home", "/about", "/login", "/register",
    "/dashboard", "/profile", "/account", "/settings", "/admin",
    "/api", "/blog", "/products", "/contact",
]

def phase_nextjs(live_hosts: list, httpx_jsonl: Path, outdir: Path, session,
                 findings: list, threads: int = 10):
    phase_header("15", "Next.js Data Probe")

    # Detect Next.js hosts from tech field
    nextjs_hosts = set()
    if httpx_jsonl.exists():
        for line in httpx_jsonl.read_text().splitlines():
            try:
                rec = json.loads(line)
                techs = [t.lower() for t in rec.get("tech", [])]
                if any("next" in t for t in techs):
                    nextjs_hosts.add(rec.get("url", "").rstrip("/"))
            except Exception:
                pass

    # Also check /_next/ presence for all live hosts
    if not nextjs_hosts and live_hosts:
        info("  Detecting Next.js by probing /_next/static/ …")
        def _detect(host):
            host = host.rstrip("/")
            r = _safe_get(session, host, timeout=10)
            if r and "/_next/" in r.text:
                return host
            return None
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for host in as_completed({ex.submit(_detect, h): h for h in live_hosts[:20]}):
                result = host.result()
                if result:
                    nextjs_hosts.add(result)

    if not nextjs_hosts:
        info("  No Next.js hosts detected — skipping")
        return

    info(f"  {len(nextjs_hosts)} Next.js hosts found")
    out_dir = outdir / "nextjs"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _get_build_id(host):
        # Try fetching root page and extracting __NEXT_DATA__ or buildId
        r = _safe_get(session, host, timeout=10)
        if not r:
            return None
        # From embedded __NEXT_DATA__ JSON
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>\s*({.+?})\s*</script>', r.text, re.DOTALL)
        if m:
            try:
                d = json.loads(m.group(1))
                return d.get("buildId")
            except Exception:
                pass
        # Note: _NEXT_BUILD_RE would extract a chunk content-hash from /_next/static/<hash>/
        # paths, which is NOT the buildId. Without __NEXT_DATA__, buildId is unknown.
        return None

    for host in nextjs_hosts:
        build_id = _get_build_id(host)
        if not build_id:
            info(f"  {host} → could not extract buildId")
            continue
        ok(f"  {host} → buildId={build_id}")

        data_endpoints = []
        for page in NEXT_PROBE_PAGES:
            url = f"{host}/_next/data/{build_id}{page}.json"
            r = _safe_get(session, url, timeout=8)
            if not r or r.status_code not in (200,):
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if "pageProps" in data:
                data_endpoints.append({"url": url, "status": r.status_code,
                                        "size": len(r.content),
                                        "keys": list(data.get("pageProps", {}).keys())[:10]})
                _add_finding(findings, "nextjs", "medium", "nextjs_data_endpoint",
                             url, f"Next.js data endpoint exposed: {page}.json",
                             detail=f"pageProps keys: {list(data.get('pageProps',{}).keys())[:10]}",
                             evidence={"url": url, "build_id": build_id, "page": page})

        if data_endpoints:
            fname = host.replace("://", "_").replace("/", "_")
            (out_dir / f"{fname[:60]}_data.json").write_text(json.dumps(data_endpoints, indent=2))

    ok(f"  Next.js phase done")

# ─── Phase 16 · Exploit Mapper ────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

def phase_exploit_mapper(findings: list, outdir: Path):
    """
    Phase 16 — Map CVEs detected in previous phases to local exploits in tools/cve/.
    Prints path + files for every CVE that has a matching subdirectory.
    """
    phase_header("16", "Exploit Mapper — Local CVE Inventory")

    if not RAPTOR_CVE_DIR.exists():
        warn(f"  tools/cve/ not found at {RAPTOR_CVE_DIR} — skipping")
        return

    # Collect CVE IDs from all findings
    cve_ids: set = set()
    for f in findings:
        text = str(f.get("title", "")) + " " + str(f.get("detail", ""))
        for m in _CVE_RE.findall(text):
            cve_ids.add(m.upper())

    if not cve_ids:
        info("  No CVE findings from previous phases — skipping exploit mapper")
        return

    hits = []
    for cve_id in sorted(cve_ids):
        cve_dir = RAPTOR_CVE_DIR / cve_id
        if cve_dir.exists() and cve_dir.is_dir():
            files = sorted(p.name for p in cve_dir.iterdir() if p.is_file())
            hits.append({"cve": cve_id, "path": str(cve_dir), "files": files})

    if hits:
        ok(f"  {len(hits)}/{len(cve_ids)} CVEs have local exploits in tools/cve/:")
        for hit in hits:
            print(f"    {bold(hit['cve'])}  →  {cyan(hit['path'])}")
            for fname in hit["files"][:4]:
                print(f"      {dim(fname)}")
            if len(hit["files"]) > 4:
                extra = len(hit["files"]) - 4
                print(f"      {dim(f'… {extra} more')}")
        (outdir / "exploit_map.json").write_text(json.dumps(hits, indent=2))
        ok(f"  exploit_map.json written")
    else:
        missing = sorted(cve_ids)[:8]
        info(f"  No local exploits matched {len(cve_ids)} detected CVEs")
        info(f"  Checked: {', '.join(missing)}{'…' if len(cve_ids) > 8 else ''}")

# ─── Report ───────────────────────────────────────────────────────────────────

def write_report(base: Path, findings: list, target: str, phases_run: list):
    report = base / "inspect_report.md"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    counts = {}
    by_phase = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        phase = f.get("phase", "other")
        by_phase.setdefault(phase, []).append(f)

    lines = [
        f"# web_inspect.py Report — {target}",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        lines.append(f"| {sev.capitalize()} | {n} |")

    lines += ["", f"Phases run: {', '.join(str(p) for p in phases_run)}", ""]

    for phase, pfindings in sorted(by_phase.items()):
        lines.append(f"## Phase: {phase}")
        lines.append("")
        for f in sorted(pfindings, key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info"))):
            sev = f.get("severity", "info")
            lines.append(f"- **[{sev.upper()}]** `{f.get('host','')}` — {f.get('title','')}")
            if f.get("detail"):
                lines.append(f"  - {f['detail']}")
        lines.append("")

    report.write_text("\n".join(lines))
    return report

def print_summary(findings: list, base: Path):
    counts = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    print()
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        col = red if sev == "critical" else (red if sev == "high" else (yellow if sev == "medium" else dim))
        tag = col(str(n).rjust(4)) if n else dim("   0")
        print(f"  {tag}  {sev}")

    print()
    print(f"  {cyan('inspect_report.md')}  full report")
    print(f"  {cyan('findings.jsonl')}     structured findings")
    print(f"  {dim(str(base))}")
    print()

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="web_inspect.py",
        description="Deep web surface analysis — headers, DNS, TLS, GraphQL, OpenAPI, CI/CD, …",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--recon-dir",   metavar="DIR",  help="recon.py output dir (auto-loads all inputs)")
    p.add_argument("--secret-dir",  metavar="DIR",  help="secret-scan.py output dir (JS files for WS scan)")
    p.add_argument("--hosts",       metavar="FILE", help="Live hosts file (one URL per line)")
    p.add_argument("--ips",         metavar="FILE", help="IPs file (one IP per line)")
    p.add_argument("--domain",      metavar="DOMAIN", help="Primary domain for DNS queries")
    p.add_argument("-o", "--output", metavar="DIR", help="Output directory")
    p.add_argument("--tor",         action="store_true", help="Route HTTP requests via TOR (socks5h://127.0.0.1:9050)")
    p.add_argument("--threads",     type=int, default=20, help="Concurrent threads (default: 20)")
    p.add_argument("--user-agent",  default=DEFAULT_UA, metavar="UA", help="HTTP User-Agent")
    p.add_argument("--timeout",     type=int, default=12, help="HTTP timeout seconds (default: 12)")
    # Skip flags
    p.add_argument("--skip-headers",  action="store_true", help="Skip phases 0+1+2 (header/CSP/cookie)")
    p.add_argument("--skip-dns",      action="store_true", help="Skip phase 3 (DNS security)")
    p.add_argument("--skip-cve",      action="store_true", help="Skip phase 4 (Tech→CVE)")
    p.add_argument("--skip-nvd",      action="store_true", help="Skip NVD API queries (use local DB only)")
    p.add_argument("--skip-favicon",  action="store_true", help="Skip phase 5 (favicon hash)")
    p.add_argument("--skip-content",  action="store_true", help="Skip phase 6 (robots/sitemap)")
    p.add_argument("--skip-asn",      action="store_true", help="Skip phase 7 (ASN/reverse IP)")
    p.add_argument("--skip-tls",      action="store_true", help="Skip phase 8 (TLS/SAN)")
    p.add_argument("--skip-graphql",  action="store_true", help="Skip phase 9 (GraphQL)")
    p.add_argument("--skip-openapi",  action="store_true", help="Skip phase 10 (OpenAPI/Swagger)")
    p.add_argument("--skip-403",      action="store_true", help="Skip phase 11 (403 bypass)")
    p.add_argument("--skip-cache",    action="store_true", help="Skip phase 12 (cache probe)")
    p.add_argument("--skip-ws",       action="store_true", help="Skip phase 13 (WebSocket)")
    p.add_argument("--skip-cicd",     action="store_true", help="Skip phase 14 (CI/CD)")
    p.add_argument("--skip-nextjs",   action="store_true", help="Skip phase 15 (Next.js probe)")
    p.add_argument("--skip-exploits", action="store_true", help="Skip phase 16 (exploit mapper — tools/cve/ lookup)")
    return p

def _banner():
    print(f"""
{C.BD}{C.B}╔══════════════════════════════════════════════════════════════╗
║  web_inspect.py — Deep Web Surface Analysis  v1.0           ║
╚══════════════════════════════════════════════════════════════╝{C.RS}""")

def main():
    _source_bashrc()
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = build_parser()
    args = parser.parse_args()

    if not HAS_REQUESTS:
        err("requests not installed — pip install requests")
        sys.exit(1)

    _banner()

    # ── Resolve inputs ──────────────────────────────────────────────────────
    recon_dir = Path(args.recon_dir) if args.recon_dir else None
    secret_dir = Path(args.secret_dir) if args.secret_dir else None

    # Auto-detect files from recon-dir
    httpx_jsonl     = Path("/dev/null")
    httpx_live      = Path("/dev/null")
    ips_file        = Path("/dev/null")
    urls_file       = Path("/dev/null")
    js_dir          = Path("/dev/null")

    if recon_dir:
        candidates = {
            "httpx_jsonl": [
                recon_dir / "httpx" / "httpx_results.jsonl",
                recon_dir / "httpx_results.jsonl",
            ],
            "httpx_live": [
                recon_dir / "httpx" / "httpx_live.txt",
                recon_dir / "httpx_live.txt",
            ],
            "ips_file": [
                recon_dir / "ips" / "unique_ips.txt",
                recon_dir / "unique_ips.txt",
            ],
            "urls_file": [
                recon_dir / "urls" / "all_urls.txt",
                recon_dir / "all_urls.txt",
            ],
        }
        for attr, paths in candidates.items():
            for p in paths:
                if p.exists():
                    locals()[attr]  # just to reference — see below
                    if attr == "httpx_jsonl":   httpx_jsonl = p
                    elif attr == "httpx_live":  httpx_live = p
                    elif attr == "ips_file":    ips_file = p
                    elif attr == "urls_file":   urls_file = p
                    break

    if args.hosts:
        httpx_live = Path(args.hosts)
    if args.ips:
        ips_file = Path(args.ips)

    if secret_dir and (secret_dir / "js").exists():
        js_dir = secret_dir / "js"

    # Load live hosts
    live_hosts = []
    if httpx_live.exists():
        live_hosts = [ln.strip() for ln in httpx_live.read_text().splitlines() if ln.strip()]
    info(f"Loaded {len(live_hosts)} live hosts")

    # Guess domain if not provided
    domain = args.domain
    if not domain and live_hosts:
        try:
            hostname = urlparse(live_hosts[0]).hostname or ""
            domain = _extract_domain(hostname)
        except Exception:
            pass
    if not domain and recon_dir:
        m = re.match(r"([a-zA-Z0-9.-]+)_\d{8}", Path(recon_dir).name)
        if m:
            domain = m.group(1)
    if domain:
        info(f"Target domain: {domain}")

    # ── Output directory ────────────────────────────────────────────────────
    if args.output:
        base = Path(args.output)
    elif recon_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = recon_dir / f"inspect_{ts}"
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = Path(f"inspect_{ts}")
    base.mkdir(parents=True, exist_ok=True)
    info(f"Output: {base}")

    # ── Session ─────────────────────────────────────────────────────────────
    session = _make_session(args.tor, args.user_agent)
    if args.tor:
        info("TOR proxy active (socks5h://127.0.0.1:9050)")

    findings = []
    phases_run = []

    # ── Phase 0+1+2: Headers · CSP · Cookies ───────────────────────────────
    if not args.skip_headers:
        phase_headers(live_hosts, base, session, findings, threads=args.threads)
        phases_run += [0, 1, 2]

    # ── Phase 3: DNS Security ───────────────────────────────────────────────
    if not args.skip_dns:
        if domain:
            phase_dns(domain, base, findings)
            phases_run.append(3)
        else:
            warn("  --domain not set, skipping DNS phase (pass --domain example.com)")

    # ── Phase 4: Tech → CVE ─────────────────────────────────────────────────
    if not args.skip_cve:
        phase_tech_cve(httpx_jsonl, base, session, findings, skip_nvd=args.skip_nvd)
        phases_run.append(4)

    # ── Phase 5: Favicon Hash ───────────────────────────────────────────────
    if not args.skip_favicon:
        phase_favicon(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(5)

    # ── Phase 6: Content Recon ──────────────────────────────────────────────
    if not args.skip_content:
        phase_content_recon(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(6)

    # ── Phase 7: ASN + Reverse IP ───────────────────────────────────────────
    if not args.skip_asn:
        phase_asn(ips_file, base, session, findings)
        phases_run.append(7)

    # ── Phase 8: TLS / SAN ──────────────────────────────────────────────────
    if not args.skip_tls:
        phase_tls(live_hosts, base, findings, threads=args.threads)
        phases_run.append(8)

    # ── Phase 9: GraphQL ────────────────────────────────────────────────────
    if not args.skip_graphql:
        phase_graphql(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(9)

    # ── Phase 10: OpenAPI / Swagger ─────────────────────────────────────────
    if not args.skip_openapi:
        phase_openapi(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(10)

    # ── Phase 11: 403 Bypass ────────────────────────────────────────────────
    if not args.skip_403:
        phase_403_bypass(httpx_jsonl, base, session, findings)
        phases_run.append(11)

    # ── Phase 12: Cache Probe ───────────────────────────────────────────────
    if not args.skip_cache:
        phase_cache_probe(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(12)

    # ── Phase 13: WebSocket ─────────────────────────────────────────────────
    if not args.skip_ws:
        phase_websocket(urls_file, js_dir, base, session, findings)
        phases_run.append(13)

    # ── Phase 14: CI/CD ─────────────────────────────────────────────────────
    if not args.skip_cicd:
        phase_cicd(live_hosts, base, session, findings, threads=args.threads)
        phases_run.append(14)

    # ── Phase 15: Next.js ───────────────────────────────────────────────────
    if not args.skip_nextjs:
        phase_nextjs(live_hosts, httpx_jsonl, base, session, findings, threads=args.threads)
        phases_run.append(15)

    # ── Phase 16: Exploit Mapper ─────────────────────────────────────────────
    if not args.skip_exploits:
        phase_exploit_mapper(findings, base)
        phases_run.append(16)

    # ── Save findings ────────────────────────────────────────────────────────
    findings_path = base / "findings.jsonl"
    _write_jsonl(findings_path, findings)

    # ── Report ───────────────────────────────────────────────────────────────
    report = write_report(base, findings, domain or "target", phases_run)

    # ── Summary ─────────────────────────────────────────────────────────────
    phase_header("✓", "Complete")
    print(f"\n{bold('Output:')} {base}\n")
    print_summary(findings, base)


if __name__ == "__main__":
    main()
