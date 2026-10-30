# Em Fase de Testes

# Guia Prático

Três scripts Python independentes para reconhecimento web e bug bounty autorizados.

---

## Índice

- [recon.py — Pipeline Completo de Recon](#reconpy--pipeline-completo-de-recon)
- [secret-scan.py — Scanner de Segredos e Endpoints JS](#secret-scanpy--scanner-de-segredos-e-endpoints-js)
- [web_inspect.py — Análise Profunda de Superfície Web](#web_inspectpy--análise-profunda-de-superfície-web)
- [Workflow: Encadeando as Três Ferramentas](#workflow-encadeando-as-três-ferramentas)
- [Instalação dos Requisitos](#instalação-dos-requisitos)

---

## recon.py — Pipeline Completo de Recon

**Versão:** v1.3
**Objetivo:** Enumeração de subdomínios → validação de hosts vivos → coleta de URLs → varredura de vulnerabilidades → descoberta de buckets em nuvem.

### Fases

| Fase | O que faz | Ferramentas |
|------|-----------|-------------|
| 1 | Enumeração de subdomínios (14 fontes em paralelo) | crt.sh, chaos, github-subdomains, assetfinder, subfinder, amass, findomain, shodanx, subcat, alienvault OTX, webarchive, urlscan.io |
| 1.5 *(opcional)* | Brute force de DNS | puredns → dnsx → massdns (cadeia de fallback) |
| 2 | Validação httpx — hosts vivos + extração de IPs + port scan | httpx |
| 2c | Fingerprinting de CMS/framework (passivo + 40+ sondas ativas) | httpx tech-detect + sondas HTTP |
| 2d | Detecção de WAF nos hosts vivos | wafw00f |
| 2.5 | Detecção de subdomain takeover (CNAME dangling + fingerprint) | dnsx, subjack, subzy, nuclei |
| 3 | Coleta de URLs (9 fontes passivas + 4 crawlers ativos) | gau, waybackurls, wayback-api, commoncrawl, waymore, paramspider, katana, hakrawler, gospider |
| 3.5 | Extração de endpoints a partir de arquivos JS | regex (4 padrões) + linkfinder *(opcional)* |
| 4 | Filtragem de padrões GF nas URLs coletadas | gf |
| 5 | Fuzzing com Nuclei nas URLs filtradas + URLs brutas | nuclei + fuzzing-templates/ |
| 6 | Descoberta de buckets em nuvem (S3, GCS, Azure) | sondas HTTP paralelas |

### Detecção de CMS/Framework (Phase 2c)

Detecta 65+ CMS e frameworks incluindo WordPress, Drupal, Joomla, PrestaShop, OpenCart, Magento, Shopify, VTEX, Strapi, Ghost, AEM, Next.js, Nuxt.js, Laravel, Django, Spring, Ruby on Rails, ASP.NET, TYPO3, Craft CMS e outros.

Hosts com superfície de CVE conhecida (WordPress, Drupal, OpenCart, Joomla, etc.) são destacados com marcador `⚑` no sumário.

### Phase 2d — WAF Detection

Roda `wafw00f` contra todos os hosts vivos e reporta:
- **Vendor e produto** do WAF detectado por host
- Hosts sem proteção (direto ao backend)

Output: `waf/wafw00f_results.json`

### Phase 3.5 — JS Endpoint Extraction

Filtra todos os arquivos `.js` coletados (ignorando CDNs como jQuery, Bootstrap, GTM) e extrai endpoints de API via:
- Regex sobre `fetch(`, `axios.get(`, `url=`, `endpoint=`, paths `/api/`, `/v1/`, `/graphql/`
- Pass com `linkfinder` se instalado (primeiros 100 JS)

Endpoints novos são **appendados automaticamente ao `all_urls.txt`** para que GF e nuclei os processem na fase seguinte.

Output: `js_endpoints/all_js_endpoints.txt`

### Phase 6 — Cloud Bucket Discovery (otimizada)

Gera candidatos a partir do domínio (prefixo, sufixos, variações com/sem TLD) e testa S3, GCS e Azure em paralelo:

| Otimização | Detalhe |
|------------|---------|
| S3 + GCS + Azure paralelos por nome | 3 threads internas por candidato |
| Azure: early-exit por DNS | Detecta conta inexistente com 1 HEAD antes de testar 24 containers |
| Probing de objetos paralelo | 20 HEADs simultâneos (vs. sequencial antes) |
| 50 workers externos | Dobrado de 25 |
| `--no-bucket-objects` | Pula enumeração de arquivos sensíveis (scan ~4x mais rápido) |

### Instalação

```bash
# Dependência Python
pip install requests

# Ferramentas principais (Go)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/gf@latest

# Coletores de URL
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/gospider@latest
pip install waymore paramspider

# Brute force de DNS (instale pelo menos um)
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# massdns: https://github.com/blechschmidt/massdns

# Detecção de WAF
pip install wafw00f

# Extração de endpoints JS (opcional)
pip install LinkFinder

# Takeover
go install github.com/haccer/subjack@latest
go install github.com/PentestPad/subzy@latest

# Opcional: amass, findomain
go install github.com/owasp-amass/amass/v4/...@master
# findomain: https://github.com/Findomain/Findomain/releases

# Padrões GF (obrigatório estar em ~/.gf/)
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Templates de fuzzing do Nuclei
nuclei -update-templates
```

### Chaves de API (opcional, mas recomendado)

```bash
export CHAOS_KEY="sua_chave_projectdiscovery"
export GITHUB_TOKEN="ghp_seutoken"
```

### Uso

```bash
# Básico — pipeline completo
python3 recon.py exemplo.com.br

# Diretório de saída personalizado
python3 recon.py exemplo.com.br -o /tmp/resultados_recon

# Rotear via TOR
python3 recon.py exemplo.com.br --tor

# Habilitar brute force de DNS (Fase 1.5)
python3 recon.py exemplo.com.br --brute-force \
    --brute-wordlist /path/para/subdomains-top1million-110000.txt

# Pular nuclei (recon mais rápido)
python3 recon.py exemplo.com.br --skip-nuclei

# Rodar apenas padrões nuclei específicos
python3 recon.py exemplo.com.br --nuclei-patterns xss sqli crlf xxe

# Retomar a partir de um arquivo de subdomínios existente
python3 recon.py exemplo.com.br --subdomains-file /tmp/subs.txt --skip-enum

# Ajuste fino do nuclei
python3 recon.py exemplo.com.br \
    --user-agent "Mozilla/5.0 Custom" \
    --rate-limit 50 \
    --concurrency 10

# Bucket scan rápido (sem enumerar arquivos sensíveis)
python3 recon.py exemplo.com.br --no-bucket-objects

# Pular fases específicas
python3 recon.py exemplo.com.br \
    --skip-waf \
    --skip-js-endpoints \
    --skip-fingerprint \
    --skip-takeover \
    --skip-buckets

# Apenas descoberta de buckets
python3 recon.py exemplo.com.br --buckets-only
```

### Flags de Skip

| Flag | Fase pulada |
|------|------------|
| `--skip-enum` | Enumeração de subdomínios (Fase 1) |
| `--skip-httpx` | Validação httpx (Fase 2) |
| `--skip-fingerprint` | Fingerprinting CMS/framework (Fase 2c) |
| `--skip-waf` | Detecção de WAF (Fase 2d) |
| `--skip-takeover` | Subdomain takeover (Fase 2.5) |
| `--skip-urls` | Coleta de URLs (Fase 3) |
| `--skip-js-endpoints` | Extração de endpoints JS (Fase 3.5) |
| `--skip-gf` | Filtragem GF (Fase 4) |
| `--skip-nuclei` | Fuzzing nuclei (Fase 5) |
| `--skip-buckets` | Descoberta de buckets (Fase 6) |
| `--no-bucket-objects` | Pula enumeração de arquivos sensíveis nos buckets |
| `--brute-force` | *Ativa* brute force de DNS (Fase 1.5 — off por padrão) |
| `--buckets-only` | Executa apenas a Fase 6 |

### Estrutura de Saída

```
recon_output/exemplo.com.br_20261001_120000/
├── subdomains/
│   ├── raw_crtsh.txt          # Resultados brutos por fonte
│   ├── raw_subfinder.txt
│   ├── raw_*.txt
│   └── all_subdomains.txt     # Mesclado + deduplicado
├── httpx/
│   ├── httpx_results.jsonl    # JSON completo por host (tech, título, status)
│   └── httpx_live.txt         # URLs vivas com esquema (https://)
├── hosts/
│   └── live_hosts.txt         # Hostnames sem esquema
├── ips/
│   └── unique_ips.txt         # IPv4/IPv6 resolvidos
├── fingerprint/
│   ├── tech_summary.json      # Breakdown CMS/framework + contagens
│   └── cms_wordpress.txt      # Listas de hosts por CMS
├── waf/
│   └── wafw00f_results.json   # Vendor/produto por host
├── takeover/
│   ├── candidates.txt         # Hosts com código não-2xx/3xx ou sem resposta
│   ├── cname_dangling.txt     # CNAMEs dangling (dnsx)
│   ├── subjack_results.txt    # Findings do subjack
│   └── nuclei_takeover_*.txt  # Findings do nuclei
├── urls/
│   ├── raw_gau.txt            # Listas de URLs por ferramenta
│   ├── raw_*.txt
│   └── all_urls.txt           # Mesclado + deduplicado (+ endpoints JS appendados)
├── js_endpoints/
│   ├── all_js_endpoints.txt   # Endpoints extraídos de JS
│   └── linkfinder_raw.txt     # Saída bruta do linkfinder (se instalado)
├── gf/
│   ├── gf_xss.txt             # URLs com parâmetros de XSS
│   ├── gf_sqli.txt
│   └── gf_*.txt               # Um arquivo por padrão
├── nuclei/
│   ├── nuclei_xss.txt         # Findings legíveis
│   └── nuclei_xss.jsonl       # Findings estruturados
└── buckets/
    └── bucket_findings.json   # Todos os findings (readable, writable, objects)
```

---

## secret-scan.py — Scanner de Segredos e Endpoints JS

**Versão:** v2.1
**Objetivo:** Encontrar segredos (chaves de API, tokens, credenciais) e endpoints de API escondidos em arquivos JavaScript e source maps. Funciona de forma independente ou como pós-processador do `recon.py`.

### Fases

| Fase | O que faz |
|------|-----------|
| 0 | Descoberta de portas nos IPs (nmap ou fallback socket) |
| 1 | Descoberta de arquivos JS: filtro no all_urls.txt + sondagem de caminhos comuns |
| 1b | Crawl com browser headless Playwright (captura chunks JS carregados dinamicamente) |
| 2 | Download concurrent de JS (pula CDNs automaticamente) |
| 3 | Descompilação de source maps (arquivos `.map` → código-fonte original) |
| 4 | Scan de segredos: **66 padrões regex** em todos os arquivos + JWT decode inline |
| 4b | Validação ao vivo de chaves contra APIs reais |
| 5b | Sondagem de arquivos sensíveis (`.env`, `config.json`, etc.) |
| 5 | Extração de endpoints de API a partir do JS (6 padrões de base URL) |

### Padrões de Segredo (66 no total)

| Categoria | Padrões |
|-----------|---------|
| Cloud | AWS Access Key, AWS Secret, GCP Service Account, Azure Storage |
| Controle de Versão | GitHub PAT (fine + classic), GitHub OAuth/Actions, GitLab PAT |
| Pagamentos | Stripe (live/test), Square OAuth, PayPal/Braintree |
| Mensageria | Slack Token/Webhook, Discord Webhook, Twilio SID, SendGrid, Mailgun, Mailchimp, **Brevo API Key**, **Resend API Key** |
| IA/LLM | Anthropic API Key, OpenAI API Key, HuggingFace Token |
| Backend | Firebase Server Key, Supabase JWT (service_role), Heroku, **npm auth token** (npmrc), strings de conexão DB |
| Infraestrutura | DigitalOcean, HashiCorp Vault, Cloudflare, Doppler, Terraform Cloud, Vercel, Netlify, **Neon Token**, **Clerk Secret Key**, **Okta SSWS Token** |
| Genérico | Credenciais hardcoded, URLs basic-auth, chaves privadas (PEM), IPs internos, tokens JWT |

**JWT decode inline:** Quando um padrão `jwt_token` ou `supabase_key` é encontrado, o header e payload são decodificados automaticamente. O campo `jwt_info` mostra `alg`, `sub`, `iss`, `exp`, `role` e `email` sem chamada externa.

### Validação de Chaves

| Padrão | Método de validação |
|--------|---------------------|
| GitHub PAT | `GET api.github.com/user` |
| GitLab PAT | `GET gitlab.com/api/v4/user` |
| Stripe | `GET api.stripe.com/v1/charges` |
| Slack | `GET slack.com/api/auth.test` |
| OpenAI | `GET api.openai.com/v1/models` |
| Anthropic | `POST api.anthropic.com/v1/messages` (sonda de 1 token) |
| AWS | `aws sts get-caller-identity` |
| Google Maps | Sonda da API de Geocoding |
| SendGrid, npm, HuggingFace, Discord, Mapbox, Mailchimp, Twilio, Cloudflare, DigitalOcean | Endpoint da respectiva API |

### Instalação

```bash
pip install requests

# Opcional: browser headless (chunks JS dinâmicos)
pip install playwright && playwright install chromium

# Opcional: AWS CLI (validação de chaves AWS)
pip install awscli

# Opcional: scanner adicional
# trufflehog: https://github.com/trufflesecurity/trufflehog/releases
# gitleaks:   https://github.com/gitleaks/gitleaks/releases

# Opcional: descoberta de portas
apt install nmap
```

### Uso

```bash
# Melhor: alimentar com o diretório de saída do recon.py
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_20261001_120000/

# A partir de arquivos de URLs e hosts manuais
python3 secret-scan.py \
    --urls urls.txt \
    --hosts hosts.txt \
    -o ./saida_segredos

# Escanear diretório JS já baixado
python3 secret-scan.py \
    --js-dir ./js_baixado/ \
    --severity critical,high

# Rotear via TOR
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --tor

# Scan rápido (sem fases lentas)
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --no-playwright \
    --no-port-scan \
    --no-sourcemaps \
    --severity critical,high

# Pular validação ao vivo (offline, mais rápido)
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --no-validate
```

### Estrutura de Saída

```
secret_output/exemplo.com.br_20261001_130000/
├── js/                        # Arquivos JS baixados (nomes com hash)
├── sourcemaps/
│   ├── playwright/            # Arquivos .map do crawl Playwright
│   └── <nome_bundle>/         # Código-fonte descompilado
├── findings/
│   ├── secrets.jsonl          # Todos os findings + resultados de validação + jwt_info
│   ├── secrets_by_type.txt    # Findings agrupados por padrão (ordenados por severidade)
│   ├── endpoints.txt          # Caminhos de API extraídos (inclui baseURL, window.API_URL)
│   ├── gitleaks.json          # Saída do gitleaks (se instalado)
│   └── env_probe.jsonl        # Hits de .env/config exposto
└── report.md                  # Resumo legível (inclui seção por host quando >1 domínio)
```

### Lendo a Saída

```bash
# Apenas chaves ativas confirmadas
jq 'select(.validated.valid == true)' findings/secrets.jsonl

# Filtrar por severidade
jq 'select(.severity == "critical")' findings/secrets.jsonl

# JWTs encontrados + claims decodificados
jq 'select(.jwt_info != null) | {url, jwt_info}' findings/secrets.jsonl

# Listar todos os endpoints extraídos
cat findings/endpoints.txt

# Findings por tipo (agrupados, legível)
cat findings/secrets_by_type.txt
```

---

## web_inspect.py — Análise Profunda de Superfície Web

**Versão:** v1.0
**Objetivo:** Inspeção profunda de hosts vivos — cabeçalhos de segurança, bypass de CSP, segurança DNS, matching de CVE, fingerprint de favicon, GraphQL, OpenAPI, bypass de 403, envenenamento de cache, WebSocket, exposição de CI/CD, score de segurança de e-mail e mais.

### Fases

| Fase | O que verifica |
|------|---------------|
| 0+1+2 | Cabeçalhos de segurança (HSTS + preload, CSP, CSP-Report-Only, X-Frame-Options), Alt-Svc/HTTP2/HTTP3, rate-limit headers, flags de cookie (Secure/HttpOnly/SameSite), CORS |
| 3 | DNS: SPF, DMARC, DKIM, transferência de zona AXFR, CAA, MX + scan de CNAME takeover (18 subs × 15 serviços) |
| 4 | Tecnologia detectada → banco local de CVE + consulta à API NVD |
| 5 | MurmurHash3 de favicon → fingerprints de produtos conhecidos (60+ produtos) |
| 6 | robots.txt, sitemap.xml, `/.well-known/`, `package.json`, `composer.json` expostos |
| 7 | Lookup de ASN (ipinfo.io) + co-hospedagem via IP reverso |
| 8 | Mineração de SAN do certificado TLS → subdomínios ocultos + verificação de expiração |
| 9 | Introspecção GraphQL (15 caminhos comuns) |
| 10 | Descoberta de spec OpenAPI/Swagger + extração de endpoints e esquemas de autenticação |
| 11 | Bypass de 403/401: injeção de cabeçalho + transformações de caminho |
| 12 | Sonda de envenenamento de cache (injeção de cabeçalho sem chave) |
| 13 | Extração de endpoints WebSocket + sonda de acesso sem autenticação |
| 14 | Exposição de painéis CI/CD: Jenkins, Spring Actuator, phpinfo, Grafana, Portainer, Jupyter, Laravel Telescope, Adminer, phpMyAdmin, GitLab CI, `.git/` e 20+ caminhos adicionais |
| 15 | Detecção de BUILD_ID do Next.js → coleta de endpoints JSON em `/_next/data/` |
| 17 | Score de segurança de e-mail: SPF + DMARC + DKIM + CAA → nota 0–10 + conceito A–F |

### Phase 17 — Email Security Score

Analisa a configuração de proteção anti-spoofing do domínio:

| Checagem | Penalidade |
|----------|------------|
| SPF ausente ou `+all` | −3 |
| DMARC ausente ou `p=none` sem reporting | −4 |
| DKIM sem seletor detectado | −2 |
| CAA ausente | −1 |

Score 0–10 → conceito A (≥9) até F (≤3). Output: `email_security/email_score.json`.

### Banco de Favicons (60+ produtos)

Identifica Fortinet FortiGate, Cisco IOS, pfSense, VMware ESXi/vSphere, Jenkins, Grafana, GitLab, Jira, Confluence, Jupyter Notebook, Kubernetes Dashboard, MinIO, pgAdmin, Adminer, phpMyAdmin, OpenVPN, Nagios, Zabbix, Prometheus, Kibana, Sonatype Nexus, JFrog Artifactory, SonarQube, Apache Tomcat, Spring Boot, Traefik, Portainer, RabbitMQ, Webmin, HashiCorp Vault, Harbor, Rancher, Plesk, cPanel, Roundcube e páginas padrão do Nginx/Apache/IIS.

### Banco Local de CVE

Matching instantâneo para PHP, Apache httpd, Nginx, jQuery, WordPress, Drupal, Joomla, Tomcat, Spring (Spring4Shell), Log4j (Log4Shell), OpenSSL, IIS, Struts2, Telerik UI.

### Expiração de Certificado TLS

| Dias restantes | Severidade |
|----------------|-----------|
| < 7 dias | Critical |
| < 30 dias | High |
| < 60 dias | Medium |

### Instalação

```bash
pip install requests
apt install dnsutils  # dig para análise DNS
```

### Uso

```bash
# Melhor: apontar para o diretório de saída do recon.py
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_20261001_120000/ \
    --domain exemplo.com.br

# A partir de arquivos manuais
python3 web_inspect.py \
    --hosts httpx_live.txt \
    --ips unique_ips.txt \
    --domain exemplo.com.br \
    -o ./inspect_out

# Rotear via TOR
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --domain exemplo.com.br \
    --tor

# Filtrar saída do terminal (padrão: medium+, não mostra INFO)
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --domain exemplo.com.br \
    --min-print-sev high      # mostra apenas high e critical

# Pular fases lentas
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --domain exemplo.com.br \
    --skip-dns \
    --skip-asn \
    --skip-nvd \
    --skip-email-score
```

### Flags de Skip

| Flag | Fase pulada |
|------|------------|
| `--skip-headers` | Cabeçalhos + CSP + cookies |
| `--skip-dns` | Análise de segurança DNS + CNAME takeover |
| `--skip-cve` | Matching tecnologia → CVE |
| `--skip-nvd` | Chamadas à API NVD (banco local continua) |
| `--skip-favicon` | Fingerprinting de favicon |
| `--skip-content` | robots.txt, sitemap, well-known, package.json |
| `--skip-asn` | Lookup de ASN + IP reverso |
| `--skip-tls` | Mineração TLS/SAN + verificação de expiração |
| `--skip-graphql` | Introspecção GraphQL |
| `--skip-openapi` | Descoberta de Swagger/OpenAPI |
| `--skip-403` | Teste de bypass de 403 |
| `--skip-cache` | Sonda de envenenamento de cache |
| `--skip-ws` | Descoberta de WebSocket |
| `--skip-cicd` | Detecção de painéis CI/CD |
| `--skip-nextjs` | Sonda de BUILD_ID do Next.js |
| `--skip-email-score` | Score de segurança de e-mail (Fase 17) |
| `--min-print-sev` | Severidade mínima para imprimir no terminal (`info`/`low`/`medium`/`high`/`critical`; padrão: `medium`) |

### Estrutura de Saída

```
inspect_20261001_140000/
├── headers/
│   └── headers.json           # Auditoria de cabeçalhos por host
├── dns/
│   ├── dns_data.json          # SPF/DMARC/DKIM/CAA/MX + CNAME takeover scan
│   └── axfr_ns1.txt           # Dump de transferência de zona (se permitido)
├── tech_cve/
│   └── cve_matches.json       # Matches tecnologia → CVE por host
├── favicons/
│   ├── favicons.json          # Hash + matches de produtos
│   └── *.ico                  # Arquivos de favicon baixados
├── content/
│   ├── content.json           # robots.txt + sitemap + package.json/composer.json
│   └── disallowed_paths.txt   # Entradas Disallow agregadas
├── asn/
│   ├── asn_data.json          # Organização + país por IP
│   └── cohosts.json           # Domínios co-hospedados por IP
├── tls/
│   ├── tls_certs.json         # SANs + dias até expiração por host
│   └── new_san_domains.txt    # SANs fora do escopo original
├── graphql/
│   └── *.json                 # Schema de introspecção por endpoint
├── openapi/
│   ├── *.json                 # Specs brutas
│   └── *_endpoints.txt        # MÉTODO /caminho por spec
├── bypass403/
│   └── bypass_results.json    # Bypasses bem-sucedidos
├── cache/
│   └── cache_results.json     # Candidatos a envenenamento de cache
├── websockets/
│   └── ws_findings.json       # Endpoints WebSocket encontrados
├── cicd/
│   └── cicd_findings.json     # Painéis/configs expostos
├── nextjs/
│   └── nextjs_data.json       # Endpoints /_next/data/
├── email_security/
│   └── email_score.json       # Score 0–10 + conceito A–F + detalhes SPF/DMARC/DKIM/CAA
├── findings.jsonl             # Todos os findings (legível por máquina)
└── report.md                  # Relatório completo legível
```

### Lendo os Findings

```bash
# Todos os findings críticos
jq 'select(.severity == "critical")' findings.jsonl

# Por fase
jq 'select(.phase == "tech_cve")' findings.jsonl

# Bypasses de 403
jq 'select(.type == "bypass_403")' findings.jsonl

# GraphQL exposto
jq 'select(.type == "graphql_introspection")' findings.jsonl

# Problemas SPF/DMARC (spoofing de e-mail)
jq 'select(.phase == "dns")' findings.jsonl

# Score de segurança de e-mail
cat email_security/email_score.json

# Certificados prestes a expirar
jq 'select(.phase == "tls" and .severity == "high")' findings.jsonl
```

---

## Workflow: Encadeando as Três Ferramentas

```bash
# Passo 1 — Recon completo (30–90 min)
python3 recon.py alvo.com.br -o ./resultados

RECON_DIR=$(ls -d ./resultados/alvo.com.br_* | tail -1)

# Passo 2 + 3 em paralelo
python3 secret-scan.py --recon-dir "$RECON_DIR" --severity critical,high &
python3 web_inspect.py --recon-dir "$RECON_DIR" --domain alvo.com.br &

wait
echo "Concluído."
echo "Segredos : $RECON_DIR/../secret_output/"
echo "Inspeção : $RECON_DIR/../inspect_*/"
```

### Com TOR

```bash
systemctl start tor

python3 recon.py      alvo.com.br --tor -o ./resultados
python3 secret-scan.py --recon-dir ./resultados/alvo.com.br_*/ --tor
python3 web_inspect.py --recon-dir ./resultados/alvo.com.br_*/ --domain alvo.com.br --tor
```

### Recon Rápido (pular fases lentas)

```bash
python3 recon.py alvo.com.br \
    --skip-nuclei \
    --skip-buckets \
    --skip-waf \
    -o ./resultados

python3 secret-scan.py \
    --recon-dir ./resultados/alvo.com.br_*/ \
    --no-playwright \
    --no-port-scan \
    --severity critical,high

python3 web_inspect.py \
    --recon-dir ./resultados/alvo.com.br_*/ \
    --domain alvo.com.br \
    --skip-asn \
    --skip-nvd \
    --min-print-sev high
```

---

## Instalação dos Requisitos

### Script de instalação completo

```bash
#!/bin/bash
# Testado em Kali Linux / Ubuntu 22.04+

# Python
pip install requests playwright waymore paramspider wafw00f LinkFinder
playwright install chromium

# Ferramentas Go (requer Go 1.21+)
GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
GOBIN=/usr/local/bin go install github.com/tomnomnom/assetfinder@latest
GOBIN=/usr/local/bin go install github.com/tomnomnom/waybackurls@latest
GOBIN=/usr/local/bin go install github.com/tomnomnom/gf@latest
GOBIN=/usr/local/bin go install github.com/lc/gau/v2/cmd/gau@latest
GOBIN=/usr/local/bin go install github.com/hakluke/hakrawler@latest
GOBIN=/usr/local/bin go install github.com/jaeles-project/gospider@latest
GOBIN=/usr/local/bin go install github.com/d3mondev/puredns/v2@latest
GOBIN=/usr/local/bin go install github.com/haccer/subjack@latest
GOBIN=/usr/local/bin go install github.com/PentestPad/subzy@latest

# Padrões GF
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns
cp /tmp/gf-patterns/*.json ~/.gf/

# Sistema
apt install -y nmap dnsutils tor

# Templates do nuclei
nuclei -update-templates
```

### Instalação mínima

```bash
pip install requests
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

### Variáveis de Ambiente

```bash
export CHAOS_KEY=""          # https://chaos.projectdiscovery.io
export GITHUB_TOKEN=""       # GitHub PAT com escopo read:user
```

---

> **Somente para testes de segurança autorizados e bug bounty.**
> Estas ferramentas realizam requisições ativas na infraestrutura do alvo. Sempre obtenha autorização por escrito antes de executá-las em qualquer sistema que não seja seu.
