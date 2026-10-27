#Em Fase de Testes

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
| 1 | Enumeração de subdomínios | crt.sh, chaos, github-subdomains, assetfinder, subfinder, amass, findomain |
| 1.5 *(opcional)* | Brute force de DNS | puredns → dnsx → massdns (cadeia de fallback) |
| 2 | Validação httpx — hosts vivos + extração de IPs | httpx |
| 2c | Fingerprinting de CMS/framework (passivo + sondas ativas) | httpx tech-detect + sondas HTTP |
| 2.5 | Detecção de subdomain takeover | subjack, subzy, nuclei |
| 3 | Coleta de URLs | gau, waybackurls, wayback-api, commoncrawl, katana, hakrawler, gospider, waymore, paramspider |
| 4 | Filtragem de padrões GF nas URLs coletadas | gf |
| 5 | Fuzzing com Nuclei nas URLs filtradas + URLs brutas | nuclei + fuzzing-templates/ |
| 6 | Descoberta de buckets em nuvem (S3, GCS, Azure) | Sondas HTTP |

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

# Opcional: amass, findomain
go install github.com/owasp-amass/amass/v4/...@master
# findomain: https://github.com/Findomain/Findomain/releases

# Padrões GF (obrigatório estar em ~/.gf/)
git clone https://github.com/tomnomnom/gf ~/.gf-src
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Templates de fuzzing do Nuclei
git clone https://github.com/projectdiscovery/fuzzing-templates \
    $(python3 -c "import os; print(os.environ.get('RAPTOR_DIR','.'))")/nuclei_fuzz/fuzzing-templates
```

### Chaves de API (opcional, mas recomendado)

```bash
# Adicione ao ~/.bashrc ou ~/.zshrc
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
python3 recon.py exemplo.com.br --brute-force

# Wordlist personalizada para brute force
python3 recon.py exemplo.com.br --brute-force \
    --brute-wordlist /path/para/subdomains-top1million-110000.txt

# Pular nuclei (recon mais rápido)
python3 recon.py exemplo.com.br --skip-nuclei

# Rodar apenas padrões nuclei específicos
python3 recon.py exemplo.com.br --nuclei-patterns xss sqli crlf xxe

# Retomar a partir de um arquivo de subdomínios existente (pula Fase 1)
python3 recon.py exemplo.com.br --subdomains-file /tmp/subs.txt --skip-enum

# Ajuste fino do nuclei
python3 recon.py exemplo.com.br \
    --user-agent "Mozilla/5.0 Custom" \
    --rate-limit 50 \
    --concurrency 10

# Pular fases específicas
python3 recon.py exemplo.com.br \
    --skip-fingerprint \
    --skip-takeover \
    --skip-buckets
```

### Estrutura de Saída

```
recon_output/exemplo.com.br_20261001_120000/
├── subdomains/
│   ├── raw_crtsh.txt          # Resultados do crt.sh
│   ├── raw_subfinder.txt      # Resultados do subfinder
│   ├── raw_*.txt              # Resultados brutos por ferramenta
│   └── all_subdomains.txt     # Mesclado + deduplicado
├── httpx/
│   ├── httpx_results.jsonl    # JSON completo por host (tech, título, status)
│   └── httpx_live.txt         # URLs vivas com esquema (https://)
├── hosts/
│   └── live_hosts.txt         # Hostnames sem esquema
├── ips/
│   └── unique_ips.txt         # IPv4/IPv6 resolvidos
├── fingerprint/
│   ├── tech_summary.json      # Detalhamento de CMS/framework
│   └── cms_wordpress.txt      # Listas de hosts por CMS
├── urls/
│   ├── raw_gau.txt            # Listas de URLs por ferramenta
│   └── all_urls.txt           # Mesclado + deduplicado
├── gf/
│   ├── gf_xss.txt             # URLs com parâmetros de XSS
│   ├── gf_sqli.txt            # URLs com parâmetros de SQLi
│   └── gf_*.txt               # Um arquivo por padrão
├── nuclei/
│   ├── nuclei_xss.txt         # Findings legíveis
│   └── nuclei_xss.jsonl       # Findings estruturados
└── buckets/
    ├── buckets.jsonl           # Todos os findings de buckets
    └── buckets_summary.txt     # Resumo legível
```

### Detecção de CMS/Framework

A ferramenta detecta 40+ CMS e frameworks incluindo WordPress, Drupal, Joomla, PrestaShop, OpenCart, Magento, Shopify, VTEX, Strapi, Ghost, AEM, Next.js, Laravel, Django, Spring e mais.

Hosts com superfície de CVE conhecida (WordPress, Drupal, OpenCart, etc.) são destacados com marcador `⚑`.

---

## secret-scan.py — Scanner de Segredos e Endpoints JS

**Versão:** v2.0  
**Objetivo:** Encontrar segredos (chaves de API, tokens, credenciais) e endpoints de API escondidos em arquivos JavaScript e source maps. Funciona de forma independente ou como pós-processador do `recon.py`.

### Fases

| Fase | O que faz |
|------|-----------|
| 0 | Descoberta de portas nos IPs (nmap ou fallback socket) |
| 1 | Descoberta de arquivos JS: filtro no all_urls.txt + sondagem de caminhos comuns |
| 1b | Crawl com browser headless Playwright (captura chunks JS carregados dinamicamente) |
| 2 | Download concurrent de JS (pula CDNs automaticamente) |
| 3 | Descompilação de source maps (arquivos `.map` → código-fonte original) |
| 4 | Scan de segredos: 46 padrões regex em todos os arquivos |
| 4b | Validação ao vivo de chaves contra APIs reais |
| 5b | Sondagem de arquivos sensíveis (`.env`, `config.json`, etc.) |
| 5 | Extração de endpoints de API a partir do JS |

### Padrões de Segredo (46 no total)

| Categoria | Padrões |
|-----------|---------|
| Cloud | AWS Access Key, AWS Secret, GCP Service Account, Azure Storage |
| Controle de Versão | GitHub PAT (fine + classic), GitHub OAuth/Actions, GitLab PAT |
| Pagamentos | Stripe (live/test), Square OAuth, PayPal/Braintree |
| Mensageria | Slack Token/Webhook, Discord Webhook, Twilio SID, SendGrid, Mailgun, Mailchimp |
| IA/LLM | Anthropic API Key, OpenAI API Key, HuggingFace Token |
| Backend | Firebase Server Key, Supabase JWT (service_role), Heroku, npm token, strings de conexão DB |
| Infraestrutura | DigitalOcean, HashiCorp Vault, Cloudflare, Doppler, Terraform Cloud, Vercel, Netlify |
| Genérico | Credenciais hardcoded, URLs basic-auth, chaves privadas (PEM), IPs internos, tokens JWT |

### Validação de Chaves

Após encontrar as chaves, a ferramenta as testa ao vivo contra as respectivas APIs:

| Padrão | Método de validação |
|--------|---------------------|
| GitHub PAT | `GET api.github.com/user` |
| GitLab PAT | `GET gitlab.com/api/v4/user` |
| Stripe | `GET api.stripe.com/v1/charges` |
| Slack | `GET slack.com/api/auth.test` |
| OpenAI | `GET api.openai.com/v1/models` |
| Anthropic | `POST api.anthropic.com/v1/messages` (sonda de 1 token) |
| AWS | `aws sts get-caller-identity` (secret errado → detecta Key ID válido) |
| Google Maps | Sonda da API de Geocoding |
| SendGrid, npm, HuggingFace, Discord, Mapbox, Mailchimp, Twilio, Cloudflare, DigitalOcean | Endpoints da respectiva API |

### Instalação

```bash
# Dependências Python
pip install requests

# Opcional: browser headless (encontra chunks JS carregados dinamicamente)
pip install playwright
playwright install chromium

# Opcional: scanners adicionais
# trufflehog: https://github.com/trufflesecurity/trufflehog/releases
# gitleaks: https://github.com/gitleaks/gitleaks/releases

# Opcional: AWS CLI (para validação de chaves AWS)
pip install awscli

# Opcional: nmap (para descoberta de portas)
apt install nmap
```

### Uso

```bash
# Melhor: alimentar com o diretório de saída do recon.py (detecta tudo automaticamente)
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

# Desabilitar funcionalidades lentas para scan rápido
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --no-playwright \
    --no-port-scan \
    --no-sourcemaps

# Mostrar apenas findings críticos e altos
python3 secret-scan.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --severity critical,high

# Pular validação ao vivo de chaves (mais rápido, offline)
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
│   └── <nome_bundle>/         # Arquivos de código-fonte descompilados
├── findings/
│   ├── secrets.jsonl          # Todos os findings + resultados de validação
│   ├── endpoints.txt          # Caminhos de API extraídos
│   ├── gitleaks.json          # Saída do gitleaks (se instalado)
│   └── env_probe.jsonl        # Hits de .env/config exposto
└── report.md                  # Resumo legível
```

### Lendo a Saída

```bash
# Mostrar apenas chaves ativas confirmadas
jq 'select(.validated.valid == true)' findings/secrets.jsonl

# Filtrar por severidade
jq 'select(.severity == "critical")' findings/secrets.jsonl

# Listar todos os endpoints
cat findings/endpoints.txt

# Mostrar findings AWS
jq 'select(.pattern | startswith("aws"))' findings/secrets.jsonl
```

---

## web_inspect.py — Análise Profunda de Superfície Web

**Versão:** v1.0  
**Objetivo:** Inspeção profunda de hosts vivos — cabeçalhos de segurança, bypass de CSP, segurança DNS, matching de CVE, fingerprint de favicon, GraphQL, OpenAPI, bypass de 403, envenenamento de cache, WebSocket, exposição de CI/CD e mais.

### Fases

| Fase | O que verifica |
|------|---------------|
| 0+1+2 | Cabeçalhos de segurança (HSTS, CSP, X-Frame-Options, etc.), domínios de bypass de CSP, flags de cookie (Secure/HttpOnly/SameSite), CORS |
| 3 | DNS: SPF, DMARC, DKIM, transferência de zona AXFR, CAA, MX |
| 4 | Tecnologia detectada → banco local de CVE + consulta à API NVD |
| 5 | MurmurHash3 de favicon → fingerprints de produtos conhecidos (60+ produtos) |
| 6 | Conteúdo de robots.txt, sitemap.xml, /.well-known/ |
| 7 | Lookup de ASN (ipinfo.io) + co-hospedagem via IP reverso (hackertarget) |
| 8 | Mineração de SAN do certificado TLS → subdomínios ocultos |
| 9 | Introspecção GraphQL (15 caminhos comuns) |
| 10 | Descoberta de spec OpenAPI/Swagger + extração de endpoints e esquemas de autenticação |
| 11 | Bypass de 403/401: injeção de cabeçalho + transformações de caminho |
| 12 | Sonda de envenenamento de cache (injeção de cabeçalho sem chave) |
| 13 | Extração de endpoints WebSocket + sonda de acesso sem autenticação |
| 14 | Exposição de painéis CI/CD: Jenkins, Spring Actuator, phpinfo, Laravel Telescope, Adminer, phpMyAdmin, GitLab CI, exposição de `.git/`, etc. |
| 15 | Detecção de BUILD_ID do Next.js → coleta de endpoints JSON em `/_next/data/` |

### Banco de Favicons (60+ produtos)

Identifica Fortinet FortiGate, Cisco IOS, pfSense, VMware ESXi/vSphere, Jenkins, Grafana, GitLab, Jira, Confluence, Jupyter Notebook, Kubernetes Dashboard, MinIO, pgAdmin, Adminer, phpMyAdmin, OpenVPN, Nagios, Zabbix, Prometheus, Kibana, Sonatype Nexus, JFrog Artifactory, SonarQube, Apache Tomcat, Spring Boot, Traefik, Portainer, RabbitMQ, Webmin, HashiCorp Vault, Harbor, Rancher, Plesk, cPanel, Roundcube e páginas padrão do Nginx/Apache/IIS.

### Banco Local de CVE

Matching instantâneo (sem necessidade de API) para PHP, Apache httpd, Nginx, jQuery, WordPress, Drupal, Joomla, Tomcat, Spring (Spring4Shell), Log4j (Log4Shell), OpenSSL, IIS, Struts2, Telerik UI.

### Instalação

```bash
# Dependência Python
pip install requests

# Opcional: dig para a fase de DNS
apt install dnsutils

# Opcional: nmap (usado internamente pelo port scan do secret-scan.py)
apt install nmap
```

### Uso

```bash
# Melhor: apontar para o diretório de saída do recon.py
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_20261001_120000/ \
    --domain exemplo.com.br

# A partir de arquivos manuais de hosts + IPs
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

# Pular fases lentas
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --domain exemplo.com.br \
    --skip-dns \
    --skip-asn \
    --skip-nvd

# Pular fases específicas
python3 web_inspect.py \
    --recon-dir recon_output/exemplo.com.br_*/ \
    --domain exemplo.com.br \
    --skip-graphql \
    --skip-403 \
    --skip-cache \
    --skip-ws
```

### Flags de Pular Fases

| Flag | Fase pulada |
|------|------------|
| `--skip-headers` | Cabeçalhos + CSP + cookies |
| `--skip-dns` | Análise de segurança DNS |
| `--skip-cve` | Matching de tecnologia → CVE |
| `--skip-nvd` | Chamadas à API NVD (banco local continua) |
| `--skip-favicon` | Fingerprinting de favicon |
| `--skip-content` | robots.txt, sitemap, well-known |
| `--skip-asn` | Lookup de ASN + IP reverso |
| `--skip-tls` | Mineração TLS/SAN |
| `--skip-graphql` | Introspecção GraphQL |
| `--skip-openapi` | Descoberta de Swagger/OpenAPI |
| `--skip-403` | Teste de bypass de 403 |
| `--skip-cache` | Sonda de envenenamento de cache |
| `--skip-ws` | Descoberta de WebSocket |
| `--skip-cicd` | Detecção de painéis CI/CD |
| `--skip-nextjs` | Sonda de BUILD_ID do Next.js |

### Estrutura de Saída

```
inspect_20261001_140000/
├── headers/
│   └── headers.json           # Auditoria de cabeçalhos por host
├── dns/
│   ├── dns_data.json          # Registros SPF/DMARC/DKIM/CAA/MX
│   └── axfr_ns1.txt           # Dump de transferência de zona (se permitido)
├── tech_cve/
│   └── cve_matches.json       # Matches de tecnologia → CVE por host
├── favicons/
│   ├── favicons.json          # Hash + matches de produtos
│   └── *.ico                  # Arquivos de favicon baixados
├── content/
│   ├── content.json           # Dados de robots.txt + sitemap
│   └── disallowed_paths.txt   # Entradas Disallow agregadas
├── asn/
│   ├── asn_data.json          # Organização + país por IP
│   ├── cohosts.json           # Domínios co-hospedados por IP
│   └── cohosts.txt            # Lista plana de co-hosts
├── tls/
│   ├── tls_certs.json         # Entradas SAN por host
│   └── new_san_domains.txt    # SANs fora do escopo original
├── graphql/
│   └── *.json                 # Schema de introspecção por endpoint
├── openapi/
│   ├── *.json                 # Arquivos de spec brutos
│   └── *_endpoints.txt        # MÉTODO /caminho por spec
├── bypass403/
│   └── bypass_results.json    # Tentativas de bypass bem-sucedidas
├── cache/
│   └── cache_results.json     # Candidatos a envenenamento de cache
├── websockets/
│   └── ws_findings.json       # Endpoints WebSocket encontrados
├── cicd/
│   └── cicd_findings.json     # Painéis/configs expostos
├── nextjs/
│   └── nextjs_data.json       # Endpoints /_next/data/
├── findings.jsonl             # Todos os findings (legível por máquina)
└── report.md                  # Relatório completo legível
```

### Lendo os Findings

```bash
# Todos os findings críticos
jq 'select(.severity == "critical")' findings.jsonl

# Por fase
jq 'select(.phase == "tech_cve")' findings.jsonl

# Apenas bypasses de 403
jq 'select(.type == "bypass_403")' findings.jsonl

# Endpoints GraphQL
jq 'select(.type == "graphql_introspection")' findings.jsonl

# Problemas SPF/DMARC (spoofing de e-mail)
jq 'select(.phase == "dns")' findings.jsonl
```

---

## Workflow: Encadeando as Três Ferramentas

As três ferramentas são projetadas para se encadear. A saída do `recon.py` alimenta diretamente o `secret-scan.py` e o `web_inspect.py` via `--recon-dir`.

```bash
# Passo 1 — Recon (30–90 min dependendo do tamanho do alvo)
python3 recon.py alvo.com.br -o ./resultados

# Anotar o diretório de saída
RECON_DIR="./resultados/alvo.com.br_$(date +%Y%m%d)*"

# Passo 2 — Scan de segredos (rodar em paralelo com web_inspect)
python3 secret-scan.py \
    --recon-dir $RECON_DIR \
    --severity critical,high &

# Passo 3 — Inspeção web profunda (rodar em paralelo)
python3 web_inspect.py \
    --recon-dir $RECON_DIR \
    --domain alvo.com.br &

wait
echo "Concluído. Verifique $RECON_DIR/inspect_*/report.md"
```

### Com TOR (recomendado para engagements autorizados)

```bash
# Garantir que o TOR está rodando
systemctl start tor

python3 recon.py alvo.com.br --tor -o ./resultados
python3 secret-scan.py --recon-dir ./resultados/alvo.com.br_*/ --tor
python3 web_inspect.py  --recon-dir ./resultados/alvo.com.br_*/ --domain alvo.com.br --tor
```

### Recon Rápido (pular fases lentas)

```bash
python3 recon.py alvo.com.br \
    --skip-nuclei \
    --skip-buckets \
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
    --skip-nvd
```

---

## Instalação dos Requisitos

### Script de instalação completo

```bash
#!/bin/bash
# Testado em Kali Linux / Ubuntu 22.04+

# Python
pip install requests playwright waymore paramspider
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

# Padrões GF
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns
cp /tmp/gf-patterns/*.json ~/.gf/

# Ferramentas do sistema
apt install -y nmap dnsutils tor

# Atualizar templates do nuclei
nuclei -update-templates
```

### Instalação mínima (apenas segredos + recon básico)

```bash
pip install requests
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

### Variáveis de Ambiente

```bash
# Adicione ao ~/.bashrc ou ~/.zshrc
export CHAOS_KEY=""          # https://chaos.projectdiscovery.io
export GITHUB_TOKEN=""       # GitHub PAT com escopo read:user
```

---

> **Somente para testes de segurança autorizados e bug bounty.**  
> Estas ferramentas realizam requisições ativas na infraestrutura do alvo. Sempre obtenha autorização por escrito antes de executá-las em qualquer sistema que não seja seu.
