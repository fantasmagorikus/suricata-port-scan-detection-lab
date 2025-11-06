# Lab de Detecção de Varredura de Portas — Suricata → Filebeat → Elasticsearch → Kibana

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/fantasmagorikus/suricata-port-scan-detection-lab)](https://github.com/fantasmagorikus/suricata-port-scan-detection-lab/releases)
[![Docs](https://img.shields.io/badge/docs-README-blue)](README.pt-BR.md)

O que eu construí
- Um lab containerizado para detectar varreduras TCP SYN e visualizar no Kibana.
- Engenharia de regras Suricata: regra básica de SYN (sid 9900001) e uma regra de threshold de scan (sid 9901001) com detection_filter.
- Pipeline EVE → ECS usando o módulo Suricata do Filebeat, gravando em data streams do Elasticsearch.
- Dashboard no Kibana (“Port Scan Detection (Suricata)”) com Lens (alertas ao longo do tempo, top fontes/portas, faixas de portas, detalhes).
- Scripts operacionais para health checks, exports reprodutíveis (NDJSON), snapshots/backups e captura de screenshots headless.
- Modos de uma máquina e em rede via `.env` (`SURICATA_IFACE=lo` ou sua interface de rede).

Detecte varreduras TCP SYN e visualize no Kibana Lens. Este lab usa Suricata para gerar EVE JSON, Filebeat (módulo suricata) para enviar dados ao Elasticsearch e um dashboard no Kibana para análise. Inclui o OWASP Juice Shop como alvo em `:3000`.

## Arquitetura e Justificativa

```mermaid
flowchart LR
  A[Suricata (EVE.json)] -->|Módulo Suricata do Filebeat| B[Elasticsearch]
  B --> C[Kibana]
  A <--> D[Regras Locais\n9900001 / 9901001]
```

- Suricata: IDS maduro que emite EVE JSON estruturado (alertas, flows, stats)
- Módulo Suricata do Filebeat: mapeamento ECS + data streams simplificam ingestão
- Elasticsearch/Kibana: busca rápida, KQL e Lens para visuais reprodutíveis
- Regras locais: detecções feitas sob medida para SYN e threshold de scan (Nmap)

## Decisões de Design

- Suricata + EVE JSON: IDS maduro com saída estruturada (alertas, flows, stats) que integra bem com ELK.
- Módulo Suricata do Filebeat: mapeamento ECS e data streams reduzem parsing/esquema customizado.
- Network mode (host) para Suricata: necessário para ver tráfego do host em Linux; alternado via `.env` para máquina única (lo) ou LAN (NIC).
- Regras locais: SYN básica + regra de threshold geram sinais claros de scan sem rulepacks pesados; fáceis de explicar e reproduzir.
- Kibana Lens + Saved Objects: iteração rápida e visuais portáveis; export NDJSON anexado ao release.
- Snapshots + scripts de backup: preservam estado e artefatos para demonstrações repetíveis e auditorias.
- Screenshots headless: evidências consistentes para portfólio sem captura manual.

## Componentes e Versões

- Suricata 8.x (container `jasonish/suricata:latest`)
- Filebeat 8.14.3 (container)
- Elasticsearch 8.14.3 (nó único, segurança desativada para o lab)
- Kibana 8.14.3
- OWASP Juice Shop (alvo) na porta `3000`

## Regras de Detecção (locais)

Definidas em `local-rules/local.rules`:

```
alert tcp any any -> $HOME_NET any (msg:"LAB - TCP SYN"; flags:S; flow:stateless; sid:9900001; rev:2;)
alert tcp any any -> $HOME_NET any (msg:"LAB - Port Scan (SYN threshold)"; flags:S; flow:stateless; detection_filter: track by_src, count 20, seconds 60; classtype:attempted-recon; sid:9901001; rev:1;)
```

- 9900001: detecção básica de SYN
- 9901001: alerta quando uma origem envia ≥20 SYN em 60s (by_src)

## Setup e Verificações

Pré‑requisitos: Linux com Docker + Docker Compose, `curl`, `jq` e `nmap` para gerar tráfego.

1) Entre no diretório do lab
```
cd homelab-security/suricata-elk-lab
```

2) Preparar o ambiente
- Copie o `.env.example` e ajuste a interface se necessário:
```
cp .env.example .env
# padrão: SURICATA_IFACE=lo (uma máquina). Para LAN, ajuste para sua NIC (ex.: wlp3s0)
```

3) Suba a stack
```
docker compose up -d
```

4) Rodar o health check (imprime e salva o resultado)
```
bash scripts/retomada_check.sh
```
Os artefatos ficam como `retomada_check-YYYY-MM-DD-HHMMSS.txt` e symlink `retomada_check-latest.txt`.

## Demo TL;DR (uma máquina)

```
git clone <este repositório>
cd suricata-port-scan-detection-lab/homelab-security/suricata-elk-lab
cp .env.example .env
docker compose up -d
bash scripts/retomada_check.sh
sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason
abra http://localhost:5601 (Dashboard: "Port Scan Detection (Suricata)")
```

## Geração de Tráfego (Nmap)

- Uma máquina só (loopback):
```
sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason
```

- Em rede (a partir de outro host na LAN, escaneando esta máquina):
```
sudo nmap -sS -p 1-1000 <IP_DA_VITIMA> -T4 --reason
```

## Dashboard Kibana e KQL

Abra o Kibana em `http://localhost:5601`.

- Data View (se solicitado):
  - Name: `filebeat-*`
  - Time field: `@timestamp`

- Dashboard: “Port Scan Detection (Suricata)”
  - Alerts over time (empilhado por signature)
  - Top source IPs (alerts)
  - Top destination ports (alerts)
  - Faixas de portas de destino (well-known/registered/dynamic)
  - Tabela de detalhes (Saved Search)

- KQL úteis:
```
event.module: "suricata" and suricata.eve.event_type: "flow"
event.module: "suricata" and suricata.eve.event_type: "alert"
suricata.eve.alert.signature_id: 9901001
```

## Exports (NDJSON) e Reprodutibilidade

Export de “Saved Objects” está em `kibana_exports/` (NDJSON). Importe para recriar o dashboard e objetos relacionados.

- Export (script):
```
bash scripts/kibana_export_dashboard.sh "Port Scan Detection (Suricata)"
```

- Import (UI): Kibana → Stack Management → Saved Objects → Import → selecione o `.ndjson` e confirme.

## Backup e Snapshots

Crie snapshot do Elasticsearch e arquive configs do lab de uma vez:
```
bash scripts/backup.sh
```
Saída em `backups/<timestamp>/`: resposta do snapshot, logs do Suricata (se houver) e tarball das configs.

## Troubleshooting

- Sem alertas após Nmap
  - Verifique se a interface condiz com o cenário (`lo` em máquina única, NIC na LAN)
  - Confirme regras carregadas e Suricata saudável (`docker logs suricata-lab-suricata`)
  - Aumente a intensidade do scan (`-p 1-10000`)

- Sem dados no Kibana
  - Verifique Filebeat config/output:
    - `docker exec suricata-lab-filebeat filebeat -e -strict.perms=false test config`
    - `docker exec suricata-lab-filebeat filebeat -e -strict.perms=false test output`
  - Cheque alcance de Elasticsearch/Kibana (portas 9200/5601)

- Fuso/tempo
  - Em Kibana, use timezone “Browser” e amplie a janela de tempo

## Estrutura do Projeto

- `docker-compose.yml` — containers e volumes
- `.env` — interface de captura (`SURICATA_IFACE`)
- `suricata/suricata.yaml` — EVE JSON (alerts, flows)
- `local-rules/local.rules` — regras do lab (9900001 / 9901001)
- `filebeat/filebeat.yml` — módulo suricata → Elasticsearch
- `scripts/` — backup, health check e export/rename
- `kibana_exports/` — export de objetos salvos (.ndjson)
- `Makefile` — tarefas comuns: `make up|down|health|backup|export|screenshots`

## Changelog

Veja CHANGELOG.md para o histórico versionado e destaques.

## Resultados e Evidências

- Flows ingeridos (últimos 10 min): 109
- Alertas (últimos 10 min): total 473
  - sid=9901001 (threshold de scan): 224
  - sid=9900001 (TCP SYN): 249
- Dashboard e export de objetos salvos disponível em `kibana_exports/`

## Licença, Conduta, Segurança

- MIT License (LICENSE)
- Código de Conduta (CODE_OF_CONDUCT.md)
- Política de segurança e reporte de vulnerabilidades (SECURITY.md)

## Créditos

- Suricata IDS, Elastic Beats, Elasticsearch, Kibana
- OWASP Juice Shop
