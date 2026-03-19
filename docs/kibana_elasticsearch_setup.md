# Kibana + Elasticsearch Run Guide (Windows)

This guide shows how to run Elasticsearch and Kibana with Docker, connect ANDS to Elasticsearch, and view stored attack history in Kibana.

## Prerequisites

- Docker Desktop installed and running
- Ports `9200` (Elasticsearch) and `5601` (Kibana) available
- Python dependencies installed:

```bash
pip install -r requirements.txt
```

## 1) Start Elasticsearch

Create a Docker network (one time):

```bash
docker network create elastic
```

Run Elasticsearch (single-node dev mode, no auth):

```bash
docker run -d --name elasticsearch --net elastic -p 9200:9200 \
  -e discovery.type=single-node \
  -e xpack.security.enabled=false \
  -e ES_JAVA_OPTS="-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.2
```

Verify Elasticsearch is up:

```powershell
Invoke-WebRequest -Uri http://localhost:9200 -UseBasicParsing | Select-Object -ExpandProperty Content
```

## 2) Start Kibana

Run Kibana and connect it to Elasticsearch:

```bash
docker run -d --name kibana --net elastic -p 5601:5601 \
  -e ELASTICSEARCH_HOSTS=http://elasticsearch:9200 \
  docker.elastic.co/kibana/kibana:8.17.2
```

Open Kibana:

- http://localhost:5601

Note: first startup may take 30-90 seconds.

## 3) Run ANDS with real Elasticsearch

From the project root:

```bash
python -m src.main --mode csv --csv data/test/traffic2_flows.csv \
  --kibana-host http://localhost:9200 \
  --kibana-index ands-alerts
```

By default, ANDS stores attacks only. To store both benign and attack flows:

```bash
python -m src.main --mode csv --csv data/test/traffic2_flows.csv \
  --kibana-host http://localhost:9200 \
  --kibana-index ands-alerts \
  --kibana-save-all
```

## 4) Verify documents are stored

Count documents in index:

```powershell
Invoke-WebRequest -Uri http://localhost:9200/ands-alerts/_count -UseBasicParsing | Select-Object -ExpandProperty Content
```

Show latest 5 documents:

```powershell
Invoke-WebRequest -Uri "http://localhost:9200/ands-alerts/_search?size=5&sort=@timestamp:desc" -UseBasicParsing | Select-Object -ExpandProperty Content
```

## 5) View stored attacks in Kibana

1. Open Kibana at http://localhost:5601
2. Go to **Stack Management -> Data Views**
3. Create a data view:
   - Name: `ands-alerts`
   - Index pattern: `ands-alerts`
   - Timestamp field: `@timestamp`
4. Go to **Discover** and select the `ands-alerts` data view
5. Set a suitable time range (for example Last 24 hours)
6. Filter attacks only with KQL:

```text
is_attack:true
```

Recommended columns in Discover:

- `@timestamp`
- `src_ip`
- `attack_type`
- `confidence`
- `decision_source`
- `siem_alert_count`

## 6) Stop and clean up

Stop containers:

```bash
docker stop kibana elasticsearch
```

Remove containers:

```bash
docker rm kibana elasticsearch
```

Remove network (optional):

```bash
docker network rm elastic
```

## Troubleshooting

- Elasticsearch not reachable on `localhost:9200`:
  - Check container status: `docker ps`
  - Check logs: `docker logs elasticsearch`
- Kibana not loading on `localhost:5601`:
  - Check logs: `docker logs kibana`
  - Wait longer on first startup
- No documents in index:
  - Ensure ANDS was run with `--kibana-host http://localhost:9200`
  - Check ANDS logs for connection or indexing errors
  - Verify index count endpoint in step 4
