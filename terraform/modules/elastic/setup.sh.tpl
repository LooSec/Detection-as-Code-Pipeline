#!/bin/bash
set -euo pipefail
exec > /var/log/elastic-setup.log 2>&1

export DEBIAN_FRONTEND=noninteractive
ELASTIC_PASSWORD="${elastic_password}"
KIBANA_READONLY_PW="${kibana_readonly_pw}"
ELASTIC_VERSION="8.15.0"

# docker
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl software-properties-common jq
curl -fsSL https://get.docker.com | sh
systemctl enable docker && systemctl start docker
apt-get install -y docker-compose-plugin

sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

mkdir -p /opt/elastic
cat > /opt/elastic/docker-compose.yml <<'COMPOSE'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTIC_VERSION}
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
      - xpack.security.transport.ssl.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -s -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/_cluster/health | grep -q '\"status\":\"green\\|yellow\"'"]
      interval: 30s
      timeout: 10s
      retries: 10

  kibana:
    image: docker.elastic.co/kibana/kibana:${ELASTIC_VERSION}
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
      - SERVER_SSL_ENABLED=false
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=a]3ej5;F9o2-Bc4^7GR!dsa#Kf0Yt6Xz
      - XPACK_SECURITY_ENCRYPTIONKEY=b]4fk6;G0p3-Cd5^8HS!etb#Lg1Zu7Ya
      - XPACK_REPORTING_ENCRYPTIONKEY=c]5gl7;H1q4-De6^9IT!fuc#Mh2Av8Zb
    ports:
      - "5601:5601"
    depends_on:
      elasticsearch:
        condition: service_healthy
    restart: unless-stopped

volumes:
  esdata:
    driver: local
COMPOSE

sed -i "s/\$${ELASTIC_PASSWORD}/$ELASTIC_PASSWORD/g" /opt/elastic/docker-compose.yml
sed -i "s/\$${ELASTIC_VERSION}/$ELASTIC_VERSION/g" /opt/elastic/docker-compose.yml

cd /opt/elastic
docker compose up -d elasticsearch

# wait for ES
until curl -s -u "elastic:$ELASTIC_PASSWORD" http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
  sleep 10
done

# set kibana_system password
curl -s -X POST -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  "http://localhost:9200/_security/user/kibana_system/_password" \
  -d "{\"password\": \"$ELASTIC_PASSWORD\"}"

docker compose up -d kibana

until curl -s http://localhost:5601/api/status | grep -q '"level":"available"'; do
  sleep 10
done

# read-only role for employer demos
curl -s -X PUT -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  "http://localhost:9200/_security/role/employer_viewer" \
  -d '{
    "cluster": ["monitor"],
    "indices": [
      {
        "names": ["logs-*", ".alerts-security*", ".siem-signals-*", "metrics-*", "filebeat-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ],
    "applications": [
      {
        "application": "kibana-.kibana",
        "privileges": ["feature_siem.read", "feature_dashboard.read", "feature_discover.read", "feature_maps.read"],
        "resources": ["space:default"]
      }
    ]
  }'

curl -s -X PUT -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  "http://localhost:9200/_security/user/employer_viewer" \
  -d "{
    \"password\": \"$KIBANA_READONLY_PW\",
    \"roles\": [\"employer_viewer\"],
    \"full_name\": \"Portfolio Viewer\"
  }"

# load prebuilt detection rules
curl -s -X POST -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "http://localhost:5601/api/detection_engine/rules/prepackaged"

echo "done — kibana at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5601"
