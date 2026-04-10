#!/bin/bash
# https://github.com/cowrie/cowrie
set -euo pipefail
exec > /var/log/honeypot-setup.log 2>&1

export DEBIAN_FRONTEND=noninteractive
ELASTIC_HOST="${elastic_host}"
ELASTIC_PASSWORD="${elastic_password}"

apt-get update -y
apt-get install -y docker.io jq
systemctl enable docker && systemctl start docker

# cowrie config — log to JSON so we can ship to elastic
mkdir -p /opt/cowrie/{etc,log}

cat > /opt/cowrie/etc/cowrie.cfg <<'CFG'
[honeypot]
hostname = svr04
log_path = /cowrie/log
download_path = /cowrie/downloads
contents_path = /cowrie/honeyfs
txtcmds_path = /cowrie/txtcmds
sensor_name = cowrie-aws

[output_jsonlog]
enabled = true
logfile = /cowrie/log/cowrie.json

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0
CFG

# run cowrie
docker run -d \
  --name cowrie \
  --restart unless-stopped \
  -p 2222:2222 \
  -p 2223:2223 \
  -v /opt/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg \
  -v /opt/cowrie/log:/cowrie/log \
  cowrie/cowrie:latest

# log shipper — tails cowrie json and bulk-ships to elasticsearch every 30s
cat > /opt/cowrie/ship_logs.sh <<'SHIPPER'
#!/bin/bash
INDEX="logs-cowrie-honeypot"
AUTH=$(echo -n "elastic:ELASTIC_PW" | base64)
POSITION_FILE="/opt/cowrie/log/.ship_position"
LOG_FILE="/opt/cowrie/log/cowrie.json"

touch "$POSITION_FILE"
LAST_LINE=$(cat "$POSITION_FILE" 2>/dev/null || echo "0")

while true; do
  CURRENT_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")

  if [ "$CURRENT_LINES" -gt "$LAST_LINE" ]; then
    BULK=""
    while IFS= read -r line; do
      # add @timestamp from cowrie's timestamp field
      TS=$(echo "$line" | jq -r '.timestamp // empty' 2>/dev/null)
      if [ -n "$TS" ]; then
        line=$(echo "$line" | jq --arg ts "$TS" '. + {"@timestamp": $ts}')
      fi
      BULK+='{"index":{"_index":"'"$INDEX"'"}}'$'\n'
      BULK+="$line"$'\n'
    done < <(tail -n +"$((LAST_LINE + 1))" "$LOG_FILE" | head -100)

    if [ -n "$BULK" ]; then
      curl -s -X POST "http://ELASTIC_HOST:9200/_bulk" \
        -H "Content-Type: application/x-ndjson" \
        -H "Authorization: Basic $AUTH" \
        --data-binary "$BULK" > /dev/null 2>&1
    fi

    LAST_LINE=$CURRENT_LINES
    echo "$LAST_LINE" > "$POSITION_FILE"
  fi

  sleep 30
done
SHIPPER

sed -i "s|ELASTIC_PW|$ELASTIC_PASSWORD|g" /opt/cowrie/ship_logs.sh
sed -i "s|ELASTIC_HOST|$ELASTIC_HOST|g" /opt/cowrie/ship_logs.sh
chmod +x /opt/cowrie/ship_logs.sh

# run shipper in background
nohup /opt/cowrie/ship_logs.sh > /var/log/cowrie-shipper.log 2>&1 &

# make it survive reboots
cat > /etc/systemd/system/cowrie-shipper.service <<'SVC'
[Unit]
Description=Cowrie log shipper to Elasticsearch
After=docker.service

[Service]
ExecStart=/opt/cowrie/ship_logs.sh
Restart=always

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable cowrie-shipper
systemctl start cowrie-shipper

echo "honeypot ready — cowrie on 2222/2223, logs shipping to elastic"
