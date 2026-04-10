"""Reads CloudTrail logs from S3, bulk-indexes into Elasticsearch."""

import gzip
import json
import urllib.request
import urllib.error
import boto3
import base64
from datetime import datetime

ELASTIC_HOST = "${elastic_host}"
ELASTIC_PASSWORD = "${elastic_password}"
INDEX = "logs-cloudtrail-detection-lab"

s3 = boto3.client("s3")


def lambda_handler(event, context):
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        obj = s3.get_object(Bucket=bucket, Key=key)
        data = json.loads(gzip.decompress(obj["Body"].read()))

        events = data.get("Records", [])
        if not events:
            return

        bulk = ""
        for e in events:
            e["@timestamp"] = e.get("eventTime", datetime.utcnow().isoformat())
            bulk += json.dumps({"index": {"_index": INDEX}}) + "\n"
            bulk += json.dumps(e) + "\n"

        auth = base64.b64encode(f"elastic:{ELASTIC_PASSWORD}".encode()).decode()
        req = urllib.request.Request(
            f"http://{ELASTIC_HOST}:9200/_bulk",
            data=bulk.encode(),
            headers={
                "Content-Type": "application/x-ndjson",
                "Authorization": f"Basic {auth}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                print(f"indexed {len(result.get('items', []))} events, errors={result.get('errors')}")
        except urllib.error.URLError as e:
            print(f"index failed: {e}")
            raise

    return {"statusCode": 200}
