# 🚨 wazuhAlertManager

An OpenSearch Dashboards plugin for managing Wazuh alert workflows.
<img width="1918" height="910" alt="image" src="https://github.com/user-attachments/assets/1c5dd49e-73c5-4050-8e27-f9cbe04c3845" />


---

# 📦 Installation Guide

### 1. Create the `wazuh-alert-status` index

In **OpenSearch Dashboards → Dev Tools**, run:

```json
PUT wazuh-alert-status
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "status":     { "type": "keyword" }
    }
  }
}
```

---

### 2. Create the Wazuh workflow pipeline

This pipeline ensures new alerts copied into `wazuh-alert-status` always have a `status` field.

```json
PUT _ingest/pipeline/wazuh_workflow_pipeline
{
  "description": "Set workflow status for Wazuh alerts",
  "processors": [
    {
      "set": {
        "field": "status",
        "value": "open",
        "override": false
      }
    }
  ]
}
```

---

### 3. Create the index copy script

On the Wazuh indexer, create:

`/usr/local/bin/copy_wazuh_alerts.sh`

```bash
#!/bin/bash

# Connection Info
ES_HOST="https://127.0.0.1:9200" # change the host if the script is not located on the indexer
ES_USER="YOUR_USERNAME_HERE"
ES_PASS="YOUR_PASSWORD_HERE"

SOURCE_INDEX="wazuh-alerts-*"
DEST_INDEX="wazuh-alert-status"
LAST_RUN_FILE="/var/tmp/last_wazuh_copy_time.txt"

echo "=============================="
echo "Starting Wazuh alerts copy"

if [ -f "$LAST_RUN_FILE" ]; then
  LAST_RUN=$(cat "$LAST_RUN_FILE")
else
  LAST_RUN=$(date -u -d "-10 minutes" +"%Y-%m-%dT%H:%M:%SZ")
fi

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Last run timestamp: $LAST_RUN"
echo "Current timestamp: $NOW"
echo "------------------------------"

RESPONSE=$(curl -s -k -w "\n%{http_code}\n" \
  -u "$ES_USER:$ES_PASS" \
  -X POST "$ES_HOST/_reindex" \
  -H 'Content-Type: application/json' -d"
{
  \"source\": {
    \"index\": \"$SOURCE_INDEX\",
    \"size\": 10000,
    \"query\": {
      \"range\": {
        \"@timestamp\": {
          \"gte\": \"$LAST_RUN\",
          \"lte\": \"$NOW\"
        }
      }
    }
  },
  \"dest\": {
    \"index\": \"$DEST_INDEX\",
    \"pipeline\": \"wazuh_workflow_pipeline\"
  }
}
")

echo "$RESPONSE"
echo "$NOW" > "$LAST_RUN_FILE"

echo "Finished Wazuh alerts copy"
echo "=============================="
```

You can also narrow down the alerting level by specifying rule.level as a parameter:

```json
{
  \"source\": {
    \"index\": \"$SOURCE_INDEX\",
    \"size\": 10000,
    \"query\": {
      \"bool\": {
        \"must\": [
          {
            \"range\": {
              \"@timestamp\": {
                \"gte\": \"$LAST_RUN\",
                \"lte\": \"$NOW\"
              }
            }
          },
          {
            \"range\": {
              \"rule.level\": {
                \"gte\": 9,
                \"lt\": 16
              }
            }
          }
        ]
      }
    }
  },
  \"dest\": {
    \"index\": \"$DEST_INDEX\",
    \"pipeline\": \"wazuh_workflow_pipeline\"
  }
}
")
```

Ensure you change the ES_USER and ES_PASS to an opensearch user credentials that can read and write to indexes.

Make it executable:

```bash
sudo chmod +x /usr/local/bin/copy_wazuh_alerts.sh
```

---

### 4. Schedule cron job

Edit root crontab:

```bash
sudo crontab -e
```

Add:

```cron
* * * * * /usr/local/bin/copy_wazuh_alerts.sh >> /var/log/copy_wazuh_alerts.log 2>&1
```

This runs the sync every minute.

---

### 5. Stop Wazuh Dashboard

```bash
sudo systemctl stop wazuh-dashboard
```

---

### 6. Remove old plugin (if upgrading)

```bash
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove wazuhAlertManager --allow-root
```

---

### 7. Install wazuhAlertManager plugin

For fresh install:

**Wazuh V4.12**
```bash
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v1.0.1/wazuhAlertManager-2.19.1.zip --allow-root
```

**Wazuh V4.13**
```bash
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
https://github.com/xrisbarney/Wazuh-alert-manager/releases/download/v1.0.1/wazuhAlertManager-2.19.2.zip --allow-root
```

---

### 8. Start Wazuh Dashboard

```bash
sudo systemctl start wazuh-dashboard
```

---

### 9. Verify

* Open **Wazuh Dashboard → wazuhAlertManager** tab
* Confirm alerts appear in **`wazuh-alert-status`** index with `status=open`
* Update statuses directly from the UI

---

✅ Done. The plugin should now be fully functional, with alerts copied every minute into the workflow index.

## TODO
1. Add support for comments.
2. Modify the wazuh-alert-status index so that it supports index rollover and index lifecycle management by making the pattern wazuh-alert-status-index-dd-mm-yyy.
3. Add support to see the last time an alert was updated and the user that performed the update.
4. Add drop downs to filter by rule levels, alert status and rule ids without using Lucene.
5. Improve the Lucene filter.

## Disclaimer
1. This plugin is not officially supported by Wazuh and has only been tested with Wazuh v4.12 and v4.13.
