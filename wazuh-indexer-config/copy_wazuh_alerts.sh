#!/bin/bash

# Elasticsearch/OpenSearch connection info
ES_HOST="https://127.0.0.1:9200"
ES_USER="<>your_username_here<>"
ES_PASS="<>your_password_here<>"

# Source index and destination workflow index
SOURCE_INDEX="wazuh-alerts-*"
DEST_INDEX="wazuh-alert-status"

# File to track last copied timestamp
LAST_RUN_FILE="/var/tmp/last_wazuh_copy_time.txt"

if [ -f "$LAST_RUN_FILE" ]; then
  LAST_RUN=$(cat "$LAST_RUN_FILE")
else
  # Default to last 10 minutes if first run
  LAST_RUN=$(date -u -d "-10 minutes" +"%Y-%m-%dT%H:%M:%SZ")
fi

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=============================="
echo "Starting Wazuh alerts copy"
echo "Source index: $SOURCE_INDEX"
echo "Destination index: $DEST_INDEX"
echo "Last run timestamp: $LAST_RUN"
echo "Current timestamp: $NOW"
echo "------------------------------"

# Reindex with pipeline, log output to console
curl -v -k -X POST "$ES_HOST/_reindex?pretty" \
-u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' -d"
{
  \"source\": {
    \"index\": \"$SOURCE_INDEX\",
     \"size\": 10000,
    \"query\": {
      \"range\": {
        \"@timestamp\": {
          \"gte\": \"$LAST_RUN\"
        }
      }
    }
  },
  \"dest\": {
    \"index\": \"$DEST_INDEX\",
    \"pipeline\": \"wazuh_workflow_pipeline\"
  }
}
"

# Check exit code of curl
if [ $? -eq 0 ]; then
  echo "Reindex request sent successfully."
else
  echo "ERROR: Reindex request failed!"
fi

# Save current run timestamp
echo "$NOW" > "$LAST_RUN_FILE"

echo "Finished Wazuh alerts copy"
echo "=============================="
