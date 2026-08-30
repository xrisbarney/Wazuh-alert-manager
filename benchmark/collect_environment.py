#!/usr/bin/env python3
"""Collect non-secret environment metadata for a reproducible benchmark."""

import json
import os
import platform
import subprocess


def command(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    except Exception as error:
        return f"unavailable: {error}"


print(json.dumps({
    "collected_at_utc": command(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]),
    "platform": platform.platform(),
    "python": platform.python_version(),
    "cpu_count": os.cpu_count(),
    "cpu": command(["sh", "-c", "lscpu | grep -E 'Model name|Socket|Core|Thread|CPU\\(s\\)'"]),
    "memory": command(["free", "-b"]),
    "disk": command(["df", "-B1", "/"]),
    "wazuh_dashboard_package": command(["sh", "-c", "dpkg-query -W wazuh-dashboard 2>/dev/null || rpm -q wazuh-dashboard 2>/dev/null"]),
    "wazuh_indexer_package": command(["sh", "-c", "dpkg-query -W wazuh-indexer 2>/dev/null || rpm -q wazuh-indexer 2>/dev/null"]),
    "plugin_manifest": command(["sh", "-c", "sed -n '1,40p' /usr/share/wazuh-dashboard/plugins/wazuhAlertManager/opensearch_dashboards.json"]),
}, indent=2))
