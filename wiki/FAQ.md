# FAQ

**Does it modify my Wazuh alerts?**
No. It reads `wazuh-alerts-*` and stores all workflow state in its own indices. Your raw alerts are never changed.

**Is it official?**
No — it's an unofficial community plugin, not produced or endorsed by Wazuh Inc.

**Which versions are supported?**
Wazuh 4.12 / 4.13 / 4.14 (OpenSearch Dashboards 2.19.1 / 2.19.2 / 2.19.5). Use the matching zip.

**Do I need to reindex anything?**
No for fresh installs. The one exception: very old installs where `assigned_to` was mapped as `text` need a reindex for analyst metrics to aggregate — see [[Troubleshooting]].

**Does the AI feature send my data to a third party?**
Only if you explicitly enable it and configure a provider/key, and even then only an allowlisted projection of an alert — never the raw document, and never comment bodies. See [[Security Model#ai-egress]].

**Can it automatically close or assign alerts?**
Yes — via [[Automation Rules]]. "Set status = Closed" is auto-close; "Assign to" is auto-assign. Always Dry-run a rule first.

**Can it push responses back to agents (Active Response)?**
Not in this release — it's deliberately deferred pending a security review.

**Where does automation run — will it double-fire with multiple dashboards?**
No. Rules run inside the sync tick under a leader lock, so there is a single writer across replicas. See [[Architecture]].

**How do I install it in Docker or Kubernetes?**
Bake it into a custom dashboard image and reference that image. See [[Installation#container-deployments-docker--kubernetes]].
