# FAQ

**Does it modify my Wazuh alerts?**
No. It reads `wazuh-alerts-*` (Wazuh 4.x) or the `wazuh-findings-v5-*` data streams (Wazuh 5.0) and stores all workflow state in its own indices. Your raw alerts, events and findings are never changed.

**Is it official?**
No — it's an unofficial community plugin, not produced or endorsed by Wazuh Inc.

**Which versions are supported?**
Wazuh 4.12.0 through 4.14.10 (OpenSearch Dashboards 2.19.1 through 2.19.6), and Wazuh 5.0.0-rc2 (OpenSearch Dashboards 3.6.0) as a **preview** while 5.0 is prerelease; see [[Installation#supported-versions]] for the exact patch mapping. The same plugin serves both lines; the installer picks the artifact for your dashboard version. Use the matching ZIP because Dashboard requires an exact target-version match.

**Do I need to reindex anything?**
No for fresh installs. The one exception: very old installs where `assigned_to` was mapped as `text` need a reindex for analyst metrics to aggregate — see [[Troubleshooting]].

**Does the AI feature send my data to a third party?**
Only if you explicitly enable it and configure a provider/key, and even then only an allowlisted projection of an alert — never the raw document, and never comment bodies. See [[Security Model#ai-egress]].

**Can it automatically close or assign alerts?**
Yes — via [[Automation Rules]]. "Set status = Closed" is auto-close (with a disposition); "Assign to" is auto-assign. A rule can also open a case, apply a task list, and notify a channel. Always preview the exact saved revision first.

**Can it send to Slack, Teams or email?**
Yes, and it does not reimplement any of them: it delivers through the channels you already have in the indexer's **Notifications** plugin, or through a direct HMAC-signed webhook. See [[Notifications]].

**Can it export data?**
Yes. CSV for the alert and case queues, a full Markdown/HTML report per case, an HTML/Markdown/CSV/JSON export of the Reporting page, and scheduled Markdown summaries. "PDF" everywhere is the browser's own *Save as PDF* from a print view — no PDF library is bundled. See [[Reporting#getting-data-out]].

**Does it look anything up on the internet?**
Only if you configure an enrichment source (AbuseIPDB, MISP or a generic HTTP endpoint) or the optional AI analysis. Outbound requests are https-only to public names, follow no redirects, are size- and time-capped, and the resolved address is checked; `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS` is the one escape hatch for a private receiver. On Wazuh 5.0 the built-in `wazuh_cti_local` source makes no outbound request at all — it reads the CTI catalog Wazuh already syncs into your indexer. See [[Security Model#egress]].

**What is a "task list"?**
A reusable set of case tasks (title, owner, due offset) kept under **Settings > Task lists** and applied to a case manually or by an automation rule. It is applied at most once per case.

**Where are API keys and webhook secrets stored?**
Encrypted (AES-256-GCM) in the plugin's own index, with the key supplied through the `WAZUH_ALERT_MANAGER_ENCRYPTION_KEY` environment variable. Without that variable a secret cannot be saved at all, and no secret is ever returned to the browser. See [[Security Model#secrets]].

**Do I need extra OpenSearch roles?**
Only for the optional features. `install.sh` creates and maps `wazuh_alert_manager_native_read` (asset chips and local CTI) and `wazuh_alert_manager_notify` (delivery), each with an opt-out flag, and on Wazuh 5.0 `wazuh_alert_manager_store`. Without them the plugin degrades — chips read "no access", deliveries stay queued — rather than failing. See [[Security Model#roles-the-trial-features-need]].

**Can it push responses back to agents (Active Response)?**
Not in this release — it's deliberately deferred pending a security review.

**Where does automation run — will it double-fire with multiple dashboards?**
The sync job uses a single-writer lease and durably admits each alert with its saved ruleset snapshot before committing the cursor. Separate worker lanes use fenced leases and deterministic execution identities, so replicas, retries, restarts, and lease loss do not duplicate actions. See [[Architecture]].

**How do I install it in Docker or Kubernetes?**
Pull the prebuilt image for your Wazuh release, `ghcr.io/xrisbarney/wazuh-dashboard-alert-manager:<wazuh version>`, and swap it in for `wazuh/wazuh-dashboard` in your compose file or manifest. Do not run the installer inside a container. See [[Installation#container-deployments-docker--kubernetes]].
