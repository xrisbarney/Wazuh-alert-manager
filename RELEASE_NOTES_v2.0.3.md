# Wazuh Alert Manager 2.0.3

Version 2.0.3 expands exact-version compatibility across every OpenSearch
Dashboards release used by Wazuh 4.12.0 through 4.14.9 and includes the
Workbench fixes validated in pull request #16.

## Compatibility

The release contains six independently compiled plugin archives:

| Wazuh release(s) | OpenSearch Dashboards | Release asset |
|---|---|---|
| 4.12.0 | 2.19.1 | `wazuhAlertManager-2.19.1.zip` |
| 4.13.0–4.13.1 | 2.19.2 | `wazuhAlertManager-2.19.2.zip` |
| 4.14.0–4.14.1 | 2.19.3 | `wazuhAlertManager-2.19.3.zip` |
| 4.14.2–4.14.4 | 2.19.4 | `wazuhAlertManager-2.19.4.zip` |
| 4.14.5–4.14.7 | 2.19.5 | `wazuhAlertManager-2.19.5.zip` |
| 4.14.8–4.14.9 | 2.19.6 | `wazuhAlertManager-2.19.6.zip` |

The installer reads the installed dashboard's exact version and selects the
matching archive. A scheduled compatibility guard now detects new Wazuh patch
tags, upstream OSD-version changes, and drift between the installer and release
build matrix.

## Workbench fixes and improvements

- Related-alert linking and bulk alert mutations are immediately searchable.
- The Workbench header and redesigned case views follow the active dashboard
  theme and remain legible in dark mode.
- Linked alerts show the Wazuh rule ID.
- The case Attack graph now provides directed, count-labelled relationships,
  draggable saved layouts, graph-to-alert navigation, an alert timeline, MITRE
  technique summaries, and kill-chain context.
- Graph descriptions use evidence-neutral language rather than inferring
  attacker intent from entity co-occurrence.
- Attack-graph data is loaded only when its tab is opened, avoiding unnecessary
  resolution of large evidence sets during ordinary case work.
- Build metadata records the plugin source revision instead of accidentally
  inheriting the surrounding Wazuh Dashboard repository revision.

## Validation

- The complete six-target production build and unit-test matrix passed against
  official `wazuh/wazuh-dashboard` source tags.
- 34 Jest suites and 354 tests passed.
- The OSD 2.19.6 artifact was installed and browser-tested on Wazuh 4.14.9.
- Playwright covered sign-in, theme behavior, manual case creation, evidence
  hold/release, graph and timeline views, case status transitions, and closure.
- Native `wazuh-alerts-*` indices remain read-only. Plugin-owned data and v1/v2
  migration behavior are unchanged by this patch.
