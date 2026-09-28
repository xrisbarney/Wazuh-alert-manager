# GitHub Wiki source

These Markdown files are the source for the project's GitHub **Wiki**. They are kept in the main repo for review; the wiki itself lives in a separate `*.wiki.git` repository.

## Pages

| File | Page |
|------|------|
| `Home.md` | Landing page |
| `Installation.md` | Install / upgrade, incl. Docker & Kubernetes |
| `User-Guide.md` | Alerts, Cases, Settings |
| `Automation-Rules.md` | The rule engine |
| `Reporting.md` | Metrics & analyst breakdowns |
| `AI-Analysis.md` | Optional LLM analysis |
| `Security-Model.md` | Identity, egress, isolation |
| `Architecture.md` | Sync job & indices |
| `Lifecycle-Retention-and-RBAC.md` | Rollover, retention, retirement, restore, purge, and Wazuh RBAC |
| `Case-Evidence-and-Case-Lifecycle.md` | Rollable cases, bounded evidence relationships, archive lookup, holds, and migration |
| `Release-Notes-2.0.md` | Version 2.0 highlights, compatibility, upgrade behavior, and validation scope |
| `images/` | Browser screenshots captured from the installed release candidate |
| `Roadmap.md` | Planned work and superseded design notes |
| `Troubleshooting.md` | Common issues |
| `FAQ.md` | Quick answers |
| `_Sidebar.md` / `_Footer.md` | Wiki chrome |

## Publish to the GitHub wiki

Enable the wiki on the repo (Settings → Features → Wikis) and create one page in the UI so the wiki repo exists, then:

```bash
git clone https://github.com/SamsonIdowu/Wazuh-alert-manager.wiki.git
cp wiki/*.md Wazuh-alert-manager.wiki/
cd Wazuh-alert-manager.wiki
git add .
git commit -m "Add Wazuh Alert Manager wiki"
git push
```

Page filenames map to titles (hyphens become spaces): `Automation-Rules.md` → **Automation Rules**. `_Sidebar.md` and `_Footer.md` are special and render as the wiki's sidebar/footer. `[[Wiki Links]]` resolve by page title.
