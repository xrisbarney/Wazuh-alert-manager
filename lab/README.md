# WAM live lab

A small set of throwaway VMs and services that feed the Wazuh Alert Manager
plugin real telemetry, so the queue, cases, indicators and enrichment panels
show genuine artifacts rather than seeded fixtures. Built for
`docs/trial-features/PLAN.md` Phase 9.

Everything here is self-contained: the generated events target the lab VM
itself or well-known public test endpoints. Nothing attacks a third party.

## Contents

- `agent/` — Vagrant Ubuntu 24.04 VM enrolled as the Wazuh agent
  `wam-lab-agent` against the 4.14.10 Docker stack, plus `generate.sh` which
  produces the artifacts the plugin extracts. (step 9.1)
- `misp/` — MISP (official `misp-docker` images, pinned) on
  `https://localhost:8445`, seeded with one published event that carries the
  indicators `generate.sh` produces, so the plugin's MISP enrichment source
  answers with real verdicts. (step 9.2)
- `../e2e/lab_setup.spec.ts` — the Playwright configuration tour that wires
  both into the plugin through the UI and leaves a numbered screenshot
  walkthrough in `runtime-evidence/browser/lab/`. (step 9.3, see "9.3 Lab tour")
- "9.4 Indicator coverage" below — which generated artifact lands in which
  `common/indicators.ts` field, what the plugin extracts, and why the rest is
  not extracted. The real alerts behind it are `agent/samples/<rule_id>.json`
  and feed `common/indicators.test.ts`.

## 9.1 Agent VM (`lab/agent`)

### Prerequisites

- VirtualBox + Vagrant on the host (tested with VirtualBox 7.2.6, Vagrant 2.4.9).
- The box `bento/ubuntu-24.04` (202510.26.0) already downloaded.
- The 4.14.10 Wazuh stack running in Docker
  (`/c/Users/Chris/projects/wazuh-docker/single-node`). The manager publishes
  `1514/1515/55000` on the host; the agent reaches it over VirtualBox NAT at
  `10.0.2.2`.

### Networking

The VM uses the default VirtualBox NAT interface, so the host is reachable at
`10.0.2.2` from inside the VM. The agent therefore enrols against
`WAZUH_MANAGER=10.0.2.2` by default.

Override the manager address when the stack lives elsewhere (e.g. a host-only
IP, or another machine):

```bash
# bash / git-bash
WAM_LAB_MANAGER=192.168.56.1 vagrant up
# or re-provision an existing VM against a new manager
WAM_LAB_MANAGER=192.168.56.1 vagrant provision
```

```powershell
# PowerShell
$env:WAM_LAB_MANAGER = "192.168.56.1"; vagrant up
```

The provisioner also adds a second address (`10.0.2.77` by default, override
with `WAM_LAB_SECOND_IP`) on the NAT interface so self-directed SSH login
failures carry `data.srcip=10.0.2.77` instead of `127.0.0.1`.

If `VBoxManage` is not on PATH in your shell, add it:
`export PATH="$PATH:/c/Program Files/Oracle/VirtualBox"` (Vagrant on Windows
usually finds it through the registry regardless).

### Bring it up

```bash
cd lab/agent
vagrant up          # ~5-10 min: boot + apt + Wazuh agent install (box already present)
```

`provision.sh` (run as root by the Vagrantfile) installs auditd, curl, wget,
openssh-server and sshpass, installs the Wazuh agent 4.14.x from the official
apt repo, enrols it as `wam-lab-agent`, adds auditd rules for outbound
`connect()` syscalls (`-k audit-wazuh-c`) and `/etc` writes
(`-k audit-wazuh-w`), enables realtime syscheck on `/etc`, ensures
`<localfile>` collection of the audit log, adds the idempotent
`wam-lab-secondip` unit (`ip addr replace`), and starts the agent.

Two choices worth knowing about:

- **Auth logs come from journald only.** The stock 4.14 agent config already
  collects `journald`, which carries every sshd/sudo/PAM line. An earlier
  revision also appended `/var/log/auth.log`, which ingested every auth line
  twice (one alert from `journald`, one from `auth.log`); the provisioner now
  removes that block on re-provision and no longer installs rsyslog.
- **Audit keys are the manager's stock keys.** The stock
  `0365-auditd_rules.xml` only raises the key-based alerts 80780-80792 for
  keys present in the manager's CDB list `etc/lists/audit-keys`
  (`audit-wazuh-w|r|a|x|c`). A custom key (an earlier revision used
  `wam_connect` / `wam_etc`) is collected but never becomes an alert. With
  the stock keys, every `connect()` raises **80792** (`data.audit.exe`,
  `.command`, `.pid`, `.auid`) and the `/etc` write raises **80781** with
  `data.audit.file.name`. No manager-side change is needed.

### Where the agent appears in Wazuh

- **Wazuh dashboard** (`https://localhost:8443`, `admin` / `SecretPassword`):
  *Wazuh > Agents* lists `wam-lab-agent` as Active once enrolled.
- **Manager API** (host `55000`, API creds `wazuh-wui` /
  `MyS3cr37P450r.*-` from the stack's `docker-compose.yml`):

  ```bash
  TOKEN=$(curl -sk -u 'wazuh-wui:MyS3cr37P450r.*-' \
    -X POST 'https://localhost:55000/security/user/authenticate?raw=true')
  curl -sk -H "Authorization: Bearer $TOKEN" \
    'https://localhost:55000/agents?name=wam-lab-agent&select=id,name,ip,status,version'
  ```

- **The plugin**: open the alert queue and filter to
  `agent.name: wam-lab-agent` to see this VM's alerts flow into the WAM
  projection.

### Generate artifacts

```bash
vagrant ssh -c 'sudo bash /vagrant/generate.sh'
```

`generate.sh` produces, all against the VM or public test endpoints:

- **(a)** outbound HTTP GETs to a handful of AbuseIPDB-listed public IPs
  (sources commented in the script) → rule 80792 "Audit: Command:
  /usr/bin/curl" with `data.audit.exe` / `.command`; the destination address
  is in the SOCKADDR record but the stock auditd decoder does not parse it, so
  `data.dstip` stays empty (see below);
- **(b)** 8 failed SSH logins from the VM's second address (`10.0.2.77`) as
  `baduser` → `data.srcip`;
- **(c)** `wget http://testmyids.com/` (a standard harmless IDS test domain
  MISP feeds commonly carry) → `data.url` / `data.hostname`;
- **(d)** a change to `/etc/wam-lab-marker.conf` → realtime syscheck event
  (rule 550 after the first run, 554 on the first) with `syscheck.sha256_after`
  plus audit rule 80781 on the same path. The file is written with a single
  `printf` so exactly one filesystem write happens per run: a create-then-append
  pair lets realtime syscheck hash the intermediate file, and a tmp-file + `mv`
  is reported on the `.tmp` path instead. The sha256 is printed at the end so
  9.2 can seed MISP with it; **verify it against the indexed
  `syscheck.sha256_after` before seeding** (the script cannot read the
  manager's view).
- **(e)** a sudo burst (6× as `vagrant`) plus 3 failed `su` attempts from the
  unprivileged `vagrant` user to `root` → rules 5402/5407 (`data.srcuser`,
  `data.dstuser=root`) and 5301 "FAILED SU (to root) vagrant"
  (`data.srcuser=vagrant`, `data.dstuser=root`). The target must be an
  existing account: `su` to a non-existent user exits on the user lookup
  before PAM and logs nothing.

The script prints a summary (IPs, domain, marker sha256, usernames, UTC time).
Re-run it any time to produce a fresh batch; the marker file keeps changing so
syscheck keeps firing.

### Observed artifacts (live run, 2026-11-21, after the review fixes)

Agent `wam-lab-agent` (id `001`, Wazuh v4.14.10, agent ip `10.0.2.15`) enrolled
against manager `10.0.2.2` and went **active**. One `generate.sh` run (after
`vagrant provision` with the final script) produced **112 alerts**, all from
`journald`, `syscheck` or `/var/log/audit/audit.log` (no duplicates). Rule ids
seen (`agent.name:wam-lab-agent`):

| rule.id | count | description | from |
|---|---|---|---|
| 80792 | 32 | Audit: Command: /usr/bin/curl (3), /usr/bin/wget (3), /usr/bin/ssh (8), /usr/sbin/sshd (18) | (a)/(c)/(b) outbound + self-SSH `connect()` |
| 5710 | 15 | sshd: attempt to login using a non-existent user | (b) SSH failures |
| 5712 | 1 | sshd: brute force trying to get access | (b) SSH failures |
| 5503 | 10 | PAM: user login failed | (b) SSH failures |
| 5551 | 1 | PAM: multiple failed logins in a small period | (b) SSH failures |
| 5715 | 1 | sshd: authentication success | vagrant ssh session |
| 5501 / 5502 | 17 / 14 | PAM: login session opened / closed | sudo + ssh |
| 5402 | 7 | successful sudo to ROOT executed | (e) sudo burst |
| 5407 | 9 | successful sudo executed | (e) sudo burst |
| 5301 | 3 | user missed the password to change UID (FAILED SU to root) | (e) failed su |
| 550 | 1 | integrity checksum changed (`/etc/wam-lab-marker.conf`) | (d) marker |
| 80781 | 1 | Audit: Watch - Write access: /etc/wam-lab-marker.conf | (d) marker |

The very first run on a fresh VM additionally carries 501 (new agent
connected), 554 (file added, the marker's first write), 5403 (first sudo by
the user) and ~280 CIS Ubuntu 24.04 SCA results (19004/19007/19008/19009).
The earlier 446-alert figure came from the pre-review provisioner, which
collected `auth.log` on top of `journald` and so doubled every auth alert.

Indicator fields present, for representative alerts (feeds 9.4; raw
documents saved under `agent/samples/<rule_id>.json`):

| rule.id | srcip | dstip | url | hostname | srcuser | dstuser | process.name | syscheck.sha256_after | data.audit.* |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 5710 | ✓ (10.0.2.77) | | | | ✓ (baduser) | | | | |
| 5712 | ✓ | | | | ✓ | | | | |
| 5503 | ✓ | | | | | | | | |
| 5551 | ✓ | | | | | | | | |
| 5715 | ✓ (10.0.2.2) | | | | | ✓ | | | |
| 5402 | | | | | ✓ (vagrant) | ✓ (root) | | | |
| 5407 | | | | | ✓ | ✓ | | | |
| 5301 | | | | | | | | | |
| 550  | | | | | | | | ✓ (`2ce9f77d…7bdb376`, equals the printed sha) | |
| 80792 | | | | | | | | | ✓ (`exe=/usr/bin/curl`, `command`, `pid`, `auid`, `key=audit-wazuh-c`) |
| 80781 | | | | | | | | | ✓ (`file.name=/etc/wam-lab-marker.conf`, `exe`) |

Field presence over the whole run: `data.srcip` 25, `data.srcuser` 52,
`data.dstuser` 54, `data.audit.key` / `.exe` / `.command` 33,
`syscheck.sha256_after` 1; `data.dstip`, `data.url`, `data.hostname` 0.
(5301 carries no `data.*` at all: the stock `su` decoder leaves "FAILED SU
(to root) vagrant" undecoded on 4.14.10; an earlier revision of this table
listed users for it by mistake. `5501.json` / `5502.json` were added by 9.4
for the PAM session alerts the sudo burst and the SSH session raise.)

**Fields that did NOT appear anywhere (count 0 across all agent alerts)** —
these matter for 9.4:

- `data.dstip` — the outbound connects (a) now raise 80792 alerts, but the
  stock auditd decoder does not parse the SOCKADDR `saddr` field of the
  `connect()` record, so the destination address never reaches an alert
  field. The `/usr/bin/curl` 80792 sample shows what is available
  (`data.audit.exe`, `.command`, `.pid`, `.auid`, `.syscall=42`). Mapping
  `saddr` to `data.dstip` needs a decoder (left to 9.4).
- `data.url` / `data.hostname` — `wget http://testmyids.com/` (c) is outbound
  only; there is no local web-access log on the VM for a web decoder to parse,
  so the wget shows up only as an 80792 `connect()` alert.
- `data.process.name`, `related.ip`, `related.user` — not populated by these
  decoders.

Step 9.4 (see "9.4 Indicator coverage") accepted these as decoder-side gaps:
the plugin reads structured decoder fields only and never scrapes
`full_log`, and the stock 4.14 ruleset has no decoder that puts the
`connect()` destination or the fetched URL into a field.

### Teardown

```bash
cd lab/agent
vagrant destroy -f          # removes the VM; the box stays cached
```

The agent remains registered on the manager after destroy; remove it with
`DELETE /agents?agents_list=<id>&...` on the API, or from *Agents* in the
dashboard, if you want a clean slate before the next `vagrant up`.

### Troubleshooting

- **Agent never goes Active.** Check the VM can reach the manager:
  `vagrant ssh -c 'nc -vz 10.0.2.2 1514'`. With NAT the host is `10.0.2.2`; if
  the stack is elsewhere, re-provision with `WAM_LAB_MANAGER=<ip>`.
- **Enrolment password.** The stack manager ships
  `<auth><use_password>no</use_password>`, so none is needed. If you point the
  VM at a manager that requires one, read it from that manager
  (`/var/ossec/etc/authd.pass`) and pass
  `WAM_LAB_REGISTRATION_PASSWORD=<pw> vagrant provision`.
- **No alerts in the plugin.** Confirm the manager is indexing
  (`curl -sk -u admin:SecretPassword 'https://localhost:9200/_cat/indices/wazuh-alerts*?v'`)
  and that the WAM sync job is running; filter the queue by
  `agent.name: wam-lab-agent`.
- **Second address missing.** `vagrant ssh -c 'ip -4 addr'` should list
  `10.0.2.77`; the `wam-lab-secondip` systemd unit re-adds it on boot
  (`systemctl status wam-lab-secondip` should be `active (exited)`; it uses
  `ip addr replace`, so a re-run never fails with "File exists").
- **Every auth alert appears twice.** The VM was provisioned with an earlier
  revision that collected `/var/log/auth.log` next to `journald`; run
  `vagrant provision` to remove the duplicate block.
- **No 80792/80781 audit alerts.** `sudo auditctl -l` must show the stock
  keys `audit-wazuh-c` / `audit-wazuh-w`; run `vagrant provision` if it shows
  `wam_connect` / `wam_etc`.
- **CRLF.** `.gitattributes` pins `lab/**/*.sh` and the Vagrantfile to LF so a
  Windows checkout with `core.autocrlf=true` does not sync a carriage return
  into the VM.

## 9.2 MISP (`lab/misp`)

### What it is

`lab/misp/docker-compose.yml` is the official
[MISP/misp-docker](https://github.com/MISP/misp-docker) compose file trimmed
to four services and pinned to the newest release images at the time of
writing: `ghcr.io/misp/misp-docker/misp-core:v2.5.52`,
`ghcr.io/misp/misp-docker/misp-nginx:v2.5.52`, MariaDB 10.11 and valkey 7.2
(misp-docker publishes no GitHub releases; images are tagged per MISP release).
`misp-modules`, the SMTP relay and `misp-guard` are left out: the plugin only
calls MISP's own REST API (`/attributes/restSearch`), and the modules daemon
alone costs about a gigabyte. Each service has a `mem_limit` (128 M + 768 M +
1536 M + 128 M), so the whole lab stays under ~2.5 GB.

Ports: host **8445** → nginx 8443 (https). `8443` is the 4.14 Wazuh dashboard
and `8444` the 5.0 one, so MISP takes the next port; `BASE_URL` in `.env`
is `https://localhost:8445`.

### Start + bootstrap

```bash
bash lab/misp/bootstrap.sh      # from the repo root; re-runnable
```

On the first run the script

1. copies `.env.example` to `lab/misp/.env` (gitignored) and fills
   `ADMIN_PASSWORD` and `ADMIN_KEY` with random values — they are never
   printed; read them from `.env` when you want to log in as
   `admin@admin.test`;
2. generates a self-signed certificate in `lab/misp/data/ssl` (gitignored;
   SAN `localhost`, `misp.internal`) so nginx serves https;
3. `docker compose up -d` and waits (up to 25 minutes, `WAM_MISP_WAIT_SECONDS`)
   until `https://localhost:8445/users/login` answers 200 and the API
   responds. The first start initialises the database and copies
   galaxies/taxonomies/warninglists/objects into the named volumes: **17
   minutes measured** on a Windows host under the 1.5 GB cap (a restart of an
   initialised instance re-runs the update step and takes a few minutes). The
   `misp-core` healthcheck has a matching grace period and `misp-nginx` only
   waits for `misp-core` to be *started*, so a slow first run never makes
   `docker compose up -d` fail on a dependency; the script's own wait is the
   gate;
4. through the REST API with the admin key:
   - checks the lab org: `misp-docker` renames the default org (id 1) to
     `ADMIN_ORG` (`WAM-LAB`) at first init; the script verifies the name,
     falls back to a lookup by name and creates the org only when it is
     missing (so the "creates an org" in PLAN 9.2 is a verified rename, not a
     second org);
   - creates the automation user `wam-automation@lab.internal` (role `User`,
     in that org) and an auth key for it, and writes that key to the
     repo's `.env.e2e.local` as **`WAM_E2E_MISP_KEY`** (the line is replaced
     when present but no longer valid, kept when it still authenticates; the
     file is gitignored and the key is never echoed — the 9.3 Playwright tour
     reads it from there);
   - creates the event **"WAM lab indicators"** (distribution *This community
     only*, threat level *medium*, analysis *complete*) with `to_ids=1`
     attributes: `ip-dst` for every address in the `ABUSE_IPS` block of
     `lab/agent/generate.sh` and `domain` for its `TEST_DOMAIN` (both parsed
     from the script, so the two stay in sync), plus `sha256` of
     `/etc/wam-lab-marker.conf` read live from the VM
     (`vagrant ssh -c 'sha256sum /etc/wam-lab-marker.conf'`). When the VM is
     not running the sha256 is a placeholder (the attribute comment says so);
     re-run the bootstrap after `vagrant up` + `generate.sh` and the real hash
     is added (every `generate.sh` run changes the marker, so re-running after
     each batch keeps MISP in step);
   - publishes the event;
5. if the Wazuh dashboard container (`WAM_DASHBOARD_CONTAINER`, default
   `single-node-wazuh.dashboard-1`) is running, probes
   `https://misp.internal:8445/users/login` from inside it and prints the
   status (non-fatal; 200 means the override from `e2e-deploy.sh` is in place).

Re-running is idempotent: the event is looked up by `info` first, attributes
that already exist are skipped, the user and a working key are kept. The
summary prints only ids and counts, never keys.

Secrets handling: the admin key goes to curl through a `0600` config file in a
private temp dir (`-K`) and every request body (including the automation
user's generated password) through a `0600` file (`--data-binary @file`),
never on a command line; the entrypoint runs with
`DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true` so the container log does not
show the password or key either.

### Where things are

| | |
|---|---|
| MISP UI | `https://localhost:8445` (`admin@admin.test`, password in `lab/misp/.env`) |
| from the dashboard container | `https://misp.internal:8445` (see below) |
| plugin source URL (Settings > Enrichment, kind MISP) | `https://misp.internal:8445`, key `WAM_E2E_MISP_KEY`, switch *Insecure transport (lab only)* on |
| org | `WAM-LAB` = the renamed default org, id 1 (`ADMIN_ORG` in `.env`) |
| automation user | `wam-automation@lab.internal`, auth key in `.env.e2e.local` as `WAM_E2E_MISP_KEY` |
| event | "WAM lab indicators", id printed by the bootstrap (`/events/view/<id>`) |
| data | named volumes `mysql_data`, `cache_data`, `misp_configs`, `misp_logs`, `misp_files`, `misp_gnupg` + `lab/misp/data/ssl` |

Check the seeded indicators with the admin key, for example from the UI
*Event Actions > List Events*, or `POST /attributes/restSearch` with
`{"value": "<ip>"}` — this is exactly the call the plugin's MISP provider makes.

### Why `misp.internal` (dashboard reachability)

The plugin's egress policy (`server/lib/egress/url_policy.ts`) refuses
loopback names, IP literals and private addresses outright, and accepts a
local-suffix name (`.internal`, `.local`, `.home.arpa`) **only** when the
operator allowlisted it by name in `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS`
— the documented private-receiver escape hatch (PLAN.md decision Q9). So the
dashboard container cannot call `https://localhost:8445` or
`https://192.168.x.y:8445`; it needs a *name* with a local suffix that is both
resolvable inside the container and on the allow list.

`scripts/dev/e2e-deploy.sh` therefore writes two things into the stack's
`docker-compose.override.yml` for the `wazuh.dashboard` service:

- `extra_hosts: ["misp.internal:host-gateway"]` — Docker resolves
  `misp.internal` to the host's gateway address, where the published port
  8445 lives;
- `WAZUH_ALERT_MANAGER_EGRESS_ALLOWED_HOSTS=host.docker.internal,api.abuseipdb.com,misp.internal`
  (default in `scripts/dev/common.sh`, override with `WAM_EGRESS_ALLOWED_HOSTS`).

Plain http stays off. MISP serves the self-signed certificate from
`data/ssl`, which the dashboard's Node runtime does not trust, so the MISP
source in Settings > Enrichment must have the switch **Insecure transport
(lab only)** (`allowInsecure`) on. `boundedFetch` honours it for certificate
verification only when the host is an allowlisted local-suffix name (and for
plain http only for an allowlisted host); for a public host the switch does
nothing and verification stays on. Verify from inside the container after a
redeploy:

```bash
docker exec single-node-wazuh.dashboard-1 curl -sk -o /dev/null -w '%{http_code}' https://misp.internal:8445/users/login   # 200
```

### Teardown

```bash
cd lab/misp
docker compose down -v        # containers + every named volume (database, files)
rm -rf data                   # the self-signed certificate (optional)
```

`lab/misp/.env` keeps the generated admin credentials; delete it too for a
fully fresh start (the next bootstrap generates new ones and a new
`WAM_E2E_MISP_KEY`, since the old automation user is gone with the database).

### Troubleshooting

- **Login page never answers 200.** `docker compose logs -f misp-core`; the
  first start spends up to ~17 minutes on `cake Admin runUpdates` and copying
  galaxies/taxonomies into `app/files` (the bootstrap logs the `misp-core`
  health status once a minute while it waits). Memory: `misp-core` is capped
  at 1.5 GB.
- **Git Bash.** The script exports `MSYS_NO_PATHCONV=1` (needed for the
  `/CN=` subject and URL paths) and therefore hands `curl.exe` / `python.exe`
  mixed-form paths (`C:/...`, via `cygpath -m`) for its temp files and
  `.env.e2e.local`; a CRLF `.env.example` is tolerated (`.gitattributes` keeps
  it LF anyway).
- **`nginx: ERROR: key.pem exists but is not readable`.** On a Linux host the
  bind-mounted key must be readable by uid 101 (`chmod 644 data/ssl/key.pem`;
  the bootstrap does this; lab-only certificate).
- **Dashboard test fails with "must use HTTPS" / certificate error.** The
  source URL must be `https://misp.internal:8445` (not localhost, not an IP)
  and the *Insecure transport (lab only)* switch must be on; the stack must
  have been redeployed with `scripts/dev/e2e-deploy.sh` after this step so the
  override carries `extra_hosts` and the allow list.
- **403 from the API.** The automation user has role `User`; it sees the
  event because it belongs to the same org. A key from `.env.e2e.local` that
  stopped working (database recreated) is replaced on the next bootstrap run.

## 9.3 Lab tour (`e2e/lab_setup.spec.ts`)

With the VM (9.1) and MISP (9.2) up and the stack redeployed through
`scripts/dev/e2e-deploy.sh` (allow list with `api.abuseipdb.com` and
`misp.internal`, `extra_hosts` for `misp.internal`, encryption key), the tour
configures everything an operator would click through and captures it:

```bash
# headless, from the repo root; keys come from .env.e2e.local
WAM_E2E_LAB=1 WAM_E2E_MUTATING=1 npx playwright test e2e/lab_setup.spec.ts

# headed and slowed down (300 ms between actions) to watch it
WAM_E2E_LAB=1 WAM_E2E_MUTATING=1 WAM_E2E_SLOWMO=300 npx playwright test e2e/lab_setup.spec.ts --headed
```

What it does, in order (one screenshot each under
`runtime-evidence/browser/lab/NN-<name>.png`): signs in; removes a previous
`AbuseIPDB (lab)` / `MISP (lab)` source; creates the AbuseIPDB source with
`WAM_E2E_ABUSEIPDB_KEY` and the MISP source (`https://misp.internal:8445`,
ip / domain / hash, *Insecure transport (lab only)* on) with `WAM_E2E_MISP_KEY`
(the key field is masked in the captures and the keys are never logged);
presses *Test* on both and keeps the result callouts; captures Settings >
Notifications untouched; filters the alert queue to
`agent.name:"wam-lab-agent"` over the last 24 h (fails with the
`generate.sh` command when the queue is empty, or runs it itself with
`WAM_E2E_LAB_GENERATE=1`); opens the lab alert with the best indicator (a
public IP when one exists, otherwise the `/etc/wam-lab-marker.conf` checksum
alert whose sha256 the MISP event carries), captures its Indicators block and
its Enrichment tab after *Lookup all*; selects up to ten lab alerts, creates
the case `Lab: wam-lab-agent activity` (or reuses the open one: the modal is
still captured, then cancelled, and the alerts are linked through the API),
and captures the case's Indicators (stored verdicts + *Lookup all*), Attack
graph and Timeline. Previous captures are removed first, and traces / videos
are off for this spec so a failure never records the typed keys.

Observed on the first run (2026-11-21): AbuseIPDB test `reachable`
(`8.8.8.8` clean, score 0); MISP test `reachable` (`8.8.8.8` unknown, "No
matching attribute in MISP"); on the rule 550 alert the sha256
`2ce9f77d...7bdb376` came back **`MISP (lab): malicious`** (the seeded
`to_ids` attribute), the agent address `10.0.2.15` `AbuseIPDB (lab): clean 0`
and `MISP (lab): unknown`, the md5 / sha1 `MISP (lab): unknown`; the case
linked 11 alerts (10 selected + the enriched one) and its Indicators section
showed the same verdicts aggregated. No lab alert carries a public IP
(`data.dstip` gap, see "Observed artifacts" above and "9.4 Indicator
coverage"), so the AbuseIPDB verdict is only exercised against the benign
probe and the private agent address; 9.4 confirmed this is a stock-decoder
gap, not an extractor one.

The `e2e/README.md` "Lab tour" section lists every screenshot and the
environment variables.

## 9.4 Indicator coverage (lab artifacts -> `common/indicators.ts`)

Checked on 2026-11-21 against the live run's alerts. Every file under
`agent/samples/<rule_id>.json` is one indexer hit (`_index` +
`_source`, with `_id` / `sort` where the capture kept them): 550, 5301, 80781
and 80792 were captured from the manager's `alerts.json` and wrapped in the
same envelope with their day index and no `_id`, so a test can pass any file
straight to `projectOperationalAlert` or read `._source`.
`common/indicators.test.ts` imports 550, 5301, 5402, 5501, 5502, 5710, 5712,
5715, 80730, 80781 and 80792, so every "yes" on one of those rows is a
deterministic unit test over the real alert; the 5503 / 5551 / 5407 / 5403
rows were checked by hand against the same fields (`data.srcip`,
`data.srcuser` / `data.dstuser`) the tested rows cover.
`server/lib/operational_projection.test.ts` projects 80792 and 80730,
`correlation.test.ts` / `entity_expression.test.ts` read 80792. The rule
is the one `extractIndicators` has always followed: read structured decoder
fields only, never regex-scrape `full_log`, and never add a field whose
value is not already a clean indicator.

| Artifact (`generate.sh`) | rule.id | Alert field(s) carrying the indicator | Extracted | Why |
|---|---|---|:-:|---|
| (a) outbound `connect()` to listed IPs (curl) | 80792 | `data.audit.exe` = `/usr/bin/curl` (process) | **yes** (added by 9.4) | Clean binary path from the stock auditd decoder; indicator type `process`, field `data.audit.exe`. |
| (a) same alert, destination address | 80792 | `full_log` only: `saddr=02000050761906270000000000000000` + auditd's interpreted `SADDR={ saddr_fam=inet laddr=118.25.6.39 lport=80 }` | no | **Not extracted: encoded.** The decoder does not parse the SOCKADDR record, so there is no `data.dstip`; the hex `saddr` is not a clean indicator and the plugin does not decode it or scrape `full_log`. A manager-side decoder would be needed for `data.dstip`. |
| (a) same alert, `comm` | 80792 | `data.audit.command` = `curl` | no | Kernel `comm` (15-character truncated name); the resolved `data.audit.exe` already carries the binary, so it would only duplicate the process row. |
| (b) SSH brute force against the second address | 5710, 5712 | `data.srcip` = `10.0.2.77`, `data.srcuser` = `baduser` | **yes** (ip tagged `private`, user) | Stock `sshd` decoder fields the extractor already read. |
| (b) same burst, PAM view | 5503, 5551 | `data.srcip` = `10.0.2.77` | **yes** (ip, `private`) | Stock `pam` decoder; `data.uid` / `data.euid` / `data.tty` are not indicators. |
| (b) the vagrant SSH session | 5715 | `data.srcip` = `10.0.2.2` (the host), `data.dstuser` = `vagrant` | **yes** (ip, user) | Already read; `data.srcport` is kept on the record but is not an indicator. |
| (b)/(e) PAM session opened / closed | 5501, 5502 | `data.srcuser` / `data.dstuser` = `vagrant` | **yes** (user) | Already read. Fixtures added by 9.4. |
| (c) `wget http://testmyids.com/` | 80792 only | `data.audit.exe` = `/usr/bin/wget` | **yes** (process) / **no** (url, domain) | The VM has no web-access log and the stock ruleset has no outbound-URL decoder, so `data.url` / `data.hostname` never exist; same `saddr` gap as (a) for the destination. |
| (d) `/etc/wam-lab-marker.conf` change (syscheck) | 550 (554 on first run) | `syscheck.md5_after`, `sha1_after`, `sha256_after` | **yes** (three hashes) | Already read; the `*_before` hashes are deliberately not indicators of this alert. |
| (d) same change seen by auditd | 80781 | `data.audit.exe` = `/usr/bin/bash` (process); `data.audit.file.name` = `/etc/wam-lab-marker.conf` | **yes** (process) / **no** (file path) | Binary path added by 9.4; the watched file path is not one of the plugin's indicator types (ip / domain / url / hash / user / process / host) and is carried by the syscheck alert's hashes instead. |
| (e) sudo burst | 5402, 5407, 5403 | `data.srcuser` = `vagrant`, `data.dstuser` = `root`; `data.command` = `/usr/bin/true`, `/usr/bin/sudo -n true` | **yes** (users) / **no** (command) | Users already read. `data.command` is a command line with arguments, not a clean process indicator, so it stays out (`canonicalExecutable` rejects values with whitespace). |
| (e) failed `su` | 5301 | none (`full_log` only: `FAILED SU (to root) vagrant on none`) | no | The stock 4.14.10 `su` decoder sets no `data.*` field for this line; without a structured field nothing is extracted. |
| every alert | all | `agent.ip` = `10.0.2.15` (ip, `private`), `agent.name` = `wam-lab-agent` (host) | **yes** | Already read. |
| any artifact, `data.process.name` | none | not present on any lab alert (count 0 over the run) | n/a | No stock 4.14 decoder used by the lab artifacts sets `data.process.name`; auditd puts the binary in `data.audit.exe`, which 9.4 now reads (and the `process` correlation entity falls back to). |
| any artifact, `related.*` | none | not present on any lab alert | n/a | `related.ip` / `.user` / `.hash` / `.hosts` are ECS fields written only by the 5.0 engine; a 4.x alert never carries them, so the 5.0 fixture in `common/indicators.test.ts` covers that path instead. |
| AVC records seen while provisioning | 80730 | `data.audit.exe` = `"/usr/sbin/apparmor_parser"` (quoted by the decoder) | **yes** (process) | The one normalisation 9.4 added: a single surrounding pair of double quotes is dropped; the path is otherwise verbatim. |

What 9.4 changed in the plugin:

- `common/indicators.ts`: `extractIndicators` reads `data.audit.exe` as a
  `process` indicator through the new exported `canonicalExecutable(raw)`
  (absolute path, one surrounding quote pair removed, whitespace rejected).
  `aggregateIndicators` is unchanged and records the new field like any other.
- `server/lib/operational_projection.ts` projects `data.audit.exe` through
  the same `canonicalExecutable` (bounded, the AVC decoder quotes dropped so
  the stored keyword equals the indicator value a queue filter or term query
  is built from; `null` when absent or not an absolute path; no other
  `data.audit.*` key) and
  `server/lib/mappings.ts` maps it as a keyword; `MAPPING_VERSION` 24 -> 25 so
  an upgraded install receives the field on its existing status indices.
- The `process` correlation entity (`correlation.ts` `entityValueFromAlert`,
  `entity_expression.ts`) falls back to `data.audit.exe` when `data.process`
  is absent, so an automation rule keyed on process sees the auditd binary;
  the aggregation field (`entityField('process')`) stays `data.process.name`,
  since a path and a short name cannot share one terms bucket.
- No decoder, rule or agent change: `data.dstip` / `data.url` for the outbound
  artifacts remain a stock-decoder gap (the destination only exists inside
  `full_log`), and the AbuseIPDB / MISP IP lookups therefore keep exercising
  the private agent address and the benign probe until a manager-side decoder
  exists.

Note: the sync upsert re-copies every non-plugin-owned field (the whole
`data` object included) onto a record it replays, but it only replays alerts
inside the overlap window (`sync.overlapSeconds`, default 120 s); records
outside that window are never re-read and keep the shape they were projected
with. So `data.audit.exe` appears on auditd alerts synced or replayed after
the deploy, older ones keep their old shape unless the sync cursor is reset
for a one-off re-sync; run `generate.sh` again to see it on fresh 80792 /
80781 alerts.
