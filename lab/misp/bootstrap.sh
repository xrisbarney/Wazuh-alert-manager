#!/usr/bin/env bash
# First-run (and re-run) bootstrap for the WAM lab MISP (PLAN.md step 9.2).
# Runs on the host (Git Bash / Linux / macOS with bash 3.2+; needs docker
# compose, curl, openssl, python3 and, for the live sha256, vagrant):
#
#   bash lab/misp/bootstrap.sh
#
# 1. creates lab/misp/.env from .env.example with a random admin password and
#    admin API key (never printed), and a self-signed certificate in data/ssl
#    (SAN: localhost, misp.internal) so MISP serves https on :8445;
# 2. `docker compose up -d` and waits (default 25 min, WAM_MISP_WAIT_SECONDS)
#    until https://localhost:8445/users/login answers 200 and the API is up.
#    The first start initialises the database and copies galaxies/taxonomies/
#    warninglists/objects into the named volumes: measured 17 min on a
#    Windows host under the 1.5 GB cap; later starts take well under a minute;
# 3. through the REST API with the admin key:
#    - checks the lab org: misp-docker renames the default org (id 1) to
#      ADMIN_ORG (WAM-LAB) at first init; the script verifies that, looks the
#      name up otherwise and creates the org when it is missing;
#    - creates the automation user wam-automation@lab.internal (role "User",
#      in that org) and an auth key for it, written to the repo's
#      .env.e2e.local as WAM_E2E_MISP_KEY (replaced if present and no longer
#      valid, kept when it still works); the key is never echoed;
#    - creates the event "WAM lab indicators" (distribution "This community
#      only", threat level medium, analysis complete) with to_ids attributes:
#      ip-dst for every public IP in lab/agent/generate.sh, domain for its
#      TEST_DOMAIN, sha256 of /etc/wam-lab-marker.conf read live from the VM
#      (placeholder when the VM is down), then publishes it;
# 4. if the Wazuh dashboard container is running, probes
#    https://misp.internal:8445 from inside it (non-fatal; needs the
#    extra_hosts entry written by scripts/dev/e2e-deploy.sh).
# Re-running is safe: the event is looked up by info first, attributes that
# already exist are skipped, the automation user and a working key are kept.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
LAB_MISP_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"
AGENT_DIR="$REPO_ROOT/lab/agent"
GENERATE_SH="$AGENT_DIR/generate.sh"
ENV_E2E="${WAM_E2E_ENV_FILE:-$REPO_ROOT/.env.e2e.local}"
MISP_URL="${WAM_MISP_URL:-https://localhost:8445}"
AUTOMATION_EMAIL="${WAM_MISP_AUTOMATION_EMAIL:-wam-automation@lab.internal}"
EVENT_INFO="WAM lab indicators"
WAIT_SECONDS="${WAM_MISP_WAIT_SECONDS:-1500}"
DASHBOARD_CONTAINER="${WAM_DASHBOARD_CONTAINER:-single-node-wazuh.dashboard-1}"
export MSYS_NO_PATHCONV=1   # Git Bash: keep "/CN=..." and URL paths untouched
# With MSYS_NO_PATHCONV on, Git Bash no longer rewrites a literal "/dev/null"
# argument for the Windows curl.exe, so host-side curl calls discard their
# body into $DISCARD (a temp file) instead of "-o /dev/null". The docker exec
# probe at the end runs curl inside a Linux container and keeps /dev/null.

log() { printf '[misp-bootstrap] %s\n' "$*"; }
die() { printf '[misp-bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
need docker; need curl; need openssl
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || die "missing tool: python3"
# python -I: isolated mode, so nothing in cwd can shadow stdlib modules.
py() { "$PY" -I -c "$@"; }

# Secrets never go on a command line: curl reads headers from a 0600 config
# file and request bodies from 0600 files, all in a private temp dir that is
# removed on exit (umask 077 makes every file created below owner-only).
WORK="$(mktemp -d)"
# Git Bash: curl.exe and python.exe are Windows binaries and MSYS_NO_PATHCONV
# stops the shell from translating "/tmp/..." or "/c/..." for them, so hand
# them the mixed form (C:/Users/...) that bash understands too. No-op on
# Linux/macOS.
if command -v cygpath >/dev/null 2>&1; then WORK="$(cygpath -m "$WORK")"; ENV_E2E="$(cygpath -m "$ENV_E2E")"; fi
trap 'rm -rf "$WORK"' EXIT
umask 077
DISCARD="$WORK/discard"

# --- 1. .env with generated credentials ------------------------------------
if [ ! -f .env ]; then
  # CRLF-tolerant: a Windows checkout with core.autocrlf may hand us CRLF.
  tr -d '\r' < .env.example > .env
  log "created .env from .env.example"
fi
# Fill empty ADMIN_PASSWORD / ADMIN_KEY in place (never printed). The regex
# keeps whatever line ending the file has.
fill_env() {  # fill_env NAME  (value on stdin)
  py 'import io,re,sys
p,name=sys.argv[1],sys.argv[2]; v=sys.stdin.read().strip()
s=io.open(p,encoding="utf-8",newline="").read()
s=re.sub(r"(?m)^("+re.escape(name)+r"=)(\r?)$", lambda m: m.group(1)+v+m.group(2), s, count=1)
io.open(p,"w",encoding="utf-8",newline="").write(s)' .env "$1"
}
if grep -qE $'^ADMIN_PASSWORD=\r?$' .env; then
  pw="$(openssl rand -hex 12)Aa1!"
  fill_env ADMIN_PASSWORD <<<"$pw"
  unset pw
  log "generated ADMIN_PASSWORD into .env"
fi
if grep -qE $'^ADMIN_KEY=\r?$' .env; then
  key="$(openssl rand -hex 20)"   # 40 chars, MISP auth key format
  fill_env ADMIN_KEY <<<"$key"
  unset key
  log "generated ADMIN_KEY into .env"
fi
# Source with any CR stripped so values never carry a trailing \r.
tr -d '\r' < .env > "$WORK/env.sh"
# shellcheck disable=SC1091
set -a; . "$WORK/env.sh"; set +a
rm -f "$WORK/env.sh"
[ -n "${ADMIN_KEY:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ] || die ".env has no ADMIN_KEY / ADMIN_PASSWORD"
[ -n "${BASE_URL:-}" ] || die ".env has no BASE_URL"
ADMIN_ORG="${ADMIN_ORG:-WAM-LAB}"

# --- self-signed certificate for nginx ---------------------------------------
mkdir -p data/ssl
if [ ! -f data/ssl/cert.pem ] || [ ! -f data/ssl/key.pem ]; then
  # `env -u OPENSSL_CONF`: a Windows OpenSSL install often exports OPENSSL_CONF
  # pointing at a file that does not exist, which makes `req` fail; the
  # compiled-in default config is all this needs. Paths stay relative because
  # MSYS_NO_PATHCONV is on (needed for the /CN= subject).
  env -u OPENSSL_CONF openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout data/ssl/key.pem -out data/ssl/cert.pem \
    -subj '/CN=misp.internal/O=WAM lab' \
    -addext 'subjectAltName=DNS:localhost,DNS:misp.internal,IP:127.0.0.1' >/dev/null 2>&1
  # misp-nginx runs as uid 101 and mounts the dir read-only: the key must be
  # world-readable (lab-only cert, nothing to protect). Windows bind mounts are
  # 0777 anyway; this matters on a Linux host.
  chmod 644 data/ssl/cert.pem data/ssl/key.pem
  log "generated self-signed certificate (SAN localhost, misp.internal) in data/ssl"
fi

# --- 2. up + wait ------------------------------------------------------------
# misp-nginx depends on misp-core with condition service_started (not
# service_healthy), so `up -d` returns as soon as the containers run and the
# wait below is the only gate; the health status is logged for orientation.
log "docker compose up -d (images pinned to misp-core/misp-nginx v2.5.52)"
docker compose up -d
core_health() {
  docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q misp-core 2>/dev/null)" 2>/dev/null || echo unknown
}
log "waiting up to ${WAIT_SECONDS}s for ${MISP_URL}/users/login (first start initialises the DB and copies galaxies/taxonomies: ~17 min measured on Windows; later starts < 1 min)"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
last_note=0
until code="$(curl -sk -o "$DISCARD" -w '%{http_code}' "${MISP_URL}/users/login" || true)"; [ "$code" = "200" ]; do
  now="$(date +%s)"
  [ "$now" -lt "$deadline" ] || die "MISP did not answer 200 on ${MISP_URL}/users/login within ${WAIT_SECONDS}s (last: ${code:-none}, misp-core health: $(core_health)); see: docker compose logs misp-core"
  if [ $(( now - last_note )) -ge 60 ]; then
    log "  still waiting (login -> ${code:-none}, misp-core health: $(core_health), $(( deadline - now ))s left)"
    last_note="$now"
  fi
  sleep 5
done
log "login page answers 200"

ADMIN_CFG="$WORK/admin.curlrc"
printf 'header = "Authorization: %s"\nheader = "Accept: application/json"\n' "$ADMIN_KEY" > "$ADMIN_CFG"
BODY="$WORK/body.json"   # request bodies go through this 0600 file, never argv
# api METHOD PATH [BODYFILE] -> response body on stdout; the HTTP status is
# written to $WORK/status (read it with api_status) so it survives the
# command-substitution subshell callers run api in. curl failures -> 000.
api() {
  local method="$1" path="$2" bodyfile="${3:-}" out="$WORK/resp.$$" code
  if [ -n "$bodyfile" ]; then
    code="$(curl -sk -K "$ADMIN_CFG" -X "$method" -H 'Content-Type: application/json' --data-binary @"$bodyfile" -o "$out" -w '%{http_code}' "${MISP_URL}${path}" || echo 000)"
  else
    code="$(curl -sk -K "$ADMIN_CFG" -X "$method" -o "$out" -w '%{http_code}' "${MISP_URL}${path}" || echo 000)"
  fi
  printf '%s' "$code" > "$WORK/status"
  [ -f "$out" ] && cat "$out"; rm -f "$out"
  return 0
}
api_status() { cat "$WORK/status" 2>/dev/null || echo 000; }
# expect_200 CONTEXT BODY -> dies with status + first 300 bytes of the body
expect_200() { [ "$(api_status)" = "200" ] || die "$1 -> $(api_status): $(printf '%s' "$2" | head -c 300)"; }

until api GET /servers/getVersion >/dev/null; [ "$(api_status)" = "200" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || die "API not ready (GET /servers/getVersion -> $(api_status))"
  sleep 5
done
log "API ready: MISP $(api GET /servers/getVersion | py 'import json,sys; print(json.load(sys.stdin).get("version","?"))')"

# --- 3a. the lab org ---------------------------------------------------------
# misp-docker renames the default org (id 1) to ADMIN_ORG on first init; verify
# it, fall back to a lookup by name, and create the org only when it is absent.
org_id="$(api GET /organisations/view/1 | py 'import json,sys
want=sys.argv[1]
try: o=json.load(sys.stdin).get("Organisation",{})
except Exception: o={}
print(o.get("id","") if o.get("name")==want else "")' "$ADMIN_ORG")"
if [ -n "$org_id" ]; then
  log "org ${ADMIN_ORG} is the renamed default org (id ${org_id})"
else
  org_id="$(api GET /organisations/index | py 'import json,sys
want=sys.argv[1]
try: orgs=json.load(sys.stdin)
except Exception: orgs=[]
for o in orgs:
    o=o.get("Organisation",o)
    if o.get("name")==want: print(o["id"]); break' "$ADMIN_ORG")"
  if [ -n "$org_id" ]; then
    log "org ${ADMIN_ORG} exists (id ${org_id})"
  else
    py 'import json,sys; print(json.dumps({"name":sys.argv[1],"local":True,"description":"WAM lab org (lab/misp/bootstrap.sh)"}))' "$ADMIN_ORG" > "$BODY"
    resp="$(api POST /admin/organisations/add "$BODY")"; rm -f "$BODY"
    expect_200 "POST /admin/organisations/add" "$resp"
    org_id="$(printf '%s' "$resp" | py 'import json,sys; print(json.load(sys.stdin)["Organisation"]["id"])')"
    log "created org ${ADMIN_ORG} (id ${org_id})"
  fi
fi

# --- 3b. automation user ----------------------------------------------------
roles_json="$(api GET /roles/index)"
role_id="$(printf '%s' "$roles_json" | py 'import json,sys
roles=[r.get("Role",r) for r in json.load(sys.stdin)]
by={r["name"]:r["id"] for r in roles}
print(by.get("User") or by.get("Sync user") or "")')"
[ -n "$role_id" ] || die "no role named User / Sync user in /roles/index"
user_id="$(api GET /admin/users/index | py 'import json,sys
want=sys.argv[1]
for u in json.load(sys.stdin):
    u=u.get("User",u)
    if u.get("email")==want: print(u["id"]); break' "$AUTOMATION_EMAIL")"
if [ -z "$user_id" ]; then
  user_pw="$(openssl rand -hex 16)Aa1!"
  # password on python's stdin, JSON straight into the 0600 body file
  py 'import json,sys; print(json.dumps({"email":sys.argv[1],"org_id":sys.argv[2],"role_id":sys.argv[3],"password":sys.stdin.read().strip(),"change_pw":"0","termsaccepted":"1","disabled":False}))' "$AUTOMATION_EMAIL" "$org_id" "$role_id" <<<"$user_pw" > "$BODY"
  unset user_pw
  resp="$(api POST /admin/users/add "$BODY")"; rm -f "$BODY"
  expect_200 "POST /admin/users/add" "$resp"
  user_id="$(printf '%s' "$resp" | py 'import json,sys; print(json.load(sys.stdin)["User"]["id"])')"
  log "created automation user ${AUTOMATION_EMAIL} (id ${user_id}, org_id ${org_id}, role_id ${role_id})"
else
  log "automation user ${AUTOMATION_EMAIL} exists (id ${user_id})"
fi

# --- 3c. its auth key -> .env.e2e.local (never echoed) ----------------------
existing_ok=0
if [ -f "$ENV_E2E" ] && grep -qE '^WAM_E2E_MISP_KEY=.+' "$ENV_E2E"; then
  KEY_CFG="$WORK/key.curlrc"
  tr -d '\r' < "$ENV_E2E" | sed -nE 's/^WAM_E2E_MISP_KEY=(.*)$/header = "Authorization: \1"/p' | head -1 > "$KEY_CFG"
  printf 'header = "Accept: application/json"\n' >> "$KEY_CFG"
  who="$(curl -sk -K "$KEY_CFG" "${MISP_URL}/users/view/me" | py 'import json,sys
try: print(json.load(sys.stdin).get("User",{}).get("email",""))
except Exception: print("")')"
  rm -f "$KEY_CFG"
  if [ "$who" = "$AUTOMATION_EMAIL" ]; then existing_ok=1; fi
fi
if [ "$existing_ok" = "1" ]; then
  log "WAM_E2E_MISP_KEY in $(basename "$ENV_E2E") still authenticates as ${AUTOMATION_EMAIL}; kept"
else
  printf '%s' '{"comment":"WAM plugin enrichment source (lab/misp/bootstrap.sh)","read_only":"0"}' > "$BODY"
  resp="$(api POST "/auth_keys/add/${user_id}" "$BODY")"; rm -f "$BODY"
  expect_200 "POST /auth_keys/add" "$resp"
  # The raw key is shown once by MISP; hand it to python on stdin, which
  # replaces or appends the WAM_E2E_MISP_KEY line, preserving line endings.
  printf '%s' "$resp" | py 'import io,json,os,sys
raw=json.load(sys.stdin)["AuthKey"]["authkey_raw"]
p=sys.argv[1]
s=io.open(p,encoding="utf-8",newline="").read() if os.path.exists(p) else ""
nl="\r\n" if "\r\n" in s else "\n"
lines=s.split(nl)
if lines and lines[-1]=="": lines.pop()
line="WAM_E2E_MISP_KEY="+raw
for i,l in enumerate(lines):
    if l.startswith("WAM_E2E_MISP_KEY="): lines[i]=line; break
else:
    lines+=["","# MISP automation key for the enrichment lab (Phase 9.2, lab/misp/bootstrap.sh); never commit",line]
io.open(p,"w",encoding="utf-8",newline="").write(nl.join(lines)+nl)' "$ENV_E2E"
  unset resp
  log "wrote WAM_E2E_MISP_KEY to ${ENV_E2E}"
fi

# --- 3d. indicators from lab/agent/generate.sh + the live VM ----------------
[ -f "$GENERATE_SH" ] || die "missing $GENERATE_SH"
LAB_IPS=()
while IFS= read -r ip; do [ -n "$ip" ] && LAB_IPS+=("$ip"); done < <(sed -n '/^ABUSE_IPS=(/,/^)/p' "$GENERATE_SH" | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"')
LAB_DOMAIN="$(sed -nE 's/^TEST_DOMAIN="([^"]+)".*/\1/p' "$GENERATE_SH" | head -1)"
[ "${#LAB_IPS[@]}" -gt 0 ] && [ -n "$LAB_DOMAIN" ] || die "could not parse ABUSE_IPS / TEST_DOMAIN from generate.sh"
MARKER_SHA=""
SHA_NOTE=""
if command -v vagrant >/dev/null 2>&1; then
  MARKER_SHA="$( (cd "$AGENT_DIR" && vagrant ssh -c 'sha256sum /etc/wam-lab-marker.conf' 2>/dev/null) | tr -d '\r' | awk 'NR==1 && $1 ~ /^[0-9a-f]{64}$/ {print $1}' || true)"
fi
if [ -z "$MARKER_SHA" ]; then
  # openssl (required anyway) instead of sha256sum, which stock macOS lacks.
  MARKER_SHA="$(printf 'wam-lab-marker-placeholder' | openssl dgst -sha256 | awk '{print $NF}')"
  SHA_NOTE=" (PLACEHOLDER: the agent VM is not running or has no /etc/wam-lab-marker.conf yet; re-run after 'vagrant up' + generate.sh)"
  log "marker sha256 unavailable from the VM; using a placeholder"
else
  log "marker sha256 read live from the VM"
fi

# --- 3e. the event -----------------------------------------------------------
py 'import json,sys; print(json.dumps({"eventinfo":sys.argv[1]}))' "$EVENT_INFO" > "$BODY"
event_id="$(api POST /events/index "$BODY" | py 'import json,sys
want=sys.argv[1]
try: events=json.load(sys.stdin)
except Exception: events=[]
for e in events:
    e=e.get("Event",e)
    if e.get("info")==want: print(e["id"]); break' "$EVENT_INFO")"
rm -f "$BODY"
if [ -z "$event_id" ]; then
  py 'import json,sys; print(json.dumps({"Event":{"info":sys.argv[1],"distribution":"1","threat_level_id":"2","analysis":"2","published":False}}))' "$EVENT_INFO" > "$BODY"
  resp="$(api POST /events/add "$BODY")"; rm -f "$BODY"
  expect_200 "POST /events/add" "$resp"
  event_id="$(printf '%s' "$resp" | py 'import json,sys; print(json.load(sys.stdin)["Event"]["id"])')"
  log "created event ${event_id} '${EVENT_INFO}' (distribution=1 community, threat_level=2 medium, analysis=2 complete)"
else
  log "event '${EVENT_INFO}' exists (id ${event_id})"
fi

# Desired attributes: type \t value \t category \t comment
desired="$WORK/desired.tsv"
: > "$desired"
for ip in "${LAB_IPS[@]}"; do
  printf 'ip-dst\t%s\tNetwork activity\tlab/agent/generate.sh (a): outbound connect target\n' "$ip" >> "$desired"
done
printf 'domain\t%s\tNetwork activity\tlab/agent/generate.sh (c): wget target\n' "$LAB_DOMAIN" >> "$desired"
printf 'sha256\t%s\tPayload delivery\tlab/agent/generate.sh (d): /etc/wam-lab-marker.conf syscheck.sha256_after%s\n' "$MARKER_SHA" "$SHA_NOTE" >> "$desired"

py 'import json,sys; print(json.dumps({"eventid":sys.argv[1],"returnFormat":"json","limit":1000}))' "$event_id" > "$BODY"
existing="$(api POST /attributes/restSearch "$BODY")"; rm -f "$BODY"
expect_200 "POST /attributes/restSearch" "$existing"
added=0; skipped=0
while IFS=$'\t' read -r atype avalue acategory acomment; do
  if printf '%s' "$existing" | py 'import json,sys
t,v=sys.argv[1],sys.argv[2]
attrs=json.load(sys.stdin).get("response",{}).get("Attribute",[])
sys.exit(0 if any(a.get("type")==t and a.get("value")==v for a in attrs) else 1)' "$atype" "$avalue"; then
    skipped=$((skipped+1)); continue
  fi
  py 'import json,sys; print(json.dumps({"type":sys.argv[1],"value":sys.argv[2],"category":sys.argv[3],"to_ids":True,"comment":sys.argv[4],"distribution":"5"}))' "$atype" "$avalue" "$acategory" "$acomment" > "$BODY"
  resp="$(api POST "/attributes/add/${event_id}" "$BODY")"; rm -f "$BODY"
  st="$(api_status)"
  if [ "$st" = "200" ]; then
    added=$((added+1))
  elif printf '%s' "$resp" | grep -qi 'already exists'; then
    skipped=$((skipped+1))
  else
    die "POST /attributes/add/${event_id} (${atype} ${avalue}) -> ${st}: $(printf '%s' "$resp" | head -c 300)"
  fi
done < "$desired"
log "attributes: ${added} added, ${skipped} already present (${#LAB_IPS[@]} ip-dst, 1 domain, 1 sha256; all to_ids=1)"

resp="$(api POST "/events/publish/${event_id}")"
expect_200 "POST /events/publish/${event_id}" "$resp"
total="$(api GET "/events/view/${event_id}" | py 'import json,sys
e=json.load(sys.stdin)["Event"]
print("%s attributes, published=%s" % (e.get("attribute_count"), e.get("published")))')"
log "event ${event_id} published: ${total}"

# --- 4. reachability from the dashboard container (non-fatal) ----------------
dash_probe="skipped (container ${DASHBOARD_CONTAINER} not running)"
if docker inspect --format '{{.State.Running}}' "$DASHBOARD_CONTAINER" 2>/dev/null | grep -q true; then
  dash_code="$(docker exec "$DASHBOARD_CONTAINER" curl -sk -o /dev/null -w '%{http_code}' https://misp.internal:8445/users/login 2>/dev/null || echo 000)"
  if [ "$dash_code" = "200" ]; then
    dash_probe="200 from https://misp.internal:8445/users/login inside ${DASHBOARD_CONTAINER}"
  else
    dash_probe="${dash_code} from https://misp.internal:8445 inside ${DASHBOARD_CONTAINER} (redeploy with scripts/dev/e2e-deploy.sh so the override carries extra_hosts misp.internal:host-gateway)"
  fi
fi
log "dashboard reachability: ${dash_probe}"

cat <<SUMMARY
[misp-bootstrap] done
  MISP UI            : ${MISP_URL}  (login ${ADMIN_EMAIL:-admin@admin.test}, password in lab/misp/.env)
  from the dashboard : https://misp.internal:8445 (extra_hosts + egress allow list via scripts/dev/e2e-deploy.sh) - probe: ${dash_probe}
  org                : ${ADMIN_ORG} (id ${org_id})
  automation user    : ${AUTOMATION_EMAIL} (id ${user_id}); key in ${ENV_E2E} as WAM_E2E_MISP_KEY
  event              : id ${event_id} "${EVENT_INFO}", ${#LAB_IPS[@]} ip-dst + 1 domain + 1 sha256${SHA_NOTE:+ (placeholder sha)}
  teardown           : cd lab/misp && docker compose down -v
SUMMARY
