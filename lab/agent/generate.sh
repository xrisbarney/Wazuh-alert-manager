#!/usr/bin/env bash
# Generates benign, self-contained telemetry on wam-lab-agent so the Wazuh
# Alert Manager plugin has real alerts to display (queue, cases, indicators).
# Run inside the VM:  vagrant ssh -c 'sudo bash /vagrant/generate.sh'
#
# Everything here targets the VM itself or well-known test endpoints. Nothing
# attacks a third party: the "brute force" is the VM logging into its own sshd
# with a wrong password, and the outbound connects are short HTTP GETs to IPs
# that are documented test/reputation examples (see comments per IP).
set -uo pipefail

MARKER=/etc/wam-lab-marker.conf
SECOND_IP="${WAM_LAB_SECOND_IP:-10.0.2.77}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== wam-lab-agent artifact generator @ ${TS} ==="

# --- (a) outbound TCP connects to public IPs listed on AbuseIPDB ------------
# These are addresses that appear on AbuseIPDB's public reports / its own
# documentation examples, used here only as destination IPs for a 5-second
# HTTP GET so auditd logs an outbound connect() and (if the decoder maps it)
# data.dstip is set. Timeouts/refusals are expected and fine.
ABUSE_IPS=(
  "118.25.6.39"     # AbuseIPDB API documentation's own example check target (218.../118... sample)
  "185.220.101.1"   # long-listed Tor exit on AbuseIPDB (high confidence reports)
  "45.155.205.233"  # recurrently reported SSH/scan source on AbuseIPDB
)
echo "[a] outbound connects to ${#ABUSE_IPS[@]} AbuseIPDB-listed IPs"
for ip in "${ABUSE_IPS[@]}"; do
  echo "    -> ${ip}"
  curl -m 5 --connect-timeout 5 -s -o /dev/null "http://${ip}/" || true
done

# --- (b) SSH login failures from the VM's second address --------------------
# The VM logs into its OWN sshd (bound to its second address) with a wrong
# password, 8 times, as user "baduser". -b binds the source so auth.log records
# data.srcip=${SECOND_IP}. sshpass feeds the wrong password non-interactively.
echo "[b] 8 failed SSH logins from ${SECOND_IP} as baduser"
for i in $(seq 1 8); do
  sshpass -p "wrongpassword${i}" \
    ssh -b "${SECOND_IP}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        baduser@"${SECOND_IP}" true 2>/dev/null || true
done

# --- (c) wget of a well-known test domain -----------------------------------
# testmyids.com returns a static EICAR-style test string and is a standard,
# harmless IDS/threat-intel test domain that MISP feeds commonly carry. The GET
# gives the web decoder a data.url / data.hostname to extract.
TEST_DOMAIN="testmyids.com"
echo "[c] wget http://${TEST_DOMAIN}/"
wget -T 5 -t 1 -q -O /dev/null "http://${TEST_DOMAIN}/" || true

# --- (d) syscheck change in /etc --------------------------------------------
# Append a comment to a small marker file under /etc so realtime syscheck emits
# an event with syscheck.sha256_after. 9.2 seeds MISP with that sha256, so the
# file must be written EXACTLY ONCE per run: the content is built in memory and
# written with a single printf (one open/write/close on the final path). A
# create-then-append pair lets realtime syscheck hash the intermediate file, and
# a tmp-file + mv rename is reported on the .tmp path instead of the marker.
# The first run includes the header line.
if [ -f "$MARKER" ]; then
  CONTENT="$(cat "$MARKER")"
else
  CONTENT="# wam-lab marker file (created ${TS})"
fi
CONTENT="${CONTENT}
# wam-lab change ${TS}"
printf '%s
' "$CONTENT" > "$MARKER"
MARKER_SHA="$(sha256sum "$MARKER" | awk '{print $1}')"
echo "[d] ${MARKER} changed; sha256=${MARKER_SHA}"
echo "    (before seeding 9.2, confirm this value equals syscheck.sha256_after on the indexed 550/554 alert)"

# --- (e) sudo burst + failed su ---------------------------------------------
# 6 successful sudo commands as the vagrant user (data.srcuser=vagrant) and
# 3 failed su attempts from the unprivileged vagrant user to root
# (rule 5301 "FAILED SU (to root) vagrant" -> data.srcuser=vagrant,
# data.dstuser=root). The target must be an existing account: su exits on the
# user lookup before PAM for a non-existent user and logs nothing; running su
# as root is never prompted at all.
echo "[e] 6x sudo as vagrant + 3 failed su vagrant -> root"
for i in $(seq 1 6); do
  sudo -u vagrant sudo -n true 2>/dev/null || true
done
for i in $(seq 1 3); do
  sudo -u vagrant sh -c "echo wrongpass${i} | su -c true root" >/dev/null 2>&1 || true
done

# --- summary ----------------------------------------------------------------
cat <<SUMMARY

=== summary ===
utc_time        : $(date -u +%Y-%m-%dT%H:%M:%SZ)
outbound_ips    : ${ABUSE_IPS[*]}
test_domain     : ${TEST_DOMAIN}
marker_file     : ${MARKER}
marker_sha256   : ${MARKER_SHA}
ssh_src_ip      : ${SECOND_IP}
ssh_user        : baduser
sudo_srcuser    : vagrant
su_srcuser      : vagrant
su_dstuser      : root
SUMMARY
