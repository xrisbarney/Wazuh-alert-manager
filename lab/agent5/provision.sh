#!/usr/bin/env bash
# Provisions wam-lab-agent-5 (run as root by the Vagrantfile). Idempotent.
#
# Inputs (env, set by the Vagrantfile):
#   WAM_LAB5_MANAGER        NAT address of the Docker host (default 10.0.2.2)
#   WAZUH_AGENT_NAME        agent name (wam-lab-agent-5)
#   WAZUH_ENROLLMENT_TOKEN  token minted on the 5.0 manager for host.docker.internal:1527
#   WAM_LAB_SECOND_IP       extra NAT-interface address used as the self-test login source
#   WAM_AGENT_DEB_URL       the 5.0.0-rc2 agent .deb (pre-release pool on the staging host)
#
# The telemetry side (auditd rules, realtime /etc syscheck, sshd password auth,
# second address) mirrors lab/agent/provision.sh so lab/agent/generate.sh
# (mounted at /lab4) produces the same artifacts on the 5.0 line.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

WAM_LAB5_MANAGER="${WAM_LAB5_MANAGER:-10.0.2.2}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-wam-lab-agent-5}"
WAM_LAB_SECOND_IP="${WAM_LAB_SECOND_IP:-10.0.2.78}"
WAM_AGENT_DEB_URL="${WAM_AGENT_DEB_URL:?}"
OSSEC_CONF=/var/ossec/etc/ossec.conf

log() { echo "[provision5] $*"; }

# --- base packages ---------------------------------------------------------
log "installing base packages"
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins curl wget openssh-server sshpass ca-certificates >/dev/null

# --- the token names host.docker.internal; on VirtualBox NAT that is the host -
if ! grep -q 'host.docker.internal' /etc/hosts; then
  echo "${WAM_LAB5_MANAGER} host.docker.internal" >> /etc/hosts
  log "/etc/hosts: host.docker.internal -> ${WAM_LAB5_MANAGER}"
fi

# --- Wazuh agent 5.0.0-rc2 ---------------------------------------------------
# No stable apt line exists for 5.0 yet; install the pre-release .deb straight
# from the pool. The package reads WAZUH_ENROLLMENT_TOKEN / WAZUH_AGENT_NAME at
# install time, stores the token and lets the agent finish the bootstrap
# (CA fetch + enrollment) on first start.
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  [ -n "${WAZUH_ENROLLMENT_TOKEN:-}" ] || { echo "WAZUH_ENROLLMENT_TOKEN is empty: write lab/agent5/.enrollment-token first" >&2; exit 1; }
  log "downloading $(basename "$WAM_AGENT_DEB_URL")"
  curl -fsSL -o /tmp/wazuh-agent.deb "$WAM_AGENT_DEB_URL"
  log "installing wazuh-agent 5.0 (name=${WAZUH_AGENT_NAME}, token endpoint host.docker.internal:1527)"
  WAZUH_ENROLLMENT_TOKEN="$WAZUH_ENROLLMENT_TOKEN" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" \
    apt-get install -y -qq /tmp/wazuh-agent.deb >/dev/null
  apt-mark hold wazuh-agent >/dev/null
  rm -f /tmp/wazuh-agent.deb
fi

# --- ossec.conf tweaks (same as the 4.14 lab) --------------------------------
if grep -q '<directories>/etc,/usr/bin,/usr/sbin</directories>' "$OSSEC_CONF"; then
  sed -i 's#<directories>/etc,/usr/bin,/usr/sbin</directories>#<directories check_all="yes" realtime="yes">/etc</directories>\n    <directories>/usr/bin,/usr/sbin</directories>#' "$OSSEC_CONF"
  log "syscheck: /etc switched to realtime"
elif ! grep -q 'realtime="yes">/etc<' "$OSSEC_CONF"; then
  sed -i 's#</syscheck>#  <directories check_all="yes" realtime="yes">/etc</directories>\n  </syscheck>#' "$OSSEC_CONF"
  log "syscheck: realtime /etc line added"
fi
# journald carries sshd/sudo/PAM (srcip/srcuser/dstuser); add it when the
# generated profile does not already collect it.
if ! grep -q '<log_format>journald</log_format>' "$OSSEC_CONF"; then
  cat >> "$OSSEC_CONF" <<'XML'
<ossec_config>
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
</ossec_config>
XML
  log "localfile: journald added"
fi
if ! grep -q '<location>/var/log/audit/audit.log</location>' "$OSSEC_CONF"; then
  cat >> "$OSSEC_CONF" <<'XML'
<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
XML
  log "localfile: /var/log/audit/audit.log added"
fi

# --- auditd rules (keys must match the manager's audit-keys CDB list) --------
cat > /etc/audit/rules.d/wam-lab.rules <<'RULES'
-a always,exit -F arch=b64 -S connect -F a2=16 -k audit-wazuh-c
-a always,exit -F arch=b32 -S socketcall -F a0=3 -k audit-wazuh-c
-w /etc/ -p wa -k audit-wazuh-w
RULES
augenrules --load >/dev/null 2>&1 || true
systemctl enable --now auditd >/dev/null 2>&1 || true
systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true

# --- sshd password auth for the self-test logins ----------------------------
if [ -d /etc/ssh/sshd_config.d ]; then
  cat > /etc/ssh/sshd_config.d/10-wam-lab.conf <<'SSHCFG'
PasswordAuthentication yes
PermitRootLogin no
SSHCFG
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
fi

# --- second address on the NAT interface -----------------------------------
NAT_IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
NAT_IFACE="${NAT_IFACE:-enp0s3}"
ip addr replace "${WAM_LAB_SECOND_IP}/24" dev "$NAT_IFACE"
cat > /etc/systemd/system/wam-lab-secondip.service <<UNIT
[Unit]
Description=WAM lab secondary address on ${NAT_IFACE}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/ip addr replace ${WAM_LAB_SECOND_IP}/24 dev ${NAT_IFACE}
ExecStop=/sbin/ip addr del ${WAM_LAB_SECOND_IP}/24 dev ${NAT_IFACE}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed wam-lab-secondip.service >/dev/null 2>&1 || true
systemctl enable --now wam-lab-secondip.service >/dev/null 2>&1 || true
systemctl restart wam-lab-secondip.service >/dev/null 2>&1 || true

# --- start the agent --------------------------------------------------------
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent >/dev/null 2>&1 || true
sleep 15
log "provision complete; agent ${WAZUH_AGENT_NAME} -> host.docker.internal:1527 (${WAM_LAB5_MANAGER})"
systemctl --no-pager --full status wazuh-agent 2>/dev/null | head -5 || true
grep -E 'Enroll|enroll|ERROR|Connected' /var/ossec/logs/ossec.log 2>/dev/null | tail -8 || true
