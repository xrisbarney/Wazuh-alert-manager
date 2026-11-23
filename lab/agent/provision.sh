#!/usr/bin/env bash
# Provisions wam-lab-agent (run as root by the Vagrantfile). Idempotent: safe to
# re-run with `vagrant provision`.
#
# Inputs (env, set by the Vagrantfile):
#   WAZUH_MANAGER                 manager address the agent enrols against (default 10.0.2.2 = VirtualBox NAT host)
#   WAZUH_AGENT_NAME              agent name (wam-lab-agent)
#   WAZUH_REGISTRATION_PASSWORD   only forwarded when non-empty (manager <auth><use_password>)
#   WAM_LAB_SECOND_IP             extra address on the NAT interface used as the self-test login source
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# Keep needrestart from opening an interactive "which services to restart"
# prompt mid-provision (it otherwise aborts the SSH-driven run).
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

WAZUH_MANAGER="${WAZUH_MANAGER:-10.0.2.2}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-wam-lab-agent}"
WAM_LAB_SECOND_IP="${WAM_LAB_SECOND_IP:-10.0.2.77}"
OSSEC_CONF=/var/ossec/etc/ossec.conf

log() { echo "[provision] $*"; }

# --- base packages ---------------------------------------------------------
log "installing base packages"
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins curl wget openssh-server sshpass gnupg apt-transport-https ca-certificates >/dev/null

# --- Wazuh agent 4.x from the official apt repository -----------------------
# https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html
if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  log "adding Wazuh apt key"
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
fi
if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
fi
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  log "installing wazuh-agent (manager=${WAZUH_MANAGER}, name=${WAZUH_AGENT_NAME})"
  # Pin to the 4.14 line so the agent matches the 4.14.10 stack.
  CANDIDATE=$(apt-cache madison wazuh-agent | awk '$3 ~ /^4\.14\./ {print $3; exit}')
  if [ -n "${WAZUH_REGISTRATION_PASSWORD:-}" ]; then
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" \
      WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
      apt-get install -y -qq "wazuh-agent${CANDIDATE:+=$CANDIDATE}" >/dev/null
  else
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" \
      apt-get install -y -qq "wazuh-agent${CANDIDATE:+=$CANDIDATE}" >/dev/null
  fi
  # Hold the version so an unattended upgrade cannot drift past the manager.
  apt-mark hold wazuh-agent >/dev/null
fi

# --- ossec.conf tweaks -------------------------------------------------------
# Realtime syscheck on /etc (the stock config scans /etc on a schedule inside a
# combined <directories> line). Replace that line in place when present;
# otherwise add a realtime /etc line before </syscheck>.
if grep -q '<directories>/etc,/usr/bin,/usr/sbin</directories>' "$OSSEC_CONF"; then
  sed -i 's#<directories>/etc,/usr/bin,/usr/sbin</directories>#<directories check_all="yes" realtime="yes">/etc</directories>\n    <directories>/usr/bin,/usr/sbin</directories>#' "$OSSEC_CONF"
  log "syscheck: /etc switched to realtime"
elif ! grep -q 'realtime="yes">/etc<' "$OSSEC_CONF"; then
  sed -i 's#</syscheck>#  <directories check_all="yes" realtime="yes">/etc</directories>\n  </syscheck>#' "$OSSEC_CONF"
  log "syscheck: realtime /etc line added"
fi
# Log collection: the stock 4.14 Linux config already collects journald, which
# carries every sshd/sudo/PAM line (data.srcip / data.srcuser / data.dstuser).
# Adding /var/log/auth.log on top ingests every auth line twice (one alert from
# journald, one from auth.log), so this provisioner does NOT add it and removes
# the block an earlier revision appended.
if grep -q '<location>/var/log/auth.log</location>' "$OSSEC_CONF"; then
  perl -0pi -e 's#\n?<ossec_config>\s*<localfile>\s*<log_format>syslog</log_format>\s*<location>/var/log/auth.log</location>\s*</localfile>\s*</ossec_config>\n?#\n#g' "$OSSEC_CONF"
  log "localfile: duplicate /var/log/auth.log collection removed (journald already covers it)"
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

# --- auditd rules ----------------------------------------------------------
# connect() with a 16-byte sockaddr (a2=16 => AF_INET) tags outbound IPv4
# connects; /etc writes are tagged as file writes. The b32 variant covers a
# 32-bit userland via socketcall(SYS_CONNECT=3).
#
# The keys MUST be the ones in the manager's CDB list etc/lists/audit-keys
# (stock: audit-wazuh-w|r|a|x|c), because the stock 0365-auditd_rules.xml only
# raises the key-based alerts 80780-80792 for keys present in that list. A
# custom key (an earlier revision used wam_connect / wam_etc) is collected but
# never becomes an alert.
cat > /etc/audit/rules.d/wam-lab.rules <<'RULES'
-a always,exit -F arch=b64 -S connect -F a2=16 -k audit-wazuh-c
-a always,exit -F arch=b32 -S socketcall -F a0=3 -k audit-wazuh-c
-w /etc/ -p wa -k audit-wazuh-w
RULES
augenrules --load >/dev/null 2>&1 || true
systemctl enable --now auditd >/dev/null 2>&1 || true
systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true

# --- sshd: accept password auth so self-test logins reach the auth stage and
# are recorded by PAM/journald (needed for data.srcip on the agent).
if [ -d /etc/ssh/sshd_config.d ]; then
  cat > /etc/ssh/sshd_config.d/10-wam-lab.conf <<'SSHCFG'
PasswordAuthentication yes
PermitRootLogin no
SSHCFG
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
fi

# --- second address on the NAT interface -----------------------------------
# A secondary /24 address so self-directed login attempts carry a distinct
# source (data.srcip=10.0.2.77) rather than 127.0.0.1. A tiny systemd unit
# re-adds it on boot so generate.sh can rely on it (`ip addr replace` is
# idempotent, so the unit and a re-provision never fail with "File exists").
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

log "provision complete; agent targets manager ${WAZUH_MANAGER} as ${WAZUH_AGENT_NAME}"
systemctl --no-pager --full status wazuh-agent 2>/dev/null | head -5 || true
