# Prebuilt Wazuh dashboard image with the Wazuh Alert Manager plugin installed.
#
# The plugin zip must match the OpenSearch Dashboards version inside the base
# image exactly (see SUPPORTED_VERSIONS.md), so every image is built for one
# Wazuh release with the zip for that release's OSD version:
#
#   docker build -f docker/Dockerfile \
#     --build-arg WAZUH_VERSION=4.14.10 \
#     --build-arg OSD_VERSION=2.19.6 \
#     --build-arg PLUGIN_VERSION=2.0.3 \
#     -t wazuh-dashboard-alert-manager:4.14.10 .
#
# The zip and its checksum are downloaded from the matching GitHub release and
# the checksum is verified before the plugin is installed. Nothing else about
# the official image changes: same entrypoint, same user, same volumes and
# environment variables.

ARG WAZUH_VERSION
FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}

ARG WAZUH_VERSION
ARG OSD_VERSION
ARG PLUGIN_VERSION
ARG RELEASE_BASE=https://github.com/xrisbarney/Wazuh-alert-manager/releases/download

ADD --chown=1000:1000 ${RELEASE_BASE}/v${PLUGIN_VERSION}/wazuhAlertManager-${OSD_VERSION}.zip /tmp/wazuhAlertManager-${OSD_VERSION}.zip
ADD --chown=1000:1000 ${RELEASE_BASE}/v${PLUGIN_VERSION}/wazuhAlertManager-${OSD_VERSION}.zip.sha256 /tmp/wazuhAlertManager-${OSD_VERSION}.zip.sha256

RUN cd /tmp \
 && sha256sum -c wazuhAlertManager-${OSD_VERSION}.zip.sha256 \
 && /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install \
      file:///tmp/wazuhAlertManager-${OSD_VERSION}.zip \
 && rm -f /tmp/wazuhAlertManager-${OSD_VERSION}.zip /tmp/wazuhAlertManager-${OSD_VERSION}.zip.sha256

LABEL org.opencontainers.image.title="Wazuh dashboard with Wazuh Alert Manager" \
      org.opencontainers.image.description="wazuh/wazuh-dashboard:${WAZUH_VERSION} with the Wazuh Alert Manager ${PLUGIN_VERSION} plugin (OSD ${OSD_VERSION}) preinstalled" \
      org.opencontainers.image.source="https://github.com/xrisbarney/Wazuh-alert-manager" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/wazuh/wazuh-dashboard:${WAZUH_VERSION}" \
      io.wazuh-alert-manager.plugin-version="${PLUGIN_VERSION}" \
      io.wazuh-alert-manager.osd-version="${OSD_VERSION}" \
      io.wazuh-alert-manager.wazuh-version="${WAZUH_VERSION}"
