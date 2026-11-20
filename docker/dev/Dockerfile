# Development/build image: a bootstrapped wazuh-dashboard source tree so the
# plugin can be built and unit-tested on a machine without a VM.
#
#   docker build -f docker/dev/Dockerfile -t wam-dev:4.14.10 \
#     --build-arg DASHBOARD_REF=v4.14.10 docker/dev
#
# Then mount the plugin checkout at /osd/plugins/wazuhAlertManager:
#
#   docker run --rm -it -v "$PWD:/osd/plugins/wazuhAlertManager" wam-dev:4.14.10 \
#     bash -lc 'cd plugins/wazuhAlertManager && yarn test'
#
# Mirrors .github/workflows/build-and-release.yml: Node from the checkout's
# .nvmrc, corepack-managed yarn, test-only binary downloads skipped.

ARG NODE_VERSION=18.19.0
FROM node:${NODE_VERSION}-bookworm

ARG DASHBOARD_REF=v4.14.10
ENV CYPRESS_INSTALL_BINARY=0 \
    CHROMEDRIVER_SKIP_DOWNLOAD=true \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    NODE_OPTIONS=--max-old-space-size=6144 \
    OSD_REF=${DASHBOARD_REF}

RUN apt-get update && apt-get install -y --no-install-recommends git rsync zip unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /osd
RUN git clone --depth 1 --branch ${DASHBOARD_REF} https://github.com/wazuh/wazuh-dashboard.git /osd \
 && corepack enable \
 && printf 'network-timeout 600000\nnetwork-concurrency 4\n' > /osd/.yarnrc \
 && yarn osd bootstrap \
 && yarn cache clean

# The plugin is mounted here at run time.
RUN mkdir -p /osd/plugins/wazuhAlertManager
WORKDIR /osd
CMD ["bash"]
