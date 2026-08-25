# Installation

## Download

Get the plugin `.zip` from the **[Releases page](https://github.com/xrisbarney/Wazuh-alert-manager/releases)** — pick the asset matching your Wazuh version:

| Wazuh | OpenSearch Dashboards | Asset |
|-------|-----------------------|-------|
| 4.12  | 2.19.1 | `wazuhAlertManager-1.5.0-wazuh4.12.zip` |
| 4.13  | 2.19.2 | `wazuhAlertManager-1.5.0-wazuh4.13.zip` |
| 4.14  | 2.19.5 | `wazuhAlertManager-1.5.0-wazuh4.14.zip` |

## Prerequisites

- A running **Wazuh 4.12, 4.13, or 4.14** stack (indexer + dashboard).
- Administrative (root) access to the host running **wazuh-dashboard**.
- The plugin `.zip` for your version, downloaded from the [Releases page](https://github.com/xrisbarney/Wazuh-alert-manager/releases).

## Install

Pick the zip that matches your Wazuh version and install it with the bundled OpenSearch Dashboards plugin tool:

```bash
# Example for Wazuh 4.14 (OSD 2.19.5)
sudo systemctl stop wazuh-dashboard

sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  install file:///path/to/wazuhAlertManager-1.5.0-wazuh4.14.zip --allow-root

sudo systemctl start wazuh-dashboard
```

The first start after install rebuilds the dashboard's browser bundles, which can take a few minutes. When it's ready, open the dashboard and look for **Wazuh alert manager** in the left navigation.

## Upgrade

Remove the old version first, then install the new one:

```bash
sudo systemctl stop wazuh-dashboard
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove wazuhAlertManager --allow-root
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///path/to/<new>.zip --allow-root
sudo systemctl start wazuh-dashboard
```

The plugin migrates its own index mappings automatically on start (an idempotent, versioned migration). Incompatible changes fail safe — they are logged and skipped rather than aborting startup.

## Container deployments (Docker / Kubernetes)

In containerised Wazuh deployments the dashboard is an immutable image, so installing the plugin **at runtime is ephemeral** — it is lost when the container/pod is recreated. The durable approach is to **bake the plugin into a custom image**.

> **Match the version.** The plugin zip must match the OpenSearch Dashboards version inside the image. Wazuh 4.14 images ship OSD 2.19.5 → use the `…-wazuh4.14.zip`. Check with `docker exec <ctr> cat /usr/share/wazuh-dashboard/VERSION` (or the image tag).

### Docker — custom image (recommended)

`Dockerfile`:

```dockerfile
# Match this tag to your deployed Wazuh version
FROM wazuh/wazuh-dashboard:4.14.0

COPY wazuhAlertManager-1.5.0-wazuh4.14.zip /tmp/wam.zip
RUN /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
      install file:///tmp/wam.zip --allow-root \
 && rm -f /tmp/wam.zip
```

Build, then point your `docker-compose.yml` (from the [wazuh-docker](https://github.com/wazuh/wazuh-docker) repo) at it:

```bash
docker build -t my-registry/wazuh-dashboard-wam:4.14.0 .
```

```yaml
# docker-compose.yml — the wazuh.dashboard service
services:
  wazuh.dashboard:
    image: my-registry/wazuh-dashboard-wam:4.14.0   # was: wazuh/wazuh-dashboard:4.14.0
    # everything else (volumes, env, TLS certs) stays the same
```

```bash
docker compose up -d wazuh.dashboard
```

### Docker — quick runtime install (ephemeral, for testing only)

```bash
docker cp wazuhAlertManager-1.5.0-wazuh4.14.zip <dashboard-container>:/tmp/wam.zip
docker exec -u 0 <dashboard-container> \
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///tmp/wam.zip --allow-root
docker restart <dashboard-container>
```

This is undone by `docker compose up --force-recreate` or any image pull — use the custom image for anything you keep.

### Kubernetes — custom image (recommended)

The Wazuh dashboard runs as a Deployment/StatefulSet in the [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) manifests. Bake the plugin into an image (same `Dockerfile` as above), push it to a registry your cluster can pull, then reference it:

```bash
docker build -t my-registry/wazuh-dashboard-wam:4.14.0 .
docker push my-registry/wazuh-dashboard-wam:4.14.0
```

```yaml
# wazuh-dashboard Deployment (or StatefulSet)
spec:
  template:
    spec:
      containers:
        - name: wazuh-dashboard
          image: my-registry/wazuh-dashboard-wam:4.14.0   # was the stock wazuh/wazuh-dashboard image
```

Apply and roll out:

```bash
kubectl apply -f wazuh-dashboard-deploy.yaml
kubectl -n wazuh rollout restart deploy/wazuh-dashboard   # use your resource's kind/name
kubectl -n wazuh rollout status  deploy/wazuh-dashboard
```

> **Probe timeouts.** The dashboard's readiness/liveness probes may cut the first (slower) boot short after the plugin is added — the pod can `CrashLoopBackOff` while still starting. Raise `readinessProbe.initialDelaySeconds` / `failureThreshold` on the dashboard container if you see that. The same class of issue affects **wazuh-indexer**; see **[[Troubleshooting#indexer-503]]**.

### Helm

If you deploy via a Helm chart, set the dashboard image to your custom image through the chart's values (e.g. `dashboard.image.repository` / `dashboard.image.tag` — the exact keys depend on your chart) rather than editing manifests directly.

## First run

On first start the plugin provisions its own indices (see [[Architecture]]) and begins syncing alert workflow state. You do **not** need to reindex `wazuh-alerts-*`.

## Uninstall

```bash
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove wazuhAlertManager --allow-root
sudo systemctl restart wazuh-dashboard
```

Removing the plugin leaves its workflow indices (`wazuh-alert-status`, `wazuh-alert-manager-*`) in place. Delete them manually if you want a clean slate.

## Note for smaller hosts

On modest VMs the **wazuh-indexer** can take longer than systemd's default 3-minute start timeout to boot (OpenSearch loads many plugins on a small heap), especially after an unclean shutdown — the dashboard then shows HTTP 503. This is a stock Wazuh behaviour, not the plugin, but the fix is easy. See **[[Troubleshooting#indexer-503]]**.
