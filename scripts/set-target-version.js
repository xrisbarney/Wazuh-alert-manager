#!/usr/bin/env node
/**
 * Retargets this plugin at a different OpenSearch Dashboards / Wazuh
 * dashboard release without touching any source code.
 *
 * OSD refuses to load a plugin whose opensearch_dashboards.json
 * "opensearchDashboardsVersion" doesn't exactly match the running
 * dashboard version - that check is part of the platform, not something a
 * plugin can opt out of. This script is what makes that a one-command
 * step instead of hand-editing JSON: it patches opensearch_dashboards.json
 * and package.json in place with the version you're building for.
 *
 * The plugin code itself only touches stable, documented OSD APIs
 * (core.http, core.opensearch.client, core.application.register, the
 * `data` plugin, @elastic/eui), so a rebuild is normally all a new target
 * version needs - see SUPPORTED_VERSIONS.md for the range this has
 * actually been tested against.
 *
 * Usage:
 *   node scripts/set-target-version.js --osd-version 2.19.5 [--plugin-version 1.1.0]
 */
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      const value = argv[i + 1];
      args[key] = value;
      i += 1;
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (!args['osd-version']) {
  console.error('Usage: node scripts/set-target-version.js --osd-version <version> [--plugin-version <version>]');
  process.exit(1);
}

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'opensearch_dashboards.json');
const packagePath = path.join(root, 'package.json');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.opensearchDashboardsVersion = args['osd-version'];
if (args['plugin-version']) {
  manifest.version = args['plugin-version'];
}
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

if (args['plugin-version']) {
  const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  pkg.version = args['plugin-version'];
  fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
}

console.log(
  `Targeted opensearchDashboardsVersion=${args['osd-version']}` +
    (args['plugin-version'] ? `, plugin version=${args['plugin-version']}` : '')
);
console.log('Now run `yarn build` from inside <wazuh-dashboard>/plugins/wazuhAlertManager to produce the zip.');
