const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const declared = require(path.join(root, 'supported-wazuh-versions.json'));
const supportedLines = new Set(['4.12', '4.13', '4.14']);

function unique(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function sameValues(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function getJson(url) {
  const headers = { 'user-agent': 'wazuh-alert-manager-compatibility-check' };
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  return response.json();
}

async function main() {
  const tags = await getJson('https://api.github.com/repos/wazuh/wazuh-dashboard/tags?per_page=100');
  const officialVersions = unique(tags
    .map((tag) => String(tag.name || '').replace(/^v/, ''))
    .filter((version) => /^4\.(12|13|14)\.\d+$/.test(version)));
  const declaredVersions = unique(declared.map((entry) => entry.wazuhVersion));

  if (!sameValues(officialVersions, declaredVersions)) {
    const missing = officialVersions.filter((version) => !declaredVersions.includes(version));
    const stale = declaredVersions.filter((version) => !officialVersions.includes(version));
    throw new Error([
      'The supported Wazuh patch list is out of date.',
      missing.length ? `Add official release(s): ${missing.join(', ')}` : '',
      stale.length ? `No longer present upstream: ${stale.join(', ')}` : '',
    ].filter(Boolean).join(' '));
  }

  for (const entry of declared) {
    const line = entry.wazuhVersion.split('.').slice(0, 2).join('.');
    if (!supportedLines.has(line)) throw new Error(`Unexpected supported line ${line}`);
    const pkg = await getJson(`https://raw.githubusercontent.com/wazuh/wazuh-dashboard/v${entry.wazuhVersion}/package.json`);
    if (pkg.version !== entry.osdVersion) {
      throw new Error(`Wazuh ${entry.wazuhVersion} declares OSD ${pkg.version}, not ${entry.osdVersion}`);
    }
  }

  const expectedOsd = unique(declared.map((entry) => entry.osdVersion));
  const installer = fs.readFileSync(path.join(root, 'install.sh'), 'utf8');
  const installerMatch = installer.match(/^SUPPORTED_OSD_VERSIONS="([^"]+)"/m);
  if (!installerMatch) throw new Error('Could not read SUPPORTED_OSD_VERSIONS from install.sh');
  const installerOsd = unique(installerMatch[1].trim().split(/\s+/));

  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'build-and-release.yml'), 'utf8');
  const workflowOsd = unique([...workflow.matchAll(/osdVersion:\s*"([^"]+)"/g)].map((match) => match[1]));

  if (!sameValues(expectedOsd, installerOsd)) {
    throw new Error(`Installer targets ${installerOsd.join(', ')}; expected ${expectedOsd.join(', ')}`);
  }
  if (!sameValues(expectedOsd, workflowOsd)) {
    throw new Error(`Release CI targets ${workflowOsd.join(', ')}; expected ${expectedOsd.join(', ')}`);
  }

  console.log(`Compatibility matrix is current: ${declaredVersions.length} Wazuh patches, ${expectedOsd.length} OSD artifacts.`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
