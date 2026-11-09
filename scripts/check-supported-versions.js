const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const declared = require(path.join(root, 'supported-wazuh-versions.json'));
// Wazuh lines this plugin targets. 4.x reads `wazuh-alerts-*`; 5.0 reads the
// `wazuh-findings-v5-*` data streams (see server/lib/source_profile.ts).
const supportedLines = new Set(['4.12', '4.13', '4.14', '5.0']);
const FINAL_TAG = /^(4\.(12|13|14)|5\.0)\.\d+$/;

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
    .filter((version) => FINAL_TAG.test(version)));
  // Prerelease rows (release candidates, betas) are tracked deliberately and
  // are not expected to appear in the final-tag comparison. They are still
  // verified against the exact upstream OSD version below.
  const finalDeclared = declared.filter((entry) => !entry.prerelease);
  const prereleaseDeclared = declared.filter((entry) => entry.prerelease);
  const declaredVersions = unique(finalDeclared.map((entry) => entry.wazuhVersion));

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

  for (const entry of prereleaseDeclared) {
    const finalTag = entry.wazuhVersion.replace(/-.*$/, '');
    if (officialVersions.includes(finalTag)) {
      throw new Error(`Wazuh ${finalTag} is now final upstream; replace the prerelease row ${entry.wazuhVersion}`);
    }
  }

  // The installer and release CI must serve every final target. Prerelease
  // targets are development-only until the owner promotes them.
  const expectedOsd = unique(finalDeclared.map((entry) => entry.osdVersion));
  const installer = fs.readFileSync(path.join(root, 'install.sh'), 'utf8');
  const installerMatch = installer.match(/^SUPPORTED_OSD_VERSIONS="([^"]+)"/m);
  if (!installerMatch) throw new Error('Could not read SUPPORTED_OSD_VERSIONS from install.sh');
  const installerOsd = unique(installerMatch[1].trim().split(/\s+/));

  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'build-and-release.yml'), 'utf8');
  const workflowOsd = unique([...workflow.matchAll(/osdVersion:\s*"([^"]+)"/g)].map((match) => match[1]));

  const missingFromInstaller = expectedOsd.filter((version) => !installerOsd.includes(version));
  const unexpectedInInstaller = installerOsd.filter((version) => !expectedOsd.includes(version) &&
    !prereleaseDeclared.some((entry) => entry.osdVersion === version));
  if (missingFromInstaller.length || unexpectedInInstaller.length) {
    throw new Error(`Installer targets ${installerOsd.join(', ')}; expected ${expectedOsd.join(', ')}`);
  }
  const missingFromWorkflow = expectedOsd.filter((version) => !workflowOsd.includes(version));
  const unexpectedInWorkflow = workflowOsd.filter((version) => !expectedOsd.includes(version) &&
    !prereleaseDeclared.some((entry) => entry.osdVersion === version));
  if (missingFromWorkflow.length || unexpectedInWorkflow.length) {
    throw new Error(`Release CI targets ${workflowOsd.join(', ')}; expected ${expectedOsd.join(', ')}`);
  }

  console.log(
    `Compatibility matrix is current: ${declaredVersions.length} Wazuh patches, ${expectedOsd.length} OSD artifacts` +
      (prereleaseDeclared.length ? `, ${prereleaseDeclared.length} prerelease target(s) tracked` : '') + '.'
  );
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
