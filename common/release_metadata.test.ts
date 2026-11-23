/**
 * Release plumbing guard.
 *
 * The plugin version is stamped into three files that must never drift
 * (`package.json`, `opensearch_dashboards.json`, the generated
 * `common/build_info.ts`), and a release is only installable if the
 * compatibility matrix, the release workflow and `install.sh` all agree
 * about it. v3.0.0-rc.1 ships as a semver PRE-RELEASE, so everything here
 * is written against the version shape rather than a hard-coded literal -
 * a bare `\d+\.\d+\.\d+` assumption anywhere would break the RC.
 */
import fs from 'fs';
import path from 'path';

import { PLUGIN_VERSION, TARGET_OSD_VERSION, TARGET_WAZUH_VERSION, TARGET_WAZUH_MAJOR } from './build_info';

const root = path.resolve(__dirname, '..');
const read = (relative: string) => fs.readFileSync(path.join(root, relative), 'utf8');
const readJson = (relative: string) => JSON.parse(read(relative));

// CI copies the plugin into the dashboard tree with
// `rsync -a --exclude='.git' --exclude='.github'` and runs `yarn test` there,
// so repo-only files can be absent. Those assertions skip rather than make the
// whole suite (and every matrix build) fail to load.
const maybeRead = (relative: string): string | null => {
  const file = path.join(root, relative);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
};

const pkg = readJson('package.json');
const manifest = readJson('opensearch_dashboards.json');
const matrix: Array<{ wazuhVersion: string; osdVersion: string; prerelease?: boolean }> =
  readJson('supported-wazuh-versions.json');
const workflow = maybeRead(path.join('.github', 'workflows', 'build-and-release.yml'));
const installer = maybeRead('install.sh');

// major.minor.patch with an optional semver pre-release / build suffix.
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

describe('version stamps agree', () => {
  it('package.json, the manifest and build_info carry the same plugin version', () => {
    expect(PLUGIN_VERSION).toBe(pkg.version);
    expect(PLUGIN_VERSION).toBe(manifest.version);
  });

  it('the plugin version is valid semver (pre-releases allowed)', () => {
    expect(PLUGIN_VERSION).toMatch(SEMVER);
  });

  it('the manifest OSD target and build_info agree', () => {
    expect(TARGET_OSD_VERSION).toBe(manifest.opensearchDashboardsVersion);
    expect(manifest.opensearchDashboardsVersion).toMatch(SEMVER);
  });

  it('the recorded Wazuh target agrees with build_info and the matrix', () => {
    expect(TARGET_WAZUH_VERSION).toBe(pkg.wazuhAlertManager.targetWazuhVersion);
    expect(TARGET_WAZUH_MAJOR).toBe(Number(TARGET_WAZUH_VERSION.split('.')[0]));
    expect(
      matrix.some(
        (entry) =>
          entry.wazuhVersion === TARGET_WAZUH_VERSION && entry.osdVersion === TARGET_OSD_VERSION
      )
    ).toBe(true);
  });
});

(workflow ? describe : describe.skip)('release workflow', () => {
  it('marks a hyphenated (pre-release) tag as a GitHub pre-release', () => {
    expect(workflow).toContain("prerelease: ${{ contains(github.ref_name, '-') }}");
  });

  it('resolves body_path per tag and ships notes for this release line', () => {
    // The body is resolved from the tag, never hard-coded to one file.
    expect(workflow).toContain('body_path: ${{ steps.notes.outputs.path }}');
    const fallback = workflow!.match(/notes="(RELEASE_NOTES_v\$\{major\}\.0\.0\.md)"/);
    expect(fallback).not.toBeNull();
    // ... and the notes this release's tag resolves to must exist.
    const major = PLUGIN_VERSION.split('.')[0];
    expect(fs.existsSync(path.join(root, `RELEASE_NOTES_v${major}.0.0.md`))).toBe(true);
  });

  it('builds every matrix pair, including the 5.0 preview target', () => {
    const built = [
      ...workflow!.matchAll(
        /- wazuhVersion: "([^"]+)"\s*\n\s*osdVersion: "([^"]+)"\s*\n\s*dashboardRef: "([^"]+)"/g
      ),
    ].map(([, wazuhVersion, osdVersion, dashboardRef]) => ({
      wazuhVersion,
      osdVersion,
      dashboardRef,
    }));
    expect(built.length).toBeGreaterThan(0);
    for (const entry of built) {
      // Each built pair must be a pair the compatibility matrix declares, and
      // the checkout ref must be the Wazuh version it claims to build.
      expect(
        matrix.some(
          (row) =>
            row.wazuhVersion === entry.wazuhVersion && row.osdVersion === entry.osdVersion
        )
      ).toBe(true);
      expect(entry.dashboardRef).toBe(`v${entry.wazuhVersion}`);
    }
    const builtOsd = new Set(built.map((entry) => entry.osdVersion));
    for (const entry of matrix) expect(builtOsd.has(entry.osdVersion)).toBe(true);
    expect(built.some((entry) => entry.wazuhVersion === '5.0.0-rc2')).toBe(true);
  });
});

(installer ? describe : describe.skip)('install.sh resolves this release', () => {
  it('supports the OSD version this build targets', () => {
    const match = installer!.match(/^SUPPORTED_OSD_VERSIONS="([^"]+)"/m);
    expect(match).not.toBeNull();
    expect(match![1].trim().split(/\s+/)).toContain(TARGET_OSD_VERSION);
  });

  it('fails closed on an OSD version only a pre-release ships', () => {
    // `/releases/latest` never resolves a GitHub pre-release, so the default
    // (no --version) path must not build a URL that 404s.
    const match = installer!.match(/^PRERELEASE_ONLY_OSD_VERSIONS="([^"]*)"/m);
    expect(match).not.toBeNull();
    const prereleaseOnly = match![1].trim().split(/\s+/).filter(Boolean);
    for (const entry of matrix) {
      if (entry.prerelease) expect(prereleaseOnly).toContain(entry.osdVersion);
      else expect(prereleaseOnly).not.toContain(entry.osdVersion);
    }
    expect(installer).toContain('rerun with --version $PRERELEASE_TAG_HINT');
  });

  it('names the artifact by OSD version only, so any plugin version resolves', () => {
    expect(installer).toContain("printf 'wazuhAlertManager-%s.zip' \"$OSD_VERSION\"");
  });

  it('pins a release by tag without assuming a three-part version', () => {
    expect(installer).toContain('ARTIFACT_URL="$BASE_URL/download/v$VERSION/$name"');
    // Nothing may validate --version against a bare x.y.z shape.
    expect(installer).not.toMatch(/VERSION.*=~.*\[0-9\]\+\?\.\[0-9\]/);
  });
});
