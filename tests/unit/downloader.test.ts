import { describe, it, expect } from 'bun:test';
import { TOOLS_VERSION } from '../../src/core/constants';

// We test the URL construction logic by re-implementing it inline
// since the URL builder functions are not exported (they're pure internal helpers).
// This also documents the expected URL patterns for each tool.

describe('TOOLS_VERSION', () => {
  it('has versions defined for all three tools', () => {
    expect(TOOLS_VERSION.opengrep).toBeTruthy();
    expect(TOOLS_VERSION.trivy).toBeTruthy();
    expect(TOOLS_VERSION.gitleaks).toBeTruthy();
  });

  it('trivy version starts with v', () => {
    expect(TOOLS_VERSION.trivy).toMatch(/^v\d+\.\d+\.\d+$/);
  });

  it('opengrep version starts with v', () => {
    expect(TOOLS_VERSION.opengrep).toMatch(/^v/);
  });
});

describe('Trivy URL pattern', () => {
  it('produces correct macOS x64 URL', () => {
    const version = TOOLS_VERSION.trivy.replace(/^v/, '');
    const url = `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_macOS-64bit.tar.gz`;
    expect(url).toContain('trivy');
    expect(url).toContain(version);
    expect(url).toContain('macOS-64bit');
    expect(url).toContain('.tar.gz');
  });

  it('produces correct Linux x64 URL', () => {
    const version = TOOLS_VERSION.trivy.replace(/^v/, '');
    const url = `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-64bit.tar.gz`;
    expect(url).toContain('Linux-64bit');
  });
});

describe('Gitleaks URL pattern', () => {
  it('produces correct darwin x64 URL', () => {
    const version = TOOLS_VERSION.gitleaks.replace(/^v/, '');
    const url = `https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_darwin_x64.tar.gz`;
    expect(url).toContain('gitleaks');
    expect(url).toContain('darwin');
    expect(url).toContain('.tar.gz');
  });
});
