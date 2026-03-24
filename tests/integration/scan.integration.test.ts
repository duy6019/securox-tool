import { describe, it, expect, beforeAll } from 'bun:test';
import * as fs from 'fs';
import * as path from 'path';
import { getBinaryPath } from '../../src/core/environment';
import { runSAST } from '../../src/scanners/sast';
import { runSCA } from '../../src/scanners/sca';
import { runSecrets } from '../../src/scanners/secrets';

const FIXTURES_DIR = path.resolve(import.meta.dir, '../../test-workspace');

// Guard: skip entire suite if binaries are not downloaded yet
function binaryExists(tool: 'opengrep' | 'trivy' | 'gitleaks'): boolean {
  return fs.existsSync(getBinaryPath(tool));
}

describe('SAST Integration (Opengrep)', () => {
  beforeAll(() => {
    if (!binaryExists('opengrep')) {
      console.warn('⚠️  Opengrep binary not found. Run: bun run scripts/download-binaries.ts');
    }
  });

  it('detects vulnerabilities in vuln.js fixture', async () => {
    if (!binaryExists('opengrep')) return; // skip gracefully
    const findings = await runSAST(FIXTURES_DIR);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every(f => f.tool === 'sast')).toBe(true);
    expect(['low', 'medium', 'high', 'critical']).toContain(findings[0]?.severity ?? 'low');
  }, 30_000); // 30s timeout: opengrep can be slow on first run
});

describe('SCA Integration (Trivy)', () => {
  beforeAll(() => {
    if (!binaryExists('trivy')) {
      console.warn('⚠️  Trivy binary not found. Run: bun run scripts/download-binaries.ts');
    }
  });

  it('detects known CVEs in vulnerable package.json fixture', async () => {
    if (!binaryExists('trivy')) return;
    const findings = await runSCA(FIXTURES_DIR);
    // lodash 4.17.4 has multiple known CVEs
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every(f => f.tool === 'sca')).toBe(true);
    const hasLodashCVE = findings.some(f => f.title?.toLowerCase().includes('lodash') || f.id.startsWith('CVE'));
    expect(hasLodashCVE).toBe(true);
  }, 60_000); // 60s: trivy may run db update on first run
});

describe('Secrets Integration (Gitleaks)', () => {
  beforeAll(() => {
    if (!binaryExists('gitleaks')) {
      console.warn('⚠️  Gitleaks binary not found. Run: bun run scripts/download-binaries.ts');
    }
  });

  it('detects fake AWS and GitHub secrets in fixture', async () => {
    if (!binaryExists('gitleaks')) return;
    const findings = await runSecrets(FIXTURES_DIR);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every(f => f.severity === 'critical')).toBe(true);
    expect(findings.every(f => f.tool === 'secrets')).toBe(true);
  }, 30_000);
});
