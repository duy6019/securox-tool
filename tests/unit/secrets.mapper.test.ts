import { describe, it, expect } from 'bun:test';
import { mapGitleaksToFindings } from '../../src/scanners/secrets';

const FIXTURE_GITLEAKS_OUTPUT = [
  {
    RuleID: 'aws-access-token',
    Description: 'AWS Access Key ID',
    File: '.env',
    StartLine: 3,
  },
  {
    RuleID: 'github-pat',
    Description: 'GitHub Personal Access Token',
    File: 'config/auth.js',
    StartLine: 12,
  },
];

describe('mapGitleaksToFindings', () => {
  it('always maps findings to critical severity', () => {
    const findings = mapGitleaksToFindings(FIXTURE_GITLEAKS_OUTPUT);
    expect(findings.every(f => f.severity === 'critical')).toBe(true);
  });

  it('maps tool to secrets', () => {
    const findings = mapGitleaksToFindings(FIXTURE_GITLEAKS_OUTPUT);
    expect(findings.every(f => f.tool === 'secrets')).toBe(true);
  });

  it('maps file and line correctly', () => {
    const findings = mapGitleaksToFindings(FIXTURE_GITLEAKS_OUTPUT);
    const aws = findings.find(f => f.id === 'aws-access-token');
    expect(aws?.file).toBe('.env');
    expect(aws?.line).toBe(3);
  });

  it('includes rotation remediation message', () => {
    const findings = mapGitleaksToFindings(FIXTURE_GITLEAKS_OUTPUT);
    expect(findings[0]?.remediation).toContain('Rotate');
  });

  it('returns empty array for null/empty data', () => {
    expect(mapGitleaksToFindings([])).toEqual([]);
    expect(mapGitleaksToFindings(null as any)).toEqual([]);
  });
});
