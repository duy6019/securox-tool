import { describe, it, expect } from 'bun:test';
import { mapTrivyToFindings } from '../../src/scanners/sca';

const FIXTURE_TRIVY_OUTPUT = {
  Results: [
    {
      Target: 'package-lock.json',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2023-1234',
          PkgName: 'lodash',
          Severity: 'CRITICAL',
          Title: 'Prototype Pollution in lodash',
          FixedVersion: '4.17.21',
        },
        {
          VulnerabilityID: 'CVE-2023-5678',
          PkgName: 'axios',
          Severity: 'HIGH',
          Title: 'SSRF in axios',
          FixedVersion: '1.6.0',
        },
        {
          VulnerabilityID: 'CVE-2023-9999',
          PkgName: 'old-pkg',
          Severity: 'MEDIUM',
          Title: 'Some medium issue',
          FixedVersion: null,
        },
        {
          VulnerabilityID: 'CVE-2023-0001',
          PkgName: 'another-pkg',
          Severity: 'LOW',
          Title: 'Low severity issue',
          FixedVersion: '2.0.0',
        },
      ],
    },
  ],
};

describe('mapTrivyToFindings', () => {
  it('maps CRITICAL severity correctly', () => {
    const findings = mapTrivyToFindings(FIXTURE_TRIVY_OUTPUT);
    const f = findings.find(f => f.id === 'CVE-2023-1234');
    expect(f?.severity).toBe('critical');
    expect(f?.tool).toBe('sca');
    expect(f?.file).toBe('package-lock.json');
    expect(f?.line).toBeUndefined();
    expect(f?.remediation).toContain('4.17.21');
  });

  it('maps HIGH severity correctly', () => {
    const findings = mapTrivyToFindings(FIXTURE_TRIVY_OUTPUT);
    expect(findings.find(f => f.id === 'CVE-2023-5678')?.severity).toBe('high');
  });

  it('maps MEDIUM severity correctly', () => {
    const findings = mapTrivyToFindings(FIXTURE_TRIVY_OUTPUT);
    expect(findings.find(f => f.id === 'CVE-2023-9999')?.severity).toBe('medium');
  });

  it('defaults to low for LOW severity', () => {
    const findings = mapTrivyToFindings(FIXTURE_TRIVY_OUTPUT);
    expect(findings.find(f => f.id === 'CVE-2023-0001')?.severity).toBe('low');
  });

  it('shows "No known fix" remediation when no FixedVersion', () => {
    const findings = mapTrivyToFindings(FIXTURE_TRIVY_OUTPUT);
    const f = findings.find(f => f.id === 'CVE-2023-9999');
    expect(f?.remediation).toBe('No known fix yet');
  });

  it('returns empty array for empty data', () => {
    expect(mapTrivyToFindings({ Results: [] })).toEqual([]);
  });
});
