import { describe, it, expect } from 'bun:test';
import { mapOpengrepToFindings } from '../../src/scanners/sast';

const FIXTURE_OPENGREP_OUTPUT = {
  results: [
    {
      check_id: 'javascript.lang.security.audit.sqli',
      path: 'src/db.js',
      start: { line: 42 },
      extra: {
        severity: 'ERROR',
        message: 'Potential SQL injection via string concatenation',
        fix: 'Use parameterized queries instead.',
      },
    },
    {
      check_id: 'javascript.lang.security.audit.xss',
      path: 'src/render.js',
      start: { line: 10 },
      extra: {
        severity: 'WARNING',
        message: 'Potential XSS via innerHTML',
      },
    },
    {
      check_id: 'javascript.lang.security.audit.info-leak',
      path: 'src/logger.js',
      start: { line: 5 },
      extra: {
        severity: 'INFO', // unknown → defaults to 'low'
        message: 'Verbose logging may leak sensitive data',
      },
    },
  ],
};

describe('mapOpengrepToFindings', () => {
  it('maps ERROR severity to high', () => {
    const findings = mapOpengrepToFindings(FIXTURE_OPENGREP_OUTPUT);
    const sqli = findings.find(f => f.id === 'javascript.lang.security.audit.sqli');
    expect(sqli?.severity).toBe('high');
    expect(sqli?.tool).toBe('sast');
    expect(sqli?.file).toBe('src/db.js');
    expect(sqli?.line).toBe(42);
    expect(sqli?.remediation).toBe('Use parameterized queries instead.');
  });

  it('maps WARNING severity to medium', () => {
    const findings = mapOpengrepToFindings(FIXTURE_OPENGREP_OUTPUT);
    const xss = findings.find(f => f.id === 'javascript.lang.security.audit.xss');
    expect(xss?.severity).toBe('medium');
  });

  it('defaults unknown severity to low', () => {
    const findings = mapOpengrepToFindings(FIXTURE_OPENGREP_OUTPUT);
    const info = findings.find(f => f.id === 'javascript.lang.security.audit.info-leak');
    expect(info?.severity).toBe('low');
  });

  it('returns empty array for empty results', () => {
    expect(mapOpengrepToFindings({ results: [] })).toEqual([]);
    expect(mapOpengrepToFindings({})).toEqual([]);
  });
});
