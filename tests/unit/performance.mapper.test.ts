import { describe, it, expect } from 'bun:test';
import { mapBearerToFindings } from '../../src/scanners/performance';

const FIXTURE_BEARER_OUTPUT = {
  critical: [
    {
      rule_id: 'javascript_lang_sql_injection',
      title: 'SQL Injection via unsanitized input',
      filename: 'src/db.js',
      line_number: 42,
      documentation_url: 'https://docs.bearer.com/rules/javascript_lang_sql_injection',
    },
  ],
  high: [
    {
      rule_id: 'javascript_lang_http_insecure',
      title: 'HTTP request inside loop',
      filename: 'src/api.js',
      line_number: 10,
    },
  ],
  medium: [],
  low: [
    {
      id: 'PERF_001',
      description: 'Inefficient array operation',
      filename: 'src/utils.js',
      line_number: 5,
    },
  ],
  warning: [
    {
      rule_id: 'js_warning',
      title: 'Minor performance warning',
      filename: 'src/misc.js',
    },
  ],
};

describe('mapBearerToFindings', () => {
  it('maps critical findings correctly', () => {
    const findings = mapBearerToFindings(FIXTURE_BEARER_OUTPUT);
    const critical = findings.find(f => f.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical?.id).toBe('javascript_lang_sql_injection');
    expect(critical?.tool).toBe('performance');
    expect(critical?.file).toBe('src/db.js');
    expect(critical?.line).toBe(42);
    expect(critical?.remediation).toContain('docs.bearer.com');
  });

  it('maps high findings correctly', () => {
    const findings = mapBearerToFindings(FIXTURE_BEARER_OUTPUT);
    const high = findings.find(f => f.severity === 'high');
    expect(high?.severity).toBe('high');
    expect(high?.title).toBe('HTTP request inside loop');
    expect(high?.remediation).toContain('performance anti-patterns');
  });

  it('maps low findings correctly', () => {
    const findings = mapBearerToFindings(FIXTURE_BEARER_OUTPUT);
    const low = findings.find(f => f.id === 'PERF_001');
    expect(low?.severity).toBe('low');
    expect(low?.title).toBe('Inefficient array operation');
  });

  it('maps warning findings to low severity', () => {
    const findings = mapBearerToFindings(FIXTURE_BEARER_OUTPUT);
    const warning = findings.find(f => f.id === 'js_warning');
    expect(warning?.severity).toBe('low');
  });

  it('tool is always "performance"', () => {
    const findings = mapBearerToFindings(FIXTURE_BEARER_OUTPUT);
    expect(findings.every(f => f.tool === 'performance')).toBe(true);
  });

  it('returns empty array for empty output', () => {
    expect(mapBearerToFindings({})).toEqual([]);
    expect(mapBearerToFindings({ critical: [], high: [], medium: [], low: [], warning: [] })).toEqual([]);
  });
});
