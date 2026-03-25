import { execa } from 'execa';
import { getBinaryPath } from '../core/environment';
import type { Finding } from '../types/findings';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export async function runPerformance(targetDir: string): Promise<Finding[]> {
  const binaryPath = getBinaryPath('bearer');
  const tempOutputFile = path.join(os.tmpdir(), `bearer-${Date.now()}.json`);

  try {
    // --exit-code 0 so we can always read JSON output regardless of findings
    await execa(binaryPath, [
      'scan', targetDir,
      '--format', 'json',
      '--output', tempOutputFile,
      '--quiet',
      '--scanner', 'sast',
    ]);
  } catch (error: any) {
    if (!fs.existsSync(tempOutputFile)) {
      throw new Error(`Bearer failed: ${error.message}`);
    }
  }

  if (!fs.existsSync(tempOutputFile)) {
    return [];
  }

  const output = fs.readFileSync(tempOutputFile, 'utf-8');
  fs.unlinkSync(tempOutputFile);

  try {
    const data = JSON.parse(output);
    return mapBearerToFindings(data);
  } catch (e) {
    console.error('Failed to parse Bearer output:', e);
    return [];
  }
}

export function mapBearerToFindings(data: any): Finding[] {
  const findings: Finding[] = [];

  // Bearer groups findings by severity level: critical, high, medium, low, warning
  const severityMap: Record<string, Finding['severity']> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    warning: 'low',
  };

  for (const [level, severity] of Object.entries(severityMap)) {
    for (const item of ((data as any)[level] || [])) {
      findings.push({
        id: item.rule_id || item.id || 'PERF',
        tool: 'performance',
        severity,
        title: item.title || item.description || 'Performance issue',
        file: item.filename || item.file || 'unknown',
        line: item.line_number ?? item.start_line,
        remediation: item.documentation_url
          ? `See: ${item.documentation_url}`
          : 'Review the flagged code for performance anti-patterns.',
      });
    }
  }

  return findings;
}
