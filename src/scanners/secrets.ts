import { execa } from 'execa';
import { getBinaryPath } from '../core/environment';
import type { Finding } from '../types/findings';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export async function runSecrets(targetDir: string): Promise<Finding[]> {
  const binaryPath = getBinaryPath('gitleaks');
  const tempOutputFile = path.join(os.tmpdir(), `gitleaks-${Date.now()}.json`);

  try {
    // --exit-code 0 prevents gitleaks from failing the process so we can read the JSON output
    await execa(binaryPath, ['detect', '--source', targetDir, '--report-format', 'json', '--report-path', tempOutputFile, '--exit-code', '0']);
  } catch (error: any) {
    if (!fs.existsSync(tempOutputFile)) {
      throw new Error(`Gitleaks failed: ${error.message}`);
    }
  }

  if (!fs.existsSync(tempOutputFile)) {
    return [];
  }

  const output = fs.readFileSync(tempOutputFile, 'utf-8');
  fs.unlinkSync(tempOutputFile);
  
  try {
    const data = JSON.parse(output);
    return mapGitleaksToFindings(data);
  } catch (e) {
    console.error('Failed to parse Gitleaks output:', e);
    return [];
  }
}

export function mapGitleaksToFindings(data: any[]): Finding[] {
  const findings: Finding[] = [];

  for (const result of (data || [])) {
    findings.push({
      id: result.RuleID || 'SECRET_LEAK',
      tool: 'secrets',
      severity: 'critical',
      title: result.Description || 'Potential Secret Leak',
      file: result.File,
      line: result.StartLine,
      remediation: 'Rotate this secret immediately and ideally remove it from git history.',
    });
  }

  return findings;
}
