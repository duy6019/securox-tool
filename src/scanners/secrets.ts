import { execa } from 'execa';
import { getBinaryPath } from '../core/environment';
import type { Finding } from '../types/findings';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export async function runSecrets(targetDir: string, exclude: string[] = []): Promise<Finding[]> {
  const binaryPath = getBinaryPath('gitleaks');
  const tempOutputFile = path.join(os.tmpdir(), `gitleaks-${Date.now()}.json`);

  try {
    // gitleaks detect --source targetDir --report-format json --report-path <file> --exit-code 0
    // Without --no-git so it also scans git history
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
    return mapGitleaksToFindings(data, exclude);
  } catch (e) {
    console.error('Failed to parse Gitleaks output:', e);
    return [];
  }
}

export function mapGitleaksToFindings(data: any[], exclude: string[] = []): Finding[] {
  const findings: Finding[] = [];

  for (const result of (data || [])) {
    // Skip if file path matches any exclusion pattern
    if (exclude.some(pattern => {
      const p = pattern.replace(/\/\*\*$/, '');
      return result.File.includes(p);
    })) {
      continue;
    }

    findings.push({
      id: result.RuleID || 'SECRET_LEAK',
      tool: 'secrets',
      severity: 'critical', // always critical for secrets
      title: result.Description || 'Potential Secret Leak',
      file: result.File,
      line: result.StartLine,
      remediation: 'Rotate this secret immediately and ideally remove it from git history.',
    });
  }

  return findings;
}
