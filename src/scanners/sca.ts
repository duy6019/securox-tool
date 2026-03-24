import { execa } from 'execa';
import { getBinaryPath } from '../core/environment';
import type { Finding } from '../types/findings';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export async function runSCA(targetDir: string): Promise<Finding[]> {
  const binaryPath = getBinaryPath('trivy');
  const tempOutputFile = path.join(os.tmpdir(), `trivy-${Date.now()}.json`);

  try {
    // try running: trivy fs targetDir --format json -o output.json
    await execa(binaryPath, ['fs', targetDir, '--format', 'json', '--output', tempOutputFile, '--quiet']);
  } catch (error: any) {
    if (!fs.existsSync(tempOutputFile)) {
      throw new Error(`Trivy failed: ${error.message}`);
    }
  }

  if (!fs.existsSync(tempOutputFile)) {
    return [];
  }

  const output = fs.readFileSync(tempOutputFile, 'utf-8');
  fs.unlinkSync(tempOutputFile);
  
  try {
    const data = JSON.parse(output);
    return mapTrivyToFindings(data);
  } catch (e) {
    console.error('Failed to parse Trivy output:', e);
    return [];
  }
}

export function mapTrivyToFindings(data: any): Finding[] {
  const findings: Finding[] = [];
  const results = data.Results || [];

  for (const result of results) {
    const target = result.Target;

    // Handle SCA: package vulnerabilities
    for (const vuln of (result.Vulnerabilities || [])) {
      let severity: Finding['severity'] = 'low';
      if (vuln.Severity === 'CRITICAL') severity = 'critical';
      if (vuln.Severity === 'HIGH') severity = 'high';
      if (vuln.Severity === 'MEDIUM') severity = 'medium';

      findings.push({
        id: vuln.VulnerabilityID || 'UNKNOWN_CVE',
        tool: 'sca',
        severity,
        title: vuln.Title || `${vuln.PkgName} vulnerability`,
        file: target,
        line: undefined,
        remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to version ${vuln.FixedVersion}` : 'No known fix yet',
      });
    }

    // Handle Secrets: Trivy can also detect hardcoded secrets
    for (const secret of (result.Secrets || [])) {
      let severity: Finding['severity'] = 'high';
      if (secret.Severity === 'CRITICAL') severity = 'critical';
      if (secret.Severity === 'MEDIUM') severity = 'medium';

      findings.push({
        id: secret.RuleID || 'SECRET',
        tool: 'sca', // still categorized under sca since it's from trivy
        severity,
        title: secret.Title || 'Hardcoded Secret',
        file: target,
        line: secret.StartLine,
        remediation: 'Rotate this secret immediately and remove from codebase.',
      });
    }
  }

  return findings;
}
