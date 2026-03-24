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

function mapTrivyToFindings(data: any): Finding[] {
  const findings: Finding[] = [];
  const results = data.Results || [];

  for (const result of results) {
    const target = result.Target;
    const vulnerabilities = result.Vulnerabilities || [];

    for (const vuln of vulnerabilities) {
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
        line: 0,
        remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to version ${vuln.FixedVersion}` : 'No known fix yet',
      });
    }
  }

  return findings;
}
