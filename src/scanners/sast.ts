import { execa } from 'execa';
import { getBinaryPath } from '../core/environment';
import type { Finding } from '../types/findings';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export async function runSAST(targetDir: string): Promise<Finding[]> {
  const binaryPath = getBinaryPath('opengrep');
  const tempOutputFile = path.join(os.tmpdir(), `opengrep-${Date.now()}.json`);

  // __dirname works in both Bun (native TS) and bundled Node.js (dist/action.js)
  // import.meta.dir is Bun-only and returns undefined when run via Node.js
  const rulesPath = path.resolve(__dirname, '../../rules/default');

  try {
    // --no-git-ignore: scan all files, not just git-tracked ones
    // stderr: 'pipe' keeps Python warnings from corrupting the JSON output file
    await execa(binaryPath, ['scan', '--json', '--config', rulesPath, '--output', tempOutputFile, '--no-git-ignore', targetDir], { stderr: 'pipe' });
  } catch (error: any) {
    // Opengrep exits with non-zero if findings are strictly failed or it hits an error.
    // We can still read the JSON if it managed to generate it.
    if (!fs.existsSync(tempOutputFile)) {
       throw new Error(`Opengrep failed: ${error.message}`);
    }
  }

  if (!fs.existsSync(tempOutputFile)) {
    return [];
  }

  const output = fs.readFileSync(tempOutputFile, 'utf-8');
  fs.unlinkSync(tempOutputFile);
  
  try {
    const data = JSON.parse(output);
    return mapOpengrepToFindings(data);
  } catch (e) {
    console.error('Failed to parse Opengrep output:', e);
    return [];
  }
}

export function mapOpengrepToFindings(data: any): Finding[] {
  const findings: Finding[] = [];
  const results = data.results || [];

  for (const result of results) {
    let severity: Finding['severity'] = 'low';
    if (result.extra?.severity === 'ERROR') severity = 'high';
    if (result.extra?.severity === 'WARNING') severity = 'medium';

    findings.push({
      id: result.check_id,
      tool: 'sast',
      severity,
      title: result.extra?.message || result.check_id,
      file: result.path,
      line: result.start?.line,
      remediation: result.extra?.fix || 'Review the vulnerable code snippet.',
    });
  }

  return findings;
}
