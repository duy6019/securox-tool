import chalk from 'chalk';
import Table from 'cli-table3';
import type { Finding } from '../types/findings';

export function reportToTerminal(findings: Finding[]): void {
  console.log('\n');

  if (findings.length === 0) {
    console.log(chalk.green('✅ No vulnerabilities found. Great job!'));
    console.log('\n');
    return;
  }

  console.log(chalk.red.bold(`⚠️ Found ${findings.length} vulnerabilities:`));
  
  const table = new Table({
    head: ['Severity', 'Tool', 'File', 'Description', 'ID'].map(h => chalk.bold(h)),
  });

  const severityColors = {
    critical: chalk.bgRed.white.bold,
    high: chalk.red.bold,
    medium: chalk.yellow.bold,
    low: chalk.gray,
  };

  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

  findings.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);

  for (const f of findings) {
    table.push([
      severityColors[f.severity](f.severity.toUpperCase()),
      f.tool.toUpperCase(),
      f.line ? `${f.file}:${f.line}` : f.file,
      f.title.length > 50 ? f.title.substring(0, 47) + '...' : f.title,
      f.id
    ]);
  }

  console.log(table.toString());
  console.log('\n');
}
