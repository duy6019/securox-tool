import { Command } from 'commander';
import ora from 'ora';
import * as path from 'path';
import { downloadAll } from '../core/downloader';
import { loadConfig } from '../config';
import { runSAST } from '../scanners/sast';
import { runSCA } from '../scanners/sca';
import { runSecrets } from '../scanners/secrets';
import { reportToTerminal } from '../reporters/terminal';
import { reportToJson } from '../reporters/json';
import { reportToSarif } from '../reporters/sarif';
import type { Finding } from '../types/findings';

export const scanCommand = new Command('scan')
  .description('Run security scans (SAST, SCA, Secrets)')
  .argument('[targetPath]', 'Path to scan', '.')
  .option('-f, --format <type>', 'Output format (terminal/json/sarif)', 'terminal')
  .option('-o, --output <path>', 'Output file path')
  .option('--fail-on <severity>', 'Fail exit code on this severity (low/medium/high/critical)')
  .action(async (targetPath, options) => {
    const spinner = ora('Initializing Securox scanners...').start();
    const resolvedPath = path.resolve(targetPath);
    const config = loadConfig(resolvedPath);

    try {
      spinner.text = 'Checking binaries... (may download on first run)';
      await downloadAll(); // This fetches binaries if they don't exist

      const allFindings: Finding[] = [];

      if (config.scanners.sast) {
        spinner.text = 'Running SAST scan (Opengrep)...';
        const sast = await runSAST(resolvedPath);
        allFindings.push(...sast);
      }

      if (config.scanners.sca) {
        spinner.text = 'Running SCA scan (Trivy)...';
        const sca = await runSCA(resolvedPath);
        allFindings.push(...sca);
      }

      if (config.scanners.secrets) {
        spinner.text = 'Running Secrets scan (Gitleaks)...';
        const secrets = await runSecrets(resolvedPath);
        allFindings.push(...secrets);
      }

      spinner.succeed('Scanning completed!');

      // Reporting
      switch (options.format) {
        case 'json':
          reportToJson(allFindings, options.output);
          break;
        case 'sarif':
          reportToSarif(allFindings, options.output);
          break;
        case 'terminal':
        default:
          reportToTerminal(allFindings);
      }

      // Exit Code logic
      const threshold = options.failOn || config['severity-threshold'];
      const severityOrder: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
      if (!severityOrder[threshold]) {
        console.warn(`Unknown severity threshold: ${threshold}. Falling back to 'high'.`);
      }
      
      const thresholdLvl = severityOrder[threshold] || 3;
      const fails = allFindings.some(f => (severityOrder[f.severity] || 0) >= thresholdLvl);

      if (fails) {
        console.log(`Failed threshold: found vulnerabilities sized >= ${threshold.toUpperCase()}`);
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail(`Scan failed: ${error.message}`);
      process.exit(1);
    }
  });
