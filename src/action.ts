import * as core from '@actions/core';
import * as cache from '@actions/cache';
import * as path from 'path';
import * as fs from 'fs';
import { loadConfig } from './core/user-loader';
import { downloadAll } from './core/downloader';
import { BIN_DIR } from './core/environment';
import { TOOLS_VERSION } from './core/constants';
import { runSAST } from './scanners/sast';
import { runSCA } from './scanners/sca';
import { runSecrets } from './scanners/secrets';
import { reportToTerminal } from './reporters/terminal';
import { reportToJson } from './reporters/json';
import { reportToSarif } from './reporters/sarif';
import type { Finding } from './types/findings';

async function run(): Promise<void> {
  try {
    const targetPath = core.getInput('targetPath') || '.';
    const failOn = core.getInput('fail-on') || 'high';
    const format = core.getInput('format') || 'terminal';

    const resolvedPath = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), targetPath);
    const config = loadConfig(resolvedPath);

    // Cache Logic
    const cacheKey = `securox-bins-${TOOLS_VERSION.opengrep}-${TOOLS_VERSION.trivy}-${TOOLS_VERSION.gitleaks}-${process.platform}-${process.arch}`;
    const cachePaths = [BIN_DIR];

    let cacheHit = false;
    try {
      const restoredKey = await cache.restoreCache(cachePaths, cacheKey);
      if (restoredKey) {
        core.info(`✅ Restored securox binaries from cache: ${restoredKey}`);
        cacheHit = true;
      }
    } catch (e) {
      core.info(`⚠️ Cache restore failed or unavailable: ${(e as Error).message}`);
    }

    if (!cacheHit || !fs.existsSync(BIN_DIR) || fs.readdirSync(BIN_DIR).length === 0) {
      core.info('⏬ Binaries not found in cache. Downloading fresh copies...');
      await downloadAll();

      try {
        await cache.saveCache(cachePaths, cacheKey);
        core.info(`💾 Saved downloaded binaries to cache: ${cacheKey}`);
      } catch (e) {
        core.info(`⚠️ Cache save failed (non-fatal): ${(e as Error).message}`);
      }
    }

    const allFindings: Finding[] = [];

    if (config.scanners.sast) {
      core.startGroup('SAST Scan (Opengrep)');
      const sast = await runSAST(resolvedPath, config.exclude);
      allFindings.push(...sast);
      core.endGroup();
    }

    if (config.scanners.sca) {
      core.startGroup('SCA Scan (Trivy)');
      const sca = await runSCA(resolvedPath, config.exclude);
      allFindings.push(...sca);
      core.endGroup();
    }

    if (config.scanners.secrets) {
      core.startGroup('Secrets Scan (Gitleaks)');
      const secrets = await runSecrets(resolvedPath, config.exclude);
      allFindings.push(...secrets);
      core.endGroup();
    }

    core.info('✅ Scanning completed!');

    // Reporting
    switch (format) {
      case 'json':
        reportToJson(allFindings);
        break;
      case 'sarif':
        reportToSarif(allFindings);
        break;
      case 'terminal':
      default:
        reportToTerminal(allFindings);
    }

    // Exit Code Logic
    const threshold = failOn || config['severity-threshold'];
    if (threshold.toLowerCase() === 'none') {
      core.info('✅ fail-on is set to "none". Pipeline will not fail despite vulnerabilities.');
    } else {
      const severityOrder: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
      const thresholdLvl = severityOrder[threshold] || 3;
      const fails = allFindings.some(f => (severityOrder[f.severity] || 0) >= thresholdLvl);

      if (fails) {
        core.setFailed(`Securox failed: Found vulnerabilities >= ${threshold.toUpperCase()}`);
      }
    }
  } catch (error: any) {
    core.setFailed(`Action execution failed: ${error.message}`);
  }
}

run();
