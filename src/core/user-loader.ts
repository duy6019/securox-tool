import * as fs from 'fs';
import * as yaml from 'js-yaml';
import * as path from 'path';

export interface SecuroxConfig {
  scanners: {
    sast: boolean;
    sca: boolean;
    secrets: boolean;
    performance: boolean;
  };
  exclude: string[];
  'severity-threshold': string;
}

export function loadConfig(dir: string): SecuroxConfig {
  const defaults: SecuroxConfig = {
    scanners: { sast: true, sca: true, secrets: true, performance: true },
    exclude: ['node_modules/', 'dist/', '**/*.test.ts'],
    'severity-threshold': 'high',
  };

  const configPath = path.join(dir, '.securox.yml');
  if (fs.existsSync(configPath)) {
    try {
      const parsed = yaml.load(fs.readFileSync(configPath, 'utf-8')) as Partial<SecuroxConfig>;
      return {
        ...defaults,
        ...parsed,
        scanners: { ...defaults.scanners, ...(parsed.scanners || {}) }
      };
    } catch (e) {
      console.warn(`Failed to parse .securox.yml, using defaults: ${(e as Error).message}`);
    }
  }
  return defaults;
}
