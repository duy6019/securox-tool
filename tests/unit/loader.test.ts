import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadConfig } from '../../src/core/user-loader';

describe('loadConfig', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securox-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('returns defaults when no .securox.yml exists', () => {
    const config = loadConfig(tmpDir);
    expect(config.scanners.sast).toBe(true);
    expect(config.scanners.sca).toBe(true);
    expect(config.scanners.secrets).toBe(true);
    expect(config['severity-threshold']).toBe('high');
    expect(config.exclude).toContain('node_modules/');
  });

  it('merges user config with defaults', () => {
    const yml = `
scanners:
  sast: false
  sca: true
severity-threshold: critical
`;
    fs.writeFileSync(path.join(tmpDir, '.securox.yml'), yml);
    const config = loadConfig(tmpDir);
    expect(config.scanners.sast).toBe(false);
    expect(config.scanners.sca).toBe(true);
    expect(config.scanners.secrets).toBe(true); // default preserved
    expect(config['severity-threshold']).toBe('critical');
  });

  it('falls back to defaults on invalid YAML', () => {
    fs.writeFileSync(path.join(tmpDir, '.securox.yml'), ':: invalid :: yaml ::');
    const config = loadConfig(tmpDir);
    expect(config['severity-threshold']).toBe('high');
  });
});
