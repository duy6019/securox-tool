import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

export const SECUROX_HOME = path.join(os.homedir(), '.securox');
export const BIN_DIR = path.join(SECUROX_HOME, 'bin');

export function ensureBinDir() {
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }
}

export function getBinaryName(tool: 'opengrep' | 'trivy' | 'gitleaks' | 'bearer'): string {
  const isWindows = os.platform() === 'win32';
  return isWindows ? `${tool}.exe` : tool;
}

export function getBinaryPath(tool: 'opengrep' | 'trivy' | 'gitleaks' | 'bearer'): string {
  return path.join(BIN_DIR, getBinaryName(tool));
}
