import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { ensureBinDir, getBinaryName, getBinaryPath, BIN_DIR } from './environment';
import { TOOLS_VERSION } from './constants';
import decompress from 'decompress';

const OS_MAP: Record<string, string> = {
  darwin: 'macos',
  linux: 'linux',
  win32: 'windows',
};

function getOpengrepUrl(): string {
  const version = TOOLS_VERSION.opengrep;
  const platform = os.platform();
  const arch = os.arch(); // 'arm64' or 'x64'

  if (platform === 'darwin') {
    // e.g. opengrep_osx_arm64 or opengrep_osx_x86
    const archStr = arch === 'arm64' ? 'arm64' : 'x86';
    return `https://github.com/opengrep/opengrep/releases/download/${version}/opengrep_osx_${archStr}`;
  } else if (platform === 'win32') {
    // e.g. opengrep-core_windows_x86.zip
    return `https://github.com/opengrep/opengrep/releases/download/${version}/opengrep-core_windows_x86.zip`;
  } else {
    // Linux: manylinux raw binary
    const archStr = arch === 'arm64' ? 'aarch64' : 'x86';
    return `https://github.com/opengrep/opengrep/releases/download/${version}/opengrep_manylinux_${archStr}`;
  }
}

function getTrivyUrl(): string {
  const version = TOOLS_VERSION.trivy.replace(/^v/, '');
  const osName = os.platform() === 'darwin' ? 'macOS' : os.platform() === 'win32' ? 'Windows' : 'Linux';
  const arch = os.arch() === 'x64' ? '64bit' : 'ARM64';
  const ext = os.platform() === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${osName}-${arch}.${ext}`;
}

function getGitleaksUrl(): string {
  const version = TOOLS_VERSION.gitleaks.replace(/^v/, '');
  const osName = os.platform() === 'darwin' ? 'darwin' : os.platform() === 'win32' ? 'windows' : 'linux';
  const archStr = os.arch() === 'x64' ? 'x64' : 'arm64';
  const ext = os.platform() === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${osName}_${archStr}.${ext}`;
}

async function downloadFile(url: string, dest: string): Promise<void> {
  console.log(`Downloading ${url}...`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download ${url}: ${response.statusText}`);
  }
  if (!response.body) {
    throw new Error(`No response body from ${url}`);
  }
  // Stream to disk to avoid loading large binaries (~80MB) into RAM
  const file = fs.createWriteStream(dest);
  const reader = response.body.getReader();
  await new Promise<void>((resolve, reject) => {
    const pump = () => reader.read().then(({ done, value }) => {
      if (done) { file.end(); resolve(); return; }
      file.write(Buffer.from(value), (err) => { if (err) reject(err); else pump(); });
    }).catch(reject);
    pump();
  });
}

async function setupBinary(tool: 'opengrep' | 'trivy' | 'gitleaks', url: string): Promise<void> {
  const finalPath = getBinaryPath(tool);
  if (fs.existsSync(finalPath)) return;

  const tmpPath = path.join(BIN_DIR, `${tool}-download-tmp`);
  await downloadFile(url, tmpPath);

  if (url.endsWith('.tar.gz') || url.endsWith('.zip')) {
    console.log(`Extracting ${tool}...`);
    await decompress(tmpPath, BIN_DIR, {
      filter: file => file.path.includes(getBinaryName(tool)),
    });
    fs.unlinkSync(tmpPath);
  } else {
    fs.renameSync(tmpPath, finalPath);
  }

  // Chmod +x
  if (os.platform() !== 'win32') {
    fs.chmodSync(finalPath, 0o755);
  }
}

export async function downloadAll(): Promise<void> {
  ensureBinDir();
  try {
    await setupBinary('opengrep', getOpengrepUrl());
    await setupBinary('trivy', getTrivyUrl());
    await setupBinary('gitleaks', getGitleaksUrl());
  } catch (error) {
    console.error('Error downloading binaries:', error);
    process.exit(1);
  }
}
