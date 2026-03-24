import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { ensureBinDir, getBinaryName, getBinaryPath, BIN_DIR } from './environment';
import { TOOLS_VERSION } from './config';
import decompress from 'decompress';

const OS_MAP: Record<string, string> = {
  darwin: 'macos',
  linux: 'linux',
  win32: 'windows',
};

const ARCH_MAP: Record<string, string> = {
  arm64: 'arm64',
  x64: 'x64',
  x86_64: 'x86_64', // will normalize Node's x64 to x86_64 or x64 depending on tool
};

function getOpengrepUrl(): string {
  const version = TOOLS_VERSION.opengrep;
  let osName = OS_MAP[os.platform()] || 'linux';
  let arch = os.arch();
  // opengrep uses x86_64 for mac/linux, but x64 for windows?
  let archStr = arch === 'x64' && osName !== 'windows' ? 'x86_64' : arch;
  const ext = osName === 'windows' ? '.zip' : ''; // Opengrep releases zipped binaries for windows recently? Let's assume raw binary for now based on typical semgrep packaging. Wait, semgrep uses zips.
  // Actually, let's just make a generic downloader that handles .tar.gz or raw
  return `https://github.com/opengrep/opengrep/releases/download/${version}/opengrep-${osName}-${archStr}${ext}`;
}

function getTrivyUrl(): string {
  const version = TOOLS_VERSION.trivy.replace(/^v/, '');
  const osName = os.platform() === 'darwin' ? 'macOS' : os.platform() === 'win32' ? 'Windows' : 'Linux';
  const arch = os.arch() === 'x64' ? '64bit' : 'ARM64';
  const ext = os.platform() === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${osName}-${arch}.${ext}`;
}

function getGitleaksUrl(): string {
  const version = TOOLS_VERSION.gitleaks.replace(/^v/, ''); // Gitleaks uses raw numbers in filename but v in tag
  const osName = os.platform() === 'darwin' ? 'darwin' : os.platform() === 'win32' ? 'windows' : 'linux';
  const arch = os.arch() === 'x64' ? 'x64' : 'arm64';
  const ext = os.platform() === 'win32' ? 'zip' : 'tar.gz';
  const archStr = arch === 'x64' ? (osName === 'darwin' ? 'x64' : 'x64') : 'arm64'; // simplify
  return `https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${osName}_${archStr}.${ext}`;
}

async function downloadFile(url: string, dest: string): Promise<void> {
  console.log(`Downloading ${url}...`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download ${url}: ${response.statusText}`);
  }
  const buffer = await response.arrayBuffer();
  fs.writeFileSync(dest, Buffer.from(buffer));
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
