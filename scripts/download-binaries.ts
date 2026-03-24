#!/usr/bin/env bun
/**
 * One-time script to download all required binaries for integration tests.
 * Run: bun run scripts/download-binaries.ts
 */
import { downloadAll } from '../src/core/downloader';

console.log('📦 Downloading Securox binaries...\n');
await downloadAll();
console.log('\n✅ All binaries ready. You can now run integration tests.');
