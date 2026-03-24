import * as fs from 'fs';
import type { Finding } from '../types/findings';

export function reportToJson(findings: Finding[], outputPath?: string): void {
  const jsonStr = JSON.stringify(findings, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, jsonStr);
    console.log(`Results saved to ${outputPath}`);
  } else {
    console.log(jsonStr);
  }
}
