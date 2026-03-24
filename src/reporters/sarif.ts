import * as fs from 'fs';
import type { Finding } from '../types/findings';

export function reportToSarif(findings: Finding[], outputPath?: string): void {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Securox',
            version: '1.0.0',
            informationUri: 'https://github.com/your-org/securox',
            rules: findings.map(f => ({
              id: f.id,
              shortDescription: { text: f.title },
              help: { text: f.remediation || '' },
              properties: { tags: [f.tool] }
            })).filter((v, i, a) => a.findIndex(t => (t.id === v.id)) === i) // Unique rules
          }
        },
        results: findings.map(f => ({
          ruleId: f.id,
          message: { text: f.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line || 1 }
              }
            }
          ]
        }))
      }
    ]
  };

  const jsonStr = JSON.stringify(sarif, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, jsonStr);
    console.log(`SARIF report saved to ${outputPath}`);
  } else {
    console.log(jsonStr);
  }
}
