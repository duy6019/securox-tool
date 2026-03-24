export interface Finding {
  id: string;                                    // CVE-ID hoặc rule ID
  tool: 'sast' | 'sca' | 'secrets';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  file: string;
  line?: number;
  remediation?: string;
}
