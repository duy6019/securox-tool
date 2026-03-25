export interface Finding {
  id: string;
  tool: 'sast' | 'sca' | 'secrets';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  file: string;
  line?: number;
  remediation?: string;
}
