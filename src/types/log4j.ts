export type CveSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface CveRecord {
  id: string; // e.g. "CVE-2021-44228"
  title: string;
  name: string; // e.g. "Log4Shell"
  cvssScore: number; // e.g. 10.0
  severity: CveSeverity;
  publishDate: string;
  affectedVersionDesc: string;
  // Range criteria:
  minAffectedVersion?: string; // inclusive or empty
  maxAffectedVersion?: string; // inclusive
  isAffectedPredicate: (version: string) => boolean;
  recommendedVersion: string; // e.g. "2.17.1" or "2.24.3"
  runtimeTargetVersions: {
    java8Plus: string;
    java7: string;
    java6: string;
    log4j1xMigration: string;
  };
  description: string;
  impact: string;
  mitigation: string;
  references: string[];
  isCustom?: boolean;
  enabled: boolean;
}

export interface DetectedArtifact {
  id: string;
  name: string; // e.g. "org.apache.logging.log4j:log4j-core"
  fileName?: string;
  sourceType: 'pom.xml' | 'build.gradle' | 'jar_archive' | 'manifest' | 'manual_input' | 'log_output';
  version: string;
  majorVersion: number;
  jndiLookupClassPresent?: boolean; // detected in JAR
  isVulnerable: boolean;
  matchedCves: CveRecord[];
  highestSeverity: CveSeverity | 'SAFE';
  highestCvss: number;
  recommendedVersion: string;
  lineNumber?: number;
  rawSnippet?: string;
  remediationSnippet?: string;
  javaVersionRequirement?: string;
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  targetName: string;
  sourceType: string;
  totalArtifacts: number;
  vulnerableArtifacts: number;
  safeArtifacts: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  artifacts: DetectedArtifact[];
  overallRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
  notes?: string;
  auditorName?: string;
  organizationName?: string;
}

export type ScanTab = 'scanner' | 'jar_analyzer' | 'cve_manager' | 'remediation' | 'audit_report' | 'powershell_exe';
