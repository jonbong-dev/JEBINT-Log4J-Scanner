import { CveRecord, DetectedArtifact, ScanResult, CveSeverity } from '../types/log4j';
import { parseVersion } from './versionComparator';

export interface ScanOptions {
  cveDatabase: CveRecord[];
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
  targetName?: string;
  sourceType?: string;
  auditorName?: string;
  organizationName?: string;
}

export function evaluateVersionAgainstCves(
  versionStr: string,
  cveDatabase: CveRecord[],
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6'
): {
  matchedCves: CveRecord[];
  isVulnerable: boolean;
  highestSeverity: CveSeverity | 'SAFE';
  highestCvss: number;
  recommendedVersion: string;
} {
  const matched = cveDatabase.filter((cve) => {
    if (!cve.enabled) return false;
    try {
      return cve.isAffectedPredicate(versionStr);
    } catch {
      return false;
    }
  });

  const isVulnerable = matched.length > 0;

  let highestCvss = 0;
  let highestSeverity: CveSeverity | 'SAFE' = 'SAFE';

  if (isVulnerable) {
    highestCvss = Math.max(...matched.map((c) => c.cvssScore));
    if (matched.some((c) => c.severity === 'CRITICAL')) highestSeverity = 'CRITICAL';
    else if (matched.some((c) => c.severity === 'HIGH')) highestSeverity = 'HIGH';
    else if (matched.some((c) => c.severity === 'MEDIUM')) highestSeverity = 'MEDIUM';
    else highestSeverity = 'LOW';
  }

  // Determine recommended safe version based on target JDK
  const parsed = parseVersion(versionStr);
  let recommendedVersion = '2.17.1';

  if (parsed.major === 1) {
    recommendedVersion = 'ch.qos.reload4j:reload4j:1.2.25';
  } else if (targetJdk === 'Java 7') {
    recommendedVersion = '2.12.4';
  } else if (targetJdk === 'Java 6') {
    recommendedVersion = '2.3.2';
  } else {
    // Java 8+
    // Use the latest recommended version from the most critical CVE or standard 2.17.1 / 2.24.3
    const customRec = matched.find((c) => c.runtimeTargetVersions?.java8Plus)?.runtimeTargetVersions.java8Plus;
    recommendedVersion = customRec || '2.24.3';
  }

  return {
    matchedCves: matched,
    isVulnerable,
    highestSeverity,
    highestCvss,
    recommendedVersion,
  };
}

export function scanPomXml(content: string, options: ScanOptions): DetectedArtifact[] {
  const artifacts: DetectedArtifact[] = [];
  const lines = content.split('\n');

  // Look for log4j properties first, e.g. <log4j2.version>2.14.1</log4j2.version>
  const propertiesMap: Record<string, string> = {};
  const propRegex = /<([a-zA-Z0-9._-]+log4j[a-zA-Z0-9._-]*)>([^<]+)<\/\1>/gi;
  let propMatch;
  while ((propMatch = propRegex.exec(content)) !== null) {
    propertiesMap[propMatch[1]] = propMatch[2].trim();
  }

  // Match Maven dependency blocks:
  // <dependency> ... <groupId>...</groupId> ... <artifactId>...</artifactId> ... <version>...</version> ... </dependency>
  const dependencyBlockRegex = /<dependency>([\s\S]*?)<\/dependency>/gi;
  let depMatch;

  while ((depMatch = dependencyBlockRegex.exec(content)) !== null) {
    const block = depMatch[1];
    const groupIdMatch = block.match(/<groupId>([^<]+)<\/groupId>/i);
    const artifactIdMatch = block.match(/<artifactId>([^<]+)<\/artifactId>/i);
    const versionMatch = block.match(/<version>([^<]+)<\/version>/i);

    const groupId = groupIdMatch ? groupIdMatch[1].trim() : '';
    const artifactId = artifactIdMatch ? artifactIdMatch[1].trim() : '';
    let version = versionMatch ? versionMatch[1].trim() : '';

    // Check if this is a Log4j dependency
    const isLog4j =
      groupId === 'org.apache.logging.log4j' ||
      groupId === 'log4j' ||
      artifactId.toLowerCase().includes('log4j') ||
      artifactId === 'spring-boot-starter-log4j2';

    if (isLog4j) {
      // Resolve property if version is like ${log4j2.version}
      if (version.startsWith('${') && version.endsWith('}')) {
        const propKey = version.slice(2, -1);
        if (propertiesMap[propKey]) {
          version = propertiesMap[propKey];
        }
      }

      if (!version) {
        // Fallback check in properties map
        const found = Object.values(propertiesMap)[0];
        if (found) version = found;
      }

      if (version) {
        const parsed = parseVersion(version);
        const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);

        // Find line number
        const charIndex = depMatch.index;
        const lineNum = content.substring(0, charIndex).split('\n').length;

        artifacts.push({
          id: `pom-${artifacts.length + 1}`,
          name: `${groupId || 'org.apache.logging.log4j'}:${artifactId}`,
          sourceType: 'pom.xml',
          version,
          majorVersion: parsed.major,
          lineNumber: lineNum,
          rawSnippet: `<dependency>\n  <groupId>${groupId || 'org.apache.logging.log4j'}</groupId>\n  <artifactId>${artifactId}</artifactId>\n  <version>${version}</version>\n</dependency>`,
          ...evalResult,
        });
      }
    }
  }

  // Also check if standalone property was declared even without explicit <dependency> (common in parent POMs)
  if (artifacts.length === 0 && Object.keys(propertiesMap).length > 0) {
    for (const [key, val] of Object.entries(propertiesMap)) {
      const parsed = parseVersion(val);
      const evalResult = evaluateVersionAgainstCves(val, options.cveDatabase, options.targetJdk);
      artifacts.push({
        id: `pom-prop-${artifacts.length + 1}`,
        name: `org.apache.logging.log4j:log4j-core (${key})`,
        sourceType: 'pom.xml',
        version: val,
        majorVersion: parsed.major,
        rawSnippet: `<${key}>${val}</${key}>`,
        ...evalResult,
      });
    }
  }

  return artifacts;
}

export function scanGradle(content: string, options: ScanOptions): DetectedArtifact[] {
  const artifacts: DetectedArtifact[] = [];
  const lines = content.split('\n');

  // Look for gradle dependency lines:
  // implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
  // implementation("org.apache.logging.log4j:log4j-core:2.14.1")
  // compile group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.1'
  const stringDepRegex = /(?:implementation|compile|api|runtimeOnly|testImplementation)\s*[\(]?\s*['"](org\.apache\.logging\.log4j|log4j):([a-zA-Z0-9_-]+):([a-zA-Z0-9._-]+)['"]/gi;
  let match;

  while ((match = stringDepRegex.exec(content)) !== null) {
    const group = match[1];
    const artifact = match[2];
    const version = match[3];

    const parsed = parseVersion(version);
    const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);
    const lineNum = content.substring(0, match.index).split('\n').length;

    artifacts.push({
      id: `gradle-${artifacts.length + 1}`,
      name: `${group}:${artifact}`,
      sourceType: 'build.gradle',
      version,
      majorVersion: parsed.major,
      lineNumber: lineNum,
      rawSnippet: match[0],
      ...evalResult,
    });
  }

  // Map-style: group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.1'
  const mapDepRegex = /group:\s*['"](org\.apache\.logging\.log4j|log4j)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]/gi;
  while ((match = mapDepRegex.exec(content)) !== null) {
    const group = match[1];
    const artifact = match[2];
    const version = match[3];

    const parsed = parseVersion(version);
    const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);
    const lineNum = content.substring(0, match.index).split('\n').length;

    artifacts.push({
      id: `gradle-map-${artifacts.length + 1}`,
      name: `${group}:${artifact}`,
      sourceType: 'build.gradle',
      version,
      majorVersion: parsed.major,
      lineNumber: lineNum,
      rawSnippet: match[0],
      ...evalResult,
    });
  }

  return artifacts;
}

export function scanGenericText(content: string, options: ScanOptions): DetectedArtifact[] {
  const artifacts: DetectedArtifact[] = [];

  // Match Maven dependency:tree or jar filenames or strings:
  // e.g. log4j-core-2.14.1.jar, log4j-1.2.17.jar, org.apache.logging.log4j:log4j-core:2.14.1
  const jarRegex = /\b(log4j(?:-[a-zA-Z0-9]+)?)-([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)\.jar\b/gi;
  let match;
  while ((match = jarRegex.exec(content)) !== null) {
    const name = match[1];
    const version = match[2];
    const parsed = parseVersion(version);
    const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);

    artifacts.push({
      id: `jar-${artifacts.length + 1}`,
      name: `org.apache.logging.log4j:${name}`,
      fileName: match[0],
      sourceType: 'log_output',
      version,
      majorVersion: parsed.major,
      rawSnippet: match[0],
      ...evalResult,
    });
  }

  // Maven tree regex:
  // +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
  const mvnTreeRegex = /(org\.apache\.logging\.log4j|log4j):([a-zA-Z0-9_-]+):(?:jar|war)?:([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)/gi;
  while ((match = mvnTreeRegex.exec(content)) !== null) {
    const group = match[1];
    const artifact = match[2];
    const version = match[3];

    // Avoid duplicates
    if (!artifacts.some((a) => a.name === `${group}:${artifact}` && a.version === version)) {
      const parsed = parseVersion(version);
      const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);
      artifacts.push({
        id: `tree-${artifacts.length + 1}`,
        name: `${group}:${artifact}`,
        sourceType: 'log_output',
        version,
        majorVersion: parsed.major,
        rawSnippet: match[0],
        ...evalResult,
      });
    }
  }

  return artifacts;
}

export function runFullScan(
  content: string,
  options: ScanOptions
): ScanResult {
  let detected: DetectedArtifact[] = [];

  const trimmed = content.trim();

  // 1. Try pom.xml
  if (trimmed.includes('<project') || trimmed.includes('<dependency') || trimmed.includes('<groupId>')) {
    detected = scanPomXml(content, options);
  }

  // 2. Try gradle
  if (detected.length === 0 && (trimmed.includes('dependencies') || trimmed.includes('implementation') || trimmed.includes('repositories'))) {
    detected = scanGradle(content, options);
  }

  // 3. Try generic text / jar list / dependency:tree
  if (detected.length === 0) {
    detected = scanGenericText(content, options);
  }

  // 4. If user simply pasted a version like "2.14.1" or "log4j-core:2.14.1"
  if (detected.length === 0) {
    const directVersionMatch = trimmed.match(/^(?:([a-zA-Z0-9._-]+):)?([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)$/);
    if (directVersionMatch) {
      const artName = directVersionMatch[1] || 'log4j-core';
      const version = directVersionMatch[2];
      const parsed = parseVersion(version);
      const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);
      detected.push({
        id: 'direct-1',
        name: `org.apache.logging.log4j:${artName}`,
        sourceType: 'manual_input',
        version,
        majorVersion: parsed.major,
        rawSnippet: trimmed,
        ...evalResult,
      });
    }
  }

  const totalArtifacts = detected.length;
  const vulnerableArtifacts = detected.filter((a) => a.isVulnerable).length;
  const safeArtifacts = totalArtifacts - vulnerableArtifacts;

  const criticalCount = detected.filter((a) => a.highestSeverity === 'CRITICAL').length;
  const highCount = detected.filter((a) => a.highestSeverity === 'HIGH').length;
  const mediumCount = detected.filter((a) => a.highestSeverity === 'MEDIUM').length;
  const lowCount = detected.filter((a) => a.highestSeverity === 'LOW').length;

  let overallRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' = 'SAFE';
  if (criticalCount > 0) overallRiskLevel = 'CRITICAL';
  else if (highCount > 0) overallRiskLevel = 'HIGH';
  else if (mediumCount > 0) overallRiskLevel = 'MEDIUM';
  else if (lowCount > 0) overallRiskLevel = 'LOW';

  return {
    scanId: `SCAN-${Date.now().toString(36).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    targetName: options.targetName || 'Log4j Manifest / Application Scope',
    sourceType: options.sourceType || 'Dependency Manifest',
    totalArtifacts,
    vulnerableArtifacts,
    safeArtifacts,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    artifacts: detected,
    overallRiskLevel,
    targetJdk: options.targetJdk,
    auditorName: options.auditorName || 'Security Auditor',
    organizationName: options.organizationName || 'Enterprise SecOps',
  };
}
