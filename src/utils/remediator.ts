import { DetectedArtifact } from '../types/log4j';

export interface RemediationPlan {
  artifactId: string;
  artifactName: string;
  currentVersion: string;
  recommendedVersion: string;
  isLog4j1x: boolean;
  pomSnippet: string;
  gradleSnippet: string;
  jvmFlagMitigation: string;
  classRemovalCommand: string;
  explanation: string;
}

export function generateRemediationPlan(artifact: DetectedArtifact, targetJdk: string): RemediationPlan {
  const is1x = artifact.majorVersion === 1 || artifact.name.includes(':log4j') && !artifact.name.includes('log4j-');
  const targetVer = artifact.recommendedVersion;

  let pomSnippet = '';
  let gradleSnippet = '';
  let explanation = '';

  if (is1x) {
    pomSnippet = `<!-- RECOMMENDED: Replace end-of-life Log4j 1.x with drop-in reload4j -->
<dependency>
  <groupId>ch.qos.reload4j</groupId>
  <artifactId>reload4j</artifactId>
  <version>1.2.25</version>
</dependency>`;

    gradleSnippet = `// Replace end-of-life Log4j 1.x with reload4j
implementation 'ch.qos.reload4j:reload4j:1.2.25'`;

    explanation =
      'Log4j 1.x is officially End-of-Life and contains multiple critical deserialization & SQL injection vulnerabilities (CVE-2019-17571, CVE-2022-23302). It cannot be patched in-place. Replace with QOS.ch reload4j 1.2.25 (100% binary drop-in replacement) or migrate to Apache Log4j 2.x.';
  } else {
    pomSnippet = `<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>${targetVer}</version>
</dependency>
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-api</artifactId>
  <version>${targetVer}</version>
</dependency>`;

    gradleSnippet = `implementation 'org.apache.logging.log4j:log4j-core:${targetVer}'
implementation 'org.apache.logging.log4j:log4j-api:${targetVer}'`;

    explanation = `Upgrades to Apache Log4j ${targetVer} which fully patches Log4Shell (CVE-2021-44228), ThreadContext pattern RCE (CVE-2021-45046), Context Lookup DoS (CVE-2021-45105), and JDBCAppender JNDI RCE (CVE-2021-44832) under ${targetJdk}.`;
  }

  const jvmFlagMitigation =
    '-Dlog4j2.formatMsgNoLookups=true\n# Or environment variable:\nexport LOG4J_FORMAT_MSG_NO_LOOKUPS=true';

  const classRemovalCommand =
    'zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class';

  return {
    artifactId: artifact.id,
    artifactName: artifact.name,
    currentVersion: artifact.version,
    recommendedVersion: targetVer,
    isLog4j1x: is1x,
    pomSnippet,
    gradleSnippet,
    jvmFlagMitigation,
    classRemovalCommand,
    explanation,
  };
}

/**
 * Automatically patches an existing pom.xml or build.gradle string by substituting
 * vulnerable versions with the recommended secure target version.
 */
export function autoPatchContent(
  originalContent: string,
  artifacts: DetectedArtifact[]
): { patchedContent: string; replacedCount: number } {
  let patched = originalContent;
  let replacedCount = 0;

  for (const artifact of artifacts) {
    if (!artifact.isVulnerable) continue;

    const oldVer = artifact.version;
    const newVer = artifact.recommendedVersion;

    if (oldVer && newVer && oldVer !== newVer) {
      if (artifact.majorVersion === 1 && newVer.includes('reload4j')) {
        // Replace log4j:log4j with reload4j
        const pom1xRegex = /<groupId>\s*log4j\s*<\/groupId>\s*<artifactId>\s*log4j\s*<\/artifactId>\s*<version>[^<]+<\/version>/g;
        if (pom1xRegex.test(patched)) {
          patched = patched.replace(
            pom1xRegex,
            `<groupId>ch.qos.reload4j</groupId>\n  <artifactId>reload4j</artifactId>\n  <version>1.2.25</version>`
          );
          replacedCount++;
        }

        const gradle1xRegex = /['"]log4j:log4j:[^'"]+['"]/g;
        if (gradle1xRegex.test(patched)) {
          patched = patched.replace(gradle1xRegex, `'ch.qos.reload4j:reload4j:1.2.25'`);
          replacedCount++;
        }
      } else {
        // Standard Log4j 2.x replacement
        // 1. Maven version tag within log4j dependency
        const mavenVerRegex = new RegExp(`(<version>)\\s*${escapeRegex(oldVer)}\\s*(<\\/version>)`, 'g');
        if (mavenVerRegex.test(patched)) {
          patched = patched.replace(mavenVerRegex, `$1${newVer}$2`);
          replacedCount++;
        }

        // 2. Maven property tag like <log4j2.version>2.14.1</log4j2.version>
        const mavenPropRegex = new RegExp(`(<[a-zA-Z0-9._-]*log4j[a-zA-Z0-9._-]*>)\\s*${escapeRegex(oldVer)}\\s*(<\\/[a-zA-Z0-9._-]*log4j[a-zA-Z0-9._-]*>)`, 'gi');
        if (mavenPropRegex.test(patched)) {
          patched = patched.replace(mavenPropRegex, `$1${newVer}$2`);
          replacedCount++;
        }

        // 3. Gradle string e.g. org.apache.logging.log4j:log4j-core:2.14.1
        const gradleRegex = new RegExp(`(org\\.apache\\.logging\\.log4j:[a-zA-Z0-9_-]+:)${escapeRegex(oldVer)}`, 'g');
        if (gradleRegex.test(patched)) {
          patched = patched.replace(gradleRegex, `$1${newVer}`);
          replacedCount++;
        }
      }
    }
  }

  return { patchedContent: patched, replacedCount };
}

function escapeRegex(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
