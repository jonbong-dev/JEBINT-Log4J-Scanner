import { CveRecord } from '../types/log4j';
import { compareVersions } from '../utils/versionComparator';

export const DEFAULT_LOG4J_CVES: CveRecord[] = [
  {
    id: 'CVE-2021-44228',
    name: 'Log4Shell',
    title: 'Apache Log4j2 JNDI Message Lookup Remote Code Execution',
    cvssScore: 10.0,
    severity: 'CRITICAL',
    publishDate: '2021-12-10',
    affectedVersionDesc: 'Log4j 2.0-beta9 <= version <= 2.14.1',
    minAffectedVersion: '2.0-beta9',
    maxAffectedVersion: '2.14.1',
    isAffectedPredicate: (v: string) => {
      // 2.0-beta9 through 2.14.1
      return compareVersions(v, '2.0-beta9') >= 0 && compareVersions(v, '2.14.1') <= 0;
    },
    recommendedVersion: '2.17.1',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'Apache Log4j2 versions 2.0-beta9 to 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.',
    impact:
      'Full unauthenticated Remote Code Execution (RCE) with the privileges of the running Java application process.',
    mitigation:
      'Upgrade to Log4j 2.17.1 (or 2.24.3+). Immediate temporary mitigation for 2.10-2.14.1: set system property log4j2.formatMsgNoLookups=true or remove JndiLookup.class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
      'https://logging.apache.org/log4j/2.x/security.html',
    ],
    enabled: true,
  },
  {
    id: 'CVE-2021-45046',
    name: 'Log4Shell Incomplete Fix / ThreadContext Pattern RCE',
    title: 'Incomplete Fix for CVE-2021-44228 in Log4j 2.15.0',
    cvssScore: 9.0,
    severity: 'CRITICAL',
    publishDate: '2021-12-14',
    affectedVersionDesc: 'Log4j 2.0-beta9 <= version <= 2.15.0 (excluding 2.12.2)',
    minAffectedVersion: '2.0-beta9',
    maxAffectedVersion: '2.15.0',
    isAffectedPredicate: (v: string) => {
      if (v === '2.12.2') return false;
      return compareVersions(v, '2.0-beta9') >= 0 && compareVersions(v, '2.15.0') <= 0;
    },
    recommendedVersion: '2.17.1',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with either a Context Lookup or a Thread Context Map pattern, attackers with control over Thread Context values can craft malicious input data using a JNDI Lookup pattern resulting in information leak and remote code execution.',
    impact:
      'Denial of Service (DoS) and potential Remote Code Execution in non-standard PatternLayout configurations.',
    mitigation:
      'Upgrade to Log4j 2.17.1 or higher. Alternatively remove org/apache/logging/log4j/core/lookup/JndiLookup.class from the classpath.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-45046',
      'https://logging.apache.org/log4j/2.x/security.html',
    ],
    enabled: true,
  },
  {
    id: 'CVE-2021-45105',
    name: 'Context Lookup Infinite Recursion DoS',
    title: 'Apache Log4j2 Does Not Protect Against Uncontrolled Recursion in Lookup Evaluation',
    cvssScore: 5.9,
    severity: 'MEDIUM',
    publishDate: '2021-12-18',
    affectedVersionDesc: 'Log4j 2.0-alpha1 <= version <= 2.16.0 (excluding 2.12.3)',
    minAffectedVersion: '2.0-alpha1',
    maxAffectedVersion: '2.16.0',
    isAffectedPredicate: (v: string) => {
      if (v === '2.12.3') return false;
      return compareVersions(v, '2.0-alpha1') >= 0 && compareVersions(v, '2.16.0') <= 0;
    },
    recommendedVersion: '2.17.1',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup, attackers with control over Thread Context Map (MDC) input data can craft malicious input that contains a recursive lookup, leading to a StackOverflowError and service crash.',
    impact:
      'Application crash (Denial of Service) via StackOverflowError terminating JVM execution.',
    mitigation:
      'Upgrade to Log4j 2.17.1 (or 2.12.3 for Java 7). Replace Context Lookups like ${ctx:loginId} with Thread Context Map patterns (%X, %mdc, or %MDC) in the Layout pattern.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-45105',
      'https://logging.apache.org/log4j/2.x/security.html',
    ],
    enabled: true,
  },
  {
    id: 'CVE-2021-44832',
    name: 'JDBCAppender JNDI DataSource RCE',
    title: 'Apache Log4j2 Vulnerable to Remote Code Execution via JDBCAppender',
    cvssScore: 6.6,
    severity: 'MEDIUM',
    publishDate: '2021-12-28',
    affectedVersionDesc: 'Log4j 2.0-beta7 <= version <= 2.17.0 (excluding 2.3.2 and 2.12.4)',
    minAffectedVersion: '2.0-beta7',
    maxAffectedVersion: '2.17.0',
    isAffectedPredicate: (v: string) => {
      if (v === '2.12.4' || v === '2.3.2') return false;
      return compareVersions(v, '2.0-beta7') >= 0 && compareVersions(v, '2.17.0') <= 0;
    },
    recommendedVersion: '2.17.1',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'Apache Log4j2 versions 2.0-beta7 through 2.17.0 are vulnerable to Remote Code Execution where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBCAppender with a data source referencing a JNDI URI which can execute arbitrary code.',
    impact:
      'Remote Code Execution if an adversary has write privileges to logging configuration (e.g. log4j2.xml).',
    mitigation:
      'Upgrade to Log4j 2.17.1 (Java 8+), 2.12.4 (Java 7), or 2.3.2 (Java 6). Limit configuration file modification permissions.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-44832',
      'https://logging.apache.org/log4j/2.x/security.html',
    ],
    enabled: true,
  },
  {
    id: 'CVE-2020-9488',
    name: 'SMTPAppender Hostname Verification Bypass',
    title: 'Improper Certificate Validation in Log4j2 SMTPAppender',
    cvssScore: 3.7,
    severity: 'LOW',
    publishDate: '2020-04-27',
    affectedVersionDesc: 'Log4j 2.0-beta9 <= version <= 2.13.1',
    minAffectedVersion: '2.0-beta9',
    maxAffectedVersion: '2.13.1',
    isAffectedPredicate: (v: string) => {
      return compareVersions(v, '2.0-beta9') >= 0 && compareVersions(v, '2.13.1') <= 0;
    },
    recommendedVersion: '2.13.2',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'Improper validation of certificate with host mismatch in Apache Log4j SMTPAppender allows an attacker on the same network to perform Man-in-the-Middle (MitM) attacks against secure email transports.',
    impact:
      'Information disclosure via intercepted email log dispatches over untrusted networks.',
    mitigation: 'Upgrade to Log4j 2.13.2 or 2.17.1+.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-9488'],
    enabled: true,
  },
  {
    id: 'CVE-2019-17571',
    name: 'Log4j 1.x SocketServer Deserialization RCE',
    title: 'Apache Log4j 1.2 SocketServer Untrusted Object Deserialization',
    cvssScore: 9.8,
    severity: 'CRITICAL',
    publishDate: '2019-12-20',
    affectedVersionDesc: 'Log4j 1.2.x all versions (EOL)',
    minAffectedVersion: '1.0.0',
    maxAffectedVersion: '1.2.17',
    isAffectedPredicate: (v: string) => {
      return v.startsWith('1.') || compareVersions(v, '1.9.9') <= 0;
    },
    recommendedVersion: 'ch.qos.reload4j:1.2.25',
    runtimeTargetVersions: {
      java8Plus: '2.24.3 (or reload4j 1.2.25)',
      java7: 'reload4j 1.2.25',
      java6: 'reload4j 1.2.25',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget.',
    impact:
      'Remote Code Execution when Log4j 1.x SocketServer is listening for incoming logging network traffic.',
    mitigation:
      'Log4j 1.x has reached End of Life (EOL) since August 2015. Replace with "ch.qos.reload4j:reload4j" (a drop-in replacement with security fixes) or migrate to Log4j 2.24.3+.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2019-17571',
      'https://reload4j.qos.ch/',
    ],
    enabled: true,
  },
  {
    id: 'CVE-2022-23302',
    name: 'Log4j 1.x JMSSink Deserialization RCE',
    title: 'Apache Log4j 1.x JMSSink Untrusted Deserialization',
    cvssScore: 8.8,
    severity: 'HIGH',
    publishDate: '2022-01-18',
    affectedVersionDesc: 'Log4j 1.0.0 <= version <= 1.2.17',
    minAffectedVersion: '1.0.0',
    maxAffectedVersion: '1.2.17',
    isAffectedPredicate: (v: string) => {
      return v.startsWith('1.');
    },
    recommendedVersion: 'ch.qos.reload4j:1.2.25',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: 'reload4j 1.2.25',
      java6: 'reload4j 1.2.25',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when configured to listen to JMS queues or topics.',
    impact: 'Remote code execution via JMS message injection.',
    mitigation: 'Migrate to reload4j 1.2.25 or Log4j 2.24.3.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-23302'],
    enabled: true,
  },
  {
    id: 'CVE-2022-23305',
    name: 'Log4j 1.x JDBCAppender SQL Injection',
    title: 'Apache Log4j 1.x JDBCAppender SQL Injection Vulnerability',
    cvssScore: 9.8,
    severity: 'CRITICAL',
    publishDate: '2022-01-18',
    affectedVersionDesc: 'Log4j 1.2.x when JDBCAppender is used',
    minAffectedVersion: '1.0.0',
    maxAffectedVersion: '1.2.17',
    isAffectedPredicate: (v: string) => {
      return v.startsWith('1.');
    },
    recommendedVersion: 'ch.qos.reload4j:1.2.25',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: 'reload4j 1.2.25',
      java6: 'reload4j 1.2.25',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description:
      'By crafting logging strings containing SQL metacharacters, an adversary can manipulate SQL queries executed by the JDBCAppender in Log4j 1.x.',
    impact: 'Database compromise and arbitrary SQL execution.',
    mitigation: 'Migrate to reload4j or Log4j 2.x.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-23305'],
    enabled: true,
  },
];

export const STORAGE_KEY_CVES = 'log4j_shield_cve_database_v1';

export function loadCveDatabase(): CveRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_CVES);
    if (!raw) return DEFAULT_LOG4J_CVES;
    const stored = JSON.parse(raw) as Partial<CveRecord>[];

    // Merge with defaults to preserve predicate functions
    return stored.map((item) => {
      const defaultMatch = DEFAULT_LOG4J_CVES.find((d) => d.id === item.id);
      return {
        ...defaultMatch,
        ...item,
        isAffectedPredicate: (v: string) => {
          if (!item.enabled) return false;
          const min = item.minAffectedVersion || '';
          const max = item.maxAffectedVersion || '';
          if (min && compareVersions(v, min) < 0) return false;
          if (max && compareVersions(v, max) > 0) return false;
          if (item.id === 'CVE-2021-45046' && v === '2.12.2') return false;
          if (item.id === 'CVE-2021-45105' && v === '2.12.3') return false;
          if (item.id === 'CVE-2021-44832' && (v === '2.12.4' || v === '2.3.2')) return false;
          if (defaultMatch) {
            return defaultMatch.isAffectedPredicate(v);
          }
          return true;
        },
      } as CveRecord;
    });
  } catch {
    return DEFAULT_LOG4J_CVES;
  }
}

export function saveCveDatabase(cves: CveRecord[]): void {
  try {
    // Exclude function predicates when serializing
    const serializable = cves.map(({ isAffectedPredicate, ...rest }) => rest);
    localStorage.setItem(STORAGE_KEY_CVES, JSON.stringify(serializable));
  } catch (err) {
    console.error('Failed to save CVE database:', err);
  }
}
