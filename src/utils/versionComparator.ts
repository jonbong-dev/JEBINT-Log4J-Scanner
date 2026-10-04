/**
 * Version parser and comparator specifically tailored for Apache Log4j releases:
 * Handles standard numeric versions (2.17.1, 1.2.17)
 * as well as milestones/pre-releases (2.0-beta9, 2.0-rc1, 2.0-alpha1)
 */

interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prereleaseTag: string; // 'alpha', 'beta', 'rc', ''
  prereleaseNum: number;
  raw: string;
}

export function parseVersion(v: string): ParsedVersion {
  const clean = v.trim().replace(/^[vV]/, '');
  const raw = clean;

  // Split on hyphen or dot or milestone indicators
  // e.g. "2.0-beta9" -> parts: ["2", "0"], prerelease: "beta9"
  // "2.14.1" -> parts: ["2", "14", "1"]
  const match = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.](alpha|beta|rc)(\d*)|\.([a-zA-Z0-9]+))?$/i);

  if (!match) {
    // Fallback: extract any digits
    const numbers = clean.match(/\d+/g)?.map(Number) || [0];
    return {
      major: numbers[0] || 0,
      minor: numbers[1] || 0,
      patch: numbers[2] || 0,
      prereleaseTag: '',
      prereleaseNum: 0,
      raw,
    };
  }

  const major = parseInt(match[1] || '0', 10);
  const minor = parseInt(match[2] || '0', 10);
  const patch = parseInt(match[3] || '0', 10);
  const tag = (match[4] || '').toLowerCase();
  const tagNum = match[5] ? parseInt(match[5], 10) : 0;

  return {
    major,
    minor,
    patch,
    prereleaseTag: tag,
    prereleaseNum: tagNum,
    raw,
  };
}

/**
 * Returns:
 *  -1 if v1 < v2
 *   0 if v1 == v2
 *   1 if v1 > v2
 */
export function compareVersions(v1Str: string, v2Str: string): number {
  const v1 = parseVersion(v1Str);
  const v2 = parseVersion(v2Str);

  if (v1.major !== v2.major) return v1.major > v2.major ? 1 : -1;
  if (v1.minor !== v2.minor) return v1.minor > v2.minor ? 1 : -1;
  if (v1.patch !== v2.patch) return v1.patch > v2.patch ? 1 : -1;

  // Prerelease comparison: non-prerelease is GREATER than prerelease of same major.minor.patch
  // e.g. 2.0 > 2.0-beta9 > 2.0-alpha1
  const tagOrder: Record<string, number> = {
    '': 4,
    rc: 3,
    beta: 2,
    alpha: 1,
  };

  const order1 = tagOrder[v1.prereleaseTag] ?? 0;
  const order2 = tagOrder[v2.prereleaseTag] ?? 0;

  if (order1 !== order2) {
    return order1 > order2 ? 1 : -1;
  }

  if (v1.prereleaseNum !== v2.prereleaseNum) {
    return v1.prereleaseNum > v2.prereleaseNum ? 1 : -1;
  }

  return 0;
}

export function isVersionGte(v1: string, v2: string): boolean {
  return compareVersions(v1, v2) >= 0;
}

export function isVersionLte(v1: string, v2: string): boolean {
  return compareVersions(v1, v2) <= 0;
}

export function isVersionBetween(version: string, min: string, max: string): boolean {
  return isVersionGte(version, min) && isVersionLte(version, max);
}
