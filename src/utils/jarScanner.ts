import JSZip from 'jszip';
import { CveRecord, DetectedArtifact } from '../types/log4j';
import { evaluateVersionAgainstCves } from './log4jScanner';
import { parseVersion } from './versionComparator';

export interface JarScanOptions {
  cveDatabase: CveRecord[];
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
}

export async function scanJarFile(file: File, options: JarScanOptions): Promise<DetectedArtifact[]> {
  const artifacts: DetectedArtifact[] = [];

  try {
    const zip = await JSZip.loadAsync(file);

    // 1. Check if JndiLookup.class exists anywhere in the archive
    let jndiLookupClassFound = false;
    zip.forEach((relativePath) => {
      if (relativePath.endsWith('JndiLookup.class')) {
        jndiLookupClassFound = true;
      }
    });

    // 2. Look for Maven pom.properties inside META-INF/maven/
    const pomPropertiesFiles: string[] = [];
    zip.forEach((path) => {
      if (path.includes('META-INF/maven/') && path.endsWith('pom.properties')) {
        pomPropertiesFiles.push(path);
      }
    });

    for (const propPath of pomPropertiesFiles) {
      const fileData = zip.file(propPath);
      if (fileData) {
        const text = await fileData.async('string');
        const groupIdMatch = text.match(/^groupId\s*=\s*(.+)$/m);
        const artifactIdMatch = text.match(/^artifactId\s*=\s*(.+)$/m);
        const versionMatch = text.match(/^version\s*=\s*(.+)$/m);

        const groupId = groupIdMatch ? groupIdMatch[1].trim() : '';
        const artifactId = artifactIdMatch ? artifactIdMatch[1].trim() : '';
        const version = versionMatch ? versionMatch[1].trim() : '';

        if (groupId.includes('log4j') || artifactId.includes('log4j')) {
          const parsed = parseVersion(version);
          const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);

          artifacts.push({
            id: `jar-prop-${artifacts.length + 1}`,
            name: `${groupId}:${artifactId}`,
            fileName: file.name,
            sourceType: 'jar_archive',
            version,
            majorVersion: parsed.major,
            jndiLookupClassPresent: jndiLookupClassFound,
            rawSnippet: `Found in ${propPath}\nversion=${version}\nJndiLookup.class present: ${jndiLookupClassFound}`,
            ...evalResult,
          });
        }
      }
    }

    // 3. Look for META-INF/MANIFEST.MF
    const manifestFile = zip.file('META-INF/MANIFEST.MF');
    if (manifestFile && artifacts.length === 0) {
      const manifestText = await manifestFile.async('string');
      const implTitleMatch = manifestText.match(/^Implementation-Title:\s*(.+)$/m);
      const implVersionMatch = manifestText.match(/^Implementation-Version:\s*(.+)$/m);
      const bundleVersionMatch = manifestText.match(/^Bundle-Version:\s*(.+)$/m);

      const title = implTitleMatch ? implTitleMatch[1].trim() : '';
      const version = (implVersionMatch ? implVersionMatch[1].trim() : '') || (bundleVersionMatch ? bundleVersionMatch[1].trim() : '');

      if (title.toLowerCase().includes('log4j') || file.name.toLowerCase().includes('log4j')) {
        if (version) {
          const parsed = parseVersion(version);
          const evalResult = evaluateVersionAgainstCves(version, options.cveDatabase, options.targetJdk);

          artifacts.push({
            id: `jar-mf-${artifacts.length + 1}`,
            name: title || file.name.replace(/\.jar$/i, ''),
            fileName: file.name,
            sourceType: 'jar_archive',
            version,
            majorVersion: parsed.major,
            jndiLookupClassPresent: jndiLookupClassFound,
            rawSnippet: `Implementation-Title: ${title}\nImplementation-Version: ${version}\nJndiLookup.class: ${jndiLookupClassFound}`,
            ...evalResult,
          });
        }
      }
    }

    // 4. Check nested JARs (Spring Boot / WAR: BOOT-INF/lib/*.jar, WEB-INF/lib/*.jar)
    const nestedJars: string[] = [];
    zip.forEach((path) => {
      if ((path.includes('BOOT-INF/lib/') || path.includes('WEB-INF/lib/')) && path.toLowerCase().endsWith('.jar')) {
        if (path.toLowerCase().includes('log4j')) {
          nestedJars.push(path);
        }
      }
    });

    for (const nestedPath of nestedJars) {
      // Extract filename & version from filename e.g. "BOOT-INF/lib/log4j-core-2.14.1.jar"
      const parts = nestedPath.split('/');
      const jarName = parts[parts.length - 1];
      const match = jarName.match(/(log4j(?:-[a-zA-Z0-9]+)?)-([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)\.jar/i);

      if (match) {
        const artName = match[1];
        const ver = match[2];
        const parsed = parseVersion(ver);
        const evalResult = evaluateVersionAgainstCves(ver, options.cveDatabase, options.targetJdk);

        artifacts.push({
          id: `nested-${artifacts.length + 1}`,
          name: `org.apache.logging.log4j:${artName}`,
          fileName: `${file.name} -> ${nestedPath}`,
          sourceType: 'jar_archive',
          version: ver,
          majorVersion: parsed.major,
          jndiLookupClassPresent: true,
          rawSnippet: `Nested embedded library: ${nestedPath}`,
          ...evalResult,
        });
      }
    }

    // 5. Fallback: Parse from JAR filename if nothing else matched
    if (artifacts.length === 0 && file.name.toLowerCase().includes('log4j')) {
      const match = file.name.match(/(log4j(?:-[a-zA-Z0-9]+)?)-([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9]+)?)\.jar/i);
      if (match) {
        const artName = match[1];
        const ver = match[2];
        const parsed = parseVersion(ver);
        const evalResult = evaluateVersionAgainstCves(ver, options.cveDatabase, options.targetJdk);

        artifacts.push({
          id: `jar-name-${artifacts.length + 1}`,
          name: `org.apache.logging.log4j:${artName}`,
          fileName: file.name,
          sourceType: 'jar_archive',
          version: ver,
          majorVersion: parsed.major,
          jndiLookupClassPresent: jndiLookupClassFound,
          rawSnippet: `Identified by filename: ${file.name}\nJndiLookup class detected: ${jndiLookupClassFound}`,
          ...evalResult,
        });
      }
    }
  } catch (err) {
    console.error('Error scanning JAR archive:', err);
    throw new Error(`Failed to inspect JAR/archive: ${err instanceof Error ? err.message : String(err)}`);
  }

  return artifacts;
}
