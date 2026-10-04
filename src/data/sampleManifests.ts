export interface SampleManifest {
  id: string;
  name: string;
  badge: string;
  badgeColor: string;
  description: string;
  format: 'pom.xml' | 'build.gradle' | 'dependency_tree';
  content: string;
}

export const SAMPLE_MANIFESTS: SampleManifest[] = [
  {
    id: 'maven-log4shell',
    name: 'Maven POM - Critical Log4Shell (v2.14.1)',
    badge: 'CVSS 10.0',
    badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
    description: 'Classic vulnerable Maven pom.xml using Apache Log4j 2.14.1 vulnerable to JNDI injection RCE.',
    format: 'pom.xml',
    content: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.enterprise.banking</groupId>
    <artifactId>payment-gateway-service</artifactId>
    <version>1.4.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <log4j2.version>2.14.1</log4j2.version>
    </properties>

    <dependencies>
        <!-- CRITICAL VULNERABILITY: Log4j 2.14.1 vulnerable to Log4Shell (CVE-2021-44228) -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-slf4j-impl</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>`,
  },
  {
    id: 'gradle-2150',
    name: 'Gradle - Incomplete Fix (v2.15.0)',
    badge: 'CVSS 9.0',
    badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    description: 'Gradle build with Log4j 2.15.0 containing incomplete patch (CVE-2021-45046).',
    format: 'build.gradle',
    content: `plugins {
    id 'java'
    id 'org.springframework.boot' version '2.5.4'
    id 'io.spring.dependency-management' version '1.0.11.RELEASE'
}

group = 'com.fintech.api'
version = '2.1.0'
sourceCompatibility = '11'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    
    // Incomplete patch for Log4Shell - still vulnerable to CVE-2021-45046
    implementation 'org.apache.logging.log4j:log4j-core:2.15.0'
    implementation 'org.apache.logging.log4j:log4j-api:2.15.0'
    
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
}`,
  },
  {
    id: 'legacy-log4j1',
    name: 'Legacy Enterprise - Log4j 1.2.17 (EOL)',
    badge: 'CVSS 9.8 EOL',
    badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
    description: 'End-of-life Log4j 1.x with SocketServer & JMS deserialization RCE (CVE-2019-17571).',
    format: 'pom.xml',
    content: `<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.telecom.billing</groupId>
    <artifactId>legacy-rating-engine</artifactId>
    <version>3.0.0</version>

    <dependencies>
        <!-- High risk legacy EOL Log4j 1.x library -->
        <dependency>
            <groupId>log4j</groupId>
            <artifactId>log4j</artifactId>
            <version>1.2.17</version>
        </dependency>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-log4j12</artifactId>
            <version>1.7.30</version>
        </dependency>
    </dependencies>
</project>`,
  },
  {
    id: 'patched-secure',
    name: 'Production Compliant - Log4j 2.17.1',
    badge: 'PASS / SAFE',
    badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    description: 'Compliant hardened build with all known Log4j CVEs fully remediated.',
    format: 'pom.xml',
    content: `<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.defense.secure</groupId>
    <artifactId>hardened-cloud-core</artifactId>
    <version>5.2.0</version>

    <properties>
        <log4j2.version>2.17.1</log4j2.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.17.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.17.1</version>
        </dependency>
    </dependencies>
</project>`,
  },
];
