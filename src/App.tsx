/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import { Navbar } from './components/Navbar';
import { ScanOverview } from './components/ScanOverview';
import { ScannerInput } from './components/ScannerInput';
import { VulnerabilityCard } from './components/VulnerabilityCard';
import { JarFileUploader } from './components/JarFileUploader';
import { CveDatabaseManager } from './components/CveDatabaseManager';
import { RemediationDrawer } from './components/RemediationDrawer';
import { PrintableReport } from './components/PrintableReport';
import { PowerShellExport } from './components/PowerShellExport';

import { ScanTab, ScanResult, CveRecord, DetectedArtifact } from './types/log4j';
import { loadCveDatabase, saveCveDatabase, DEFAULT_LOG4J_CVES } from './data/cveDatabase';
import { runFullScan } from './utils/log4jScanner';
import { SAMPLE_MANIFESTS } from './data/sampleManifests';

import {
  FileCode2,
  Archive,
  Database,
  Wrench,
  Printer,
  Sparkles,
  Info,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<ScanTab>('scanner');
  const [targetJdk, setTargetJdk] = useState<'Java 8+' | 'Java 7' | 'Java 6'>('Java 8+');
  const [cveDatabase, setCveDatabase] = useState<CveRecord[]>(() => loadCveDatabase());
  
  // Default to the first sample (Maven with Log4j 2.14.1) so users immediately see a live, interactive scan
  const [inputContent, setInputContent] = useState<string>(SAMPLE_MANIFESTS[0].content);
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  // JAR scanned artifacts if any
  const [jarArtifacts, setJarArtifacts] = useState<DetectedArtifact[]>([]);
  const [lastJarFileName, setLastJarFileName] = useState<string>('');

  // Save CVE database modifications
  const handleUpdateCve = (updated: CveRecord) => {
    const next = cveDatabase.map((c) => (c.id === updated.id ? updated : c));
    setCveDatabase(next);
    saveCveDatabase(next);
    showNotice(`Updated ${updated.id} target version to ${updated.recommendedVersion}`);
  };

  const handleAddCve = (newCve: CveRecord) => {
    const next = [newCve, ...cveDatabase];
    setCveDatabase(next);
    saveCveDatabase(next);
    showNotice(`Added custom advisory rule ${newCve.id}`);
  };

  const handleResetCves = () => {
    setCveDatabase(DEFAULT_LOG4J_CVES);
    saveCveDatabase(DEFAULT_LOG4J_CVES);
    showNotice('Reset CVE rules and targets to official Apache Security Advisory baseline');
  };

  const handleToggleCve = (id: string) => {
    const next = cveDatabase.map((c) => (c.id === id ? { ...c, enabled: !c.enabled } : c));
    setCveDatabase(next);
    saveCveDatabase(next);
  };

  const showNotice = (msg: string) => {
    setBannerNotice(msg);
    setTimeout(() => setBannerNotice(null), 3500);
  };

  // Perform full scan on the current manifest content
  const manifestScanResult: ScanResult = useMemo(() => {
    if (!inputContent.trim()) {
      return {
        scanId: 'SCAN-EMPTY',
        timestamp: new Date().toISOString(),
        targetName: 'No input provided',
        sourceType: 'Empty',
        totalArtifacts: 0,
        vulnerableArtifacts: 0,
        safeArtifacts: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        artifacts: [],
        overallRiskLevel: 'SAFE',
        targetJdk,
      };
    }
    return runFullScan(inputContent, {
      cveDatabase,
      targetJdk,
      targetName: 'Enterprise Payment Service / Web Application',
      sourceType: inputContent.includes('<project') ? 'pom.xml' : inputContent.includes('dependencies') ? 'build.gradle' : 'Dependency Manifest',
    });
  }, [inputContent, cveDatabase, targetJdk]);

  // Combined or active scan result
  const activeScanResult: ScanResult = useMemo(() => {
    if (currentTab === 'jar_analyzer' && jarArtifacts.length > 0) {
      const vuln = jarArtifacts.filter((a) => a.isVulnerable).length;
      return {
        scanId: `JAR-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        targetName: lastJarFileName || 'Inspected Archive',
        sourceType: 'JAR / Bytecode Archive',
        totalArtifacts: jarArtifacts.length,
        vulnerableArtifacts: vuln,
        safeArtifacts: jarArtifacts.length - vuln,
        criticalCount: jarArtifacts.filter((a) => a.highestSeverity === 'CRITICAL').length,
        highCount: jarArtifacts.filter((a) => a.highestSeverity === 'HIGH').length,
        mediumCount: jarArtifacts.filter((a) => a.highestSeverity === 'MEDIUM').length,
        lowCount: jarArtifacts.filter((a) => a.highestSeverity === 'LOW').length,
        artifacts: jarArtifacts,
        overallRiskLevel: vuln > 0 ? 'CRITICAL' : 'SAFE',
        targetJdk,
      };
    }
    return manifestScanResult;
  }, [currentTab, jarArtifacts, lastJarFileName, manifestScanResult, targetJdk]);

  // Quick single version check handler
  const handleQuickVersionCheck = (ver: string) => {
    setInputContent(`log4j-core:${ver}`);
    showNotice(`Evaluated version ${ver} against Log4j CVE database`);
  };

  // JAR scan complete handler
  const handleJarScanComplete = (artifacts: DetectedArtifact[], fileName: string) => {
    setJarArtifacts(artifacts);
    setLastJarFileName(fileName);
    showNotice(`Extracted ${artifacts.length} Log4j component(s) from ${fileName}`);
  };

  // Auto-apply patch to inputContent
  const handleApplyPatchedContent = (patched: string) => {
    setInputContent(patched);
    showNotice('Successfully applied recommended patched versions to manifest!');
  };

  const handleTriggerPrint = () => {
    setCurrentTab('audit_report');
    setTimeout(() => {
      window.print();
    }, 250);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-rose-500 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        targetJdk={targetJdk}
        onJdkChange={setTargetJdk}
        vulnerableCount={activeScanResult.vulnerableArtifacts}
        onTriggerPrint={handleTriggerPrint}
      />

      {/* Floating Notice / Toast */}
      {bannerNotice && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-medium text-emerald-400 shadow-2xl animate-in fade-in slide-in-from-bottom-2 duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{bannerNotice}</span>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* TAB 1: MANIFEST SCANNER */}
        {currentTab === 'scanner' && (
          <div className="space-y-6">
            {/* Risk Overview Banner & Metric Cards */}
            <ScanOverview
              scanResult={manifestScanResult}
              onOpenRemediation={() => setCurrentTab('remediation')}
              onOpenReport={() => setCurrentTab('audit_report')}
            />

            {/* Input Box with presets, upload, and quick checker */}
            <ScannerInput
              inputContent={inputContent}
              onInputChange={setInputContent}
              onRunScan={() => showNotice('Manifest scanned and evaluated against CVE database')}
              onQuickVersionCheck={handleQuickVersionCheck}
            />

            {/* Detected Artifacts & Findings */}
            {manifestScanResult.artifacts.length > 0 ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <FileCode2 className="w-4 h-4 text-rose-400" />
                    Detected Log4j Artifacts ({manifestScanResult.artifacts.length})
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    Showing vulnerability status and upgrade targets
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {manifestScanResult.artifacts.map((art) => (
                    <VulnerabilityCard
                      key={art.id}
                      artifact={art}
                      onOpenFixForArtifact={() => setCurrentTab('remediation')}
                    />
                  ))}
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border border-slate-800/80 bg-slate-900/30 p-8 text-center space-y-2">
                <Info className="w-8 h-8 text-slate-500 mx-auto" />
                <p className="text-sm font-semibold text-slate-300">
                  No Log4j dependencies found in current input
                </p>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  Paste your project's <code className="text-slate-400">pom.xml</code>, <code className="text-slate-400">build.gradle</code>, or click one of the test presets above to simulate an audit.
                </p>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: JAR ARCHIVE DEEP INSPECTOR */}
        {currentTab === 'jar_analyzer' && (
          <div className="space-y-6">
            <JarFileUploader
              cveDatabase={cveDatabase}
              targetJdk={targetJdk}
              onJarScanComplete={handleJarScanComplete}
            />

            {jarArtifacts.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                    <Archive className="w-4 h-4 text-amber-400" />
                    Archive Findings for {lastJarFileName} ({jarArtifacts.length})
                  </h3>
                  <button
                    onClick={() => setCurrentTab('audit_report')}
                    className="text-xs font-mono text-rose-400 hover:text-rose-300"
                  >
                    Generate Report for this JAR →
                  </button>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {jarArtifacts.map((art) => (
                    <VulnerabilityCard
                      key={art.id}
                      artifact={art}
                      onOpenFixForArtifact={() => setCurrentTab('remediation')}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: CVE DATABASE & TARGET VERSION MANAGER */}
        {currentTab === 'cve_manager' && (
          <CveDatabaseManager
            cveDatabase={cveDatabase}
            onUpdateCve={handleUpdateCve}
            onAddCve={handleAddCve}
            onResetCves={handleResetCves}
            onToggleCve={handleToggleCve}
          />
        )}

        {/* TAB 4: AUTOMATED REMEDIATION & AUTO-FIXER */}
        {currentTab === 'remediation' && (
          <RemediationDrawer
            originalContent={inputContent}
            artifacts={activeScanResult.artifacts}
            targetJdk={targetJdk}
            onApplyPatchedContent={handleApplyPatchedContent}
          />
        )}

        {/* TAB 5: PRINTABLE EXECUTIVE AUDIT REPORT */}
        {currentTab === 'audit_report' && (
          <PrintableReport
            scanResult={activeScanResult}
          />
        )}

        {/* TAB 6: POWERSHELL GUI & STANDALONE EXE COMPILER */}
        {currentTab === 'powershell_exe' && (
          <PowerShellExport />
        )}
      </main>

      {/* Footer (hidden in print) */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500 font-mono print:hidden">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Log4j Shield • Enterprise SCA & Audit Platform</span>
          <span>Standards: NIST SP 800-53 (SI-2) • OWASP A06:2021 • CVE-2021-44228</span>
        </div>
      </footer>
    </div>
  );
}
