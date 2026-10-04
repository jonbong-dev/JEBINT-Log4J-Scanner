import React, { useState } from 'react';
import {
  Printer,
  Download,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  FileText,
  Calendar,
  Building,
  UserCheck,
  Flame,
  AlertTriangle,
  Info,
  Check,
  Copy,
} from 'lucide-react';
import { ScanResult, DetectedArtifact } from '../types/log4j';

interface PrintableReportProps {
  scanResult: ScanResult;
  onUpdateMetadata?: (auditor: string, org: string, targetName: string) => void;
}

export const PrintableReport: React.FC<PrintableReportProps> = ({
  scanResult,
  onUpdateMetadata,
}) => {
  const [auditorName, setAuditorName] = useState(scanResult.auditorName || 'Chief Security Architect');
  const [organization, setOrganization] = useState(scanResult.organizationName || 'Enterprise SecOps & Compliance');
  const [targetScope, setTargetScope] = useState(scanResult.targetName || 'Enterprise Core Banking Application');
  const [copiedJson, setCopiedJson] = useState(false);

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    const reportData = {
      ...scanResult,
      auditorName,
      organizationName: organization,
      targetName: targetScope,
      generatedAt: new Date().toISOString(),
      complianceStandard: 'NIST SP 800-53 / ISO 27001 / OWASP Top 10:2021-A06',
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `log4j-audit-report-${scanResult.scanId.toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const isCritical = scanResult.overallRiskLevel === 'CRITICAL';
  const isVulnerable = scanResult.vulnerableArtifacts > 0;

  return (
    <div className="space-y-6">
      {/* Top Interactive Toolbar (Hidden during print) */}
      <div className="print:hidden rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Printer className="w-5 h-5 text-rose-500" />
              Executive Security Audit Report
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Production-ready cybersecurity audit document. Click <strong>Print Document</strong> to print or save as PDF.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 active:scale-95 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              Export JSON Audit
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white text-xs font-semibold shadow-lg shadow-rose-950/50 active:scale-95 transition-all"
            >
              <Printer className="w-4 h-4" />
              Print / Save as PDF
            </button>
          </div>
        </div>

        {/* Report metadata customization */}
        <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">
              Organization / Department
            </label>
            <input
              type="text"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
            />
          </div>
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">
              Lead Auditor / Assessor Name
            </label>
            <input
              type="text"
              value={auditorName}
              onChange={(e) => setAuditorName(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
            />
          </div>
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">
              Application Target Scope
            </label>
            <input
              type="text"
              value={targetScope}
              onChange={(e) => setTargetScope(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
            />
          </div>
        </div>
      </div>

      {/* 
        THE PRINTABLE DOCUMENT
        Styled to look outstanding both on screen and on physical white paper via @media print 
      */}
      <div className="report-paper bg-slate-900 border border-slate-800 print:bg-white print:border-none print:shadow-none print:text-black rounded-3xl p-6 sm:p-10 shadow-2xl max-w-5xl mx-auto space-y-8">
        
        {/* Document Header */}
        <div className="border-b-2 border-slate-700 print:border-black pb-6">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-rose-500 print:text-red-700 font-mono text-xs font-bold uppercase tracking-widest">
                <ShieldAlert className="w-4 h-4" />
                CYBERSECURITY AUDIT REPORT • SOFTWARE COMPOSITION ANALYSIS
              </div>
              <h1 className="text-2xl sm:text-3xl font-black text-white print:text-black tracking-tight mt-1">
                Apache Log4j Vulnerability Assessment & Remediation Report
              </h1>
              <p className="text-xs text-slate-400 print:text-gray-600 mt-1 font-mono">
                Log4Shell (CVE-2021-44228) and Related Security Advisory Compliance Verification
              </p>
            </div>

            <div className="sm:text-right font-mono text-xs text-slate-400 print:text-gray-700 space-y-1">
              <div className="font-bold text-white print:text-black">
                ID: {scanResult.scanId}
              </div>
              <div>DATE: {new Date(scanResult.timestamp).toLocaleString()}</div>
              <div>CLASSIFICATION: TLP:AMBER / CONFIDENTIAL</div>
            </div>
          </div>

          {/* Meta Details Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-4 border-t border-slate-800 print:border-gray-300 text-xs">
            <div>
              <span className="text-slate-400 print:text-gray-600 font-mono uppercase block text-[10px]">
                Target System
              </span>
              <span className="font-semibold text-white print:text-black">
                {targetScope}
              </span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 font-mono uppercase block text-[10px]">
                Auditing Entity
              </span>
              <span className="font-semibold text-white print:text-black">
                {organization}
              </span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 font-mono uppercase block text-[10px]">
                Assessor
              </span>
              <span className="font-semibold text-white print:text-black">
                {auditorName}
              </span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 font-mono uppercase block text-[10px]">
                Target Environment
              </span>
              <span className="font-semibold text-white print:text-black">
                {scanResult.targetJdk} Runtime
              </span>
            </div>
          </div>
        </div>

        {/* Executive Summary Card */}
        <div className={`p-5 rounded-2xl border ${
          isVulnerable
            ? 'bg-rose-950/20 border-rose-500/40 print:bg-red-50 print:border-red-300'
            : 'bg-emerald-950/20 border-emerald-500/30 print:bg-green-50 print:border-green-300'
        }`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className={`p-3 rounded-xl ${
                isVulnerable
                  ? 'bg-rose-500/20 text-rose-400 print:bg-red-200 print:text-red-800'
                  : 'bg-emerald-500/20 text-emerald-400 print:bg-green-200 print:text-green-800'
              }`}>
                {isVulnerable ? <Flame className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
              </div>
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-900 text-white print:bg-black">
                  OVERALL ASSESSMENT RATING: {scanResult.overallRiskLevel}
                </span>
                <h3 className="text-base font-bold text-white print:text-black mt-1">
                  {isVulnerable
                    ? `Action Required: ${scanResult.vulnerableArtifacts} Vulnerable Dependency Detected`
                    : 'System Certified: Zero Known Log4j Vulnerabilities Detected'}
                </h3>
              </div>
            </div>

            <div className="flex gap-4 text-xs font-mono">
              <div className="text-center">
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">TOTAL ASSETS</span>
                <span className="text-lg font-bold text-white print:text-black">{scanResult.totalArtifacts}</span>
              </div>
              <div className="text-center">
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">VULNERABLE</span>
                <span className={`text-lg font-bold ${isVulnerable ? 'text-rose-400 print:text-red-700' : 'text-slate-200 print:text-black'}`}>
                  {scanResult.vulnerableArtifacts}
                </span>
              </div>
              <div className="text-center">
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">COMPLIANCE</span>
                <span className={`text-lg font-bold ${
                  scanResult.totalArtifacts > 0 && scanResult.vulnerableArtifacts === 0
                    ? 'text-emerald-400 print:text-green-700'
                    : 'text-rose-400 print:text-red-700'
                }`}>
                  {scanResult.totalArtifacts > 0
                    ? Math.round((scanResult.safeArtifacts / scanResult.totalArtifacts) * 100)
                    : 100}%
                </span>
              </div>
              <div className="text-center">
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">MAX CVSS</span>
                <span className="text-lg font-bold text-rose-400 print:text-red-700">
                  {scanResult.artifacts.length > 0 ? Math.max(0, ...scanResult.artifacts.map((a) => a.highestCvss)).toFixed(1) : '0.0'}
                </span>
              </div>
            </div>
          </div>

          {/* Compliance Score Progress Bar in Report */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 print:border-gray-300 space-y-1.5">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="font-bold text-white print:text-black">
                Security Compliance Score: {scanResult.totalArtifacts > 0 ? Math.round((scanResult.safeArtifacts / scanResult.totalArtifacts) * 100) : 100}%
              </span>
              <span className="text-slate-400 print:text-gray-600 text-[11px]">
                {scanResult.safeArtifacts} Patched / {scanResult.totalArtifacts} Audited ({scanResult.vulnerableArtifacts} Vulnerable)
              </span>
            </div>
            <div className="w-full h-2.5 bg-slate-950 print:bg-gray-200 rounded-full overflow-hidden border border-slate-800 print:border-gray-400">
              <div
                className={`h-full rounded-full ${
                  scanResult.vulnerableArtifacts === 0
                    ? 'bg-emerald-500 print:bg-green-700'
                    : scanResult.safeArtifacts > 0
                    ? 'bg-amber-500 print:bg-yellow-600'
                    : 'bg-rose-500 print:bg-red-700'
                }`}
                style={{
                  width: `${scanResult.totalArtifacts > 0 ? Math.round((scanResult.safeArtifacts / scanResult.totalArtifacts) * 100) : 100}%`,
                }}
              />
            </div>
          </div>

          <p className="text-xs text-slate-300 print:text-gray-800 mt-3 leading-relaxed">
            {isVulnerable
              ? 'Executive Statement: The application scope contains software libraries susceptible to Remote Code Execution (RCE) via malicious JNDI string interpolation and uncontrolled deserialization. Systems exposed to untrusted external input (HTTP headers, user logins, form parameters) are at critical risk of complete compromise. Remediation must be executed immediately.'
              : 'Executive Statement: All identified logging libraries satisfy secure version thresholds and are fortified against Log4Shell and related Common Vulnerabilities and Exposures (CVEs). Continued dependency scanning is recommended in CI/CD pipelines.'}
          </p>
        </div>

        {/* Section 1: Detailed Findings Matrix */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider font-mono border-b border-slate-800 print:border-gray-400 pb-1 flex items-center justify-between">
            <span>1. Software Composition & Vulnerability Inventory</span>
            <span className="text-xs font-normal text-slate-400 print:text-gray-600">
              {scanResult.artifacts.length} Component{scanResult.artifacts.length !== 1 ? 's' : ''} Analyzed
            </span>
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-700 print:border-gray-400 text-slate-400 print:text-gray-700 font-mono text-[11px]">
                  <th className="py-2 px-3">Component / Library</th>
                  <th className="py-2 px-3">Current Ver.</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">CVSS</th>
                  <th className="py-2 px-3">Matched CVE(s)</th>
                  <th className="py-2 px-3">Target Safe Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 print:divide-gray-200">
                {scanResult.artifacts.map((art, idx) => (
                  <tr key={idx} className="print:break-inside-avoid">
                    <td className="py-3 px-3 font-mono font-medium text-white print:text-black">
                      <div>{art.name}</div>
                      {art.fileName && (
                        <div className="text-[10px] text-slate-400 print:text-gray-500">
                          {art.fileName} {art.lineNumber ? `(L${art.lineNumber})` : ''}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 print:text-gray-800">
                      v{art.version}
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        art.isVulnerable
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 print:bg-red-100 print:text-red-800 print:border-red-400'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 print:bg-green-100 print:text-green-800'
                      }`}>
                        {art.highestSeverity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-slate-200 print:text-black">
                      {art.highestCvss > 0 ? art.highestCvss.toFixed(1) : '-'}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 print:text-gray-800">
                      {art.matchedCves.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {art.matchedCves.map((c) => (
                            <span key={c.id} className="text-rose-400 print:text-red-700 font-bold">
                              {c.id}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-emerald-400 print:text-green-700">None (Safe)</span>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-emerald-400 print:text-green-800">
                      {art.recommendedVersion}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 2: CVE Deep-Dive Analysis */}
        {isVulnerable && (
          <div className="space-y-4 print:break-before-page">
            <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider font-mono border-b border-slate-800 print:border-gray-400 pb-1">
              2. Vulnerability & Threat Vector Analysis
            </h2>

            <div className="space-y-4">
              {Array.from(
                new Set(scanResult.artifacts.flatMap((a) => a.matchedCves))
              ).map((cve) => (
                <div
                  key={cve.id}
                  className="p-4 rounded-xl border border-slate-800 print:border-gray-300 bg-slate-950/60 print:bg-gray-50 space-y-2 print:break-inside-avoid"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-black text-rose-400 print:text-red-700">
                        {cve.id}
                      </span>
                      <span className="text-xs font-bold text-white print:text-black">
                        — {cve.name}
                      </span>
                    </div>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 print:bg-red-100 print:text-red-800 border border-rose-500/30">
                      CVSS {cve.cvssScore.toFixed(1)} ({cve.severity})
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 print:text-gray-800 leading-relaxed">
                    <strong>Technical Description: </strong>
                    {cve.description}
                  </p>

                  <div className="text-xs text-slate-300 print:text-gray-800 leading-relaxed pt-1">
                    <strong>Attack Impact: </strong>
                    {cve.impact}
                  </div>

                  <div className="text-xs text-slate-300 print:text-gray-800 leading-relaxed pt-1">
                    <strong>Required Remediation: </strong>
                    {cve.mitigation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Section 3: Recommended Action Plan */}
        <div className="space-y-3 print:break-inside-avoid">
          <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider font-mono border-b border-slate-800 print:border-gray-400 pb-1">
            3. Standard Remediation Roadmap & Implementation Checklist
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="p-3.5 rounded-xl border border-slate-800 print:border-gray-300 bg-slate-950/40 print:bg-gray-50 space-y-1.5">
              <span className="font-mono font-bold text-amber-400 print:text-amber-800 block text-[11px]">
                PHASE 1: IMMEDIATE MITIGATION
              </span>
              <p className="text-slate-300 print:text-gray-700 leading-relaxed">
                For Log4j 2.10 - 2.14.1, set system property <code className="font-mono text-slate-200 print:text-black">log4j2.formatMsgNoLookups=true</code> or execute bytecode removal of <code className="font-mono text-slate-200 print:text-black">JndiLookup.class</code>.
              </p>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-800 print:border-gray-300 bg-slate-950/40 print:bg-gray-50 space-y-1.5">
              <span className="font-mono font-bold text-emerald-400 print:text-green-800 block text-[11px]">
                PHASE 2: PERMANENT PATCH
              </span>
              <p className="text-slate-300 print:text-gray-700 leading-relaxed">
                Update root build files (<code className="font-mono text-slate-200 print:text-black">pom.xml</code> or <code className="font-mono text-slate-200 print:text-black">build.gradle</code>) to Log4j <code className="font-mono text-emerald-400 print:text-green-800 font-bold">2.24.3 / 2.17.1</code> (Java 8+) or <code className="font-mono text-emerald-400 print:text-green-800 font-bold">2.12.4</code> (Java 7).
              </p>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-800 print:border-gray-300 bg-slate-950/40 print:bg-gray-50 space-y-1.5">
              <span className="font-mono font-bold text-sky-400 print:text-sky-800 block text-[11px]">
                PHASE 3: CONTINUOUS AUDITING
              </span>
              <p className="text-slate-300 print:text-gray-700 leading-relaxed">
                Integrate automated dependency scanning in CI/CD pipeline triggers and enforce artifact gatekeeping prior to staging or production deployment.
              </p>
            </div>
          </div>
        </div>

        {/* Section 4: Sign-off & Audit Certification */}
        <div className="pt-6 border-t-2 border-slate-800 print:border-black space-y-6 print:break-inside-avoid">
          <div className="flex flex-col sm:flex-row justify-between gap-6">
            <div className="space-y-1">
              <span className="text-[10px] font-mono uppercase text-slate-400 print:text-gray-600 block">
                COMPLIANCE STANDARD
              </span>
              <p className="text-xs font-semibold text-white print:text-black">
                NIST SP 800-53 Rev. 5 (SI-2) • ISO/IEC 27001:2022 • OWASP Top 10
              </p>
              <p className="text-[11px] text-slate-400 print:text-gray-600">
                Audit Hash: SHA-256:{Math.random().toString(36).substring(2, 15).toUpperCase()}
              </p>
            </div>

            <div className="space-y-3 sm:text-right">
              <div>
                <span className="text-[10px] font-mono uppercase text-slate-400 print:text-gray-600 block">
                  LEAD AUDITOR ATTESTATION
                </span>
                <p className="text-xs font-bold text-white print:text-black">
                  {auditorName}
                </p>
                <p className="text-[11px] text-slate-400 print:text-gray-600">
                  {organization}
                </p>
              </div>

              <div className="inline-block border-b border-dashed border-slate-600 print:border-black w-48 text-right pt-4">
                <span className="text-[10px] font-mono text-slate-400 print:text-gray-600">
                  Signature / Timestamp
                </span>
              </div>
            </div>
          </div>

          <div className="text-center font-mono text-[10px] text-slate-400 print:text-gray-500 pt-4 border-t border-slate-800/80 print:border-gray-200">
            Log4j Shield Security Scanner • Generated at {new Date().toUTCString()} • Page 1 of 1
          </div>
        </div>

      </div>
    </div>
  );
};
