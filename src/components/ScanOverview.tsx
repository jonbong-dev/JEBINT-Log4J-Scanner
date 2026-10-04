import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  Flame,
  FileCheck,
  ArrowUpRight,
  Printer,
  Wrench,
  Clock,
  Layers,
  Gauge,
  Percent,
} from 'lucide-react';
import { ScanResult } from '../types/log4j';

interface ScanOverviewProps {
  scanResult: ScanResult;
  onOpenRemediation: () => void;
  onOpenReport: () => void;
}

export const ScanOverview: React.FC<ScanOverviewProps> = ({
  scanResult,
  onOpenRemediation,
  onOpenReport,
}) => {
  const isClean = scanResult.vulnerableArtifacts === 0 && scanResult.totalArtifacts > 0;
  const isVulnerable = scanResult.vulnerableArtifacts > 0;

  const highestCvss = Math.max(0, ...scanResult.artifacts.map((a) => a.highestCvss));

  // Security Compliance Score calculation: ratio of patched (safe) vs vulnerable artifacts
  const total = scanResult.totalArtifacts;
  const patched = scanResult.safeArtifacts;
  const vulnerable = scanResult.vulnerableArtifacts;

  const complianceScore = total > 0 ? Math.round((patched / total) * 100) : 100;

  const getScoreTheme = (score: number) => {
    if (score === 100) {
      return {
        text: 'text-emerald-400',
        bar: 'from-emerald-500 to-teal-400 shadow-emerald-500/30',
        bg: 'bg-emerald-950/20',
        border: 'border-emerald-500/30',
        badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
        label: 'FULL COMPLIANCE',
        desc: 'All identified Log4j dependencies meet or exceed safe version thresholds.',
      };
    }
    if (score >= 75) {
      return {
        text: 'text-teal-400',
        bar: 'from-teal-500 to-emerald-400 shadow-teal-500/30',
        bg: 'bg-teal-950/20',
        border: 'border-teal-500/30',
        badge: 'bg-teal-500/20 text-teal-300 border-teal-500/30',
        label: 'HIGH COMPLIANCE',
        desc: 'Majority of dependencies are patched; minor unpatched components remain.',
      };
    }
    if (score >= 50) {
      return {
        text: 'text-amber-400',
        bar: 'from-amber-500 to-yellow-400 shadow-amber-500/30',
        bg: 'bg-amber-950/20',
        border: 'border-amber-500/30',
        badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        label: 'MODERATE COMPLIANCE',
        desc: 'Significant proportion of components require CVE remediation.',
      };
    }
    return {
      text: 'text-rose-400',
      bar: 'from-rose-600 via-rose-500 to-amber-500 shadow-rose-500/30',
      bg: 'bg-rose-950/20',
      border: 'border-rose-500/30',
      badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      label: 'CRITICAL NON-COMPLIANCE',
      desc: 'Severe exposure to known Log4j CVEs. Immediate version upgrade required.',
    };
  };

  const theme = getScoreTheme(complianceScore);

  return (
    <div className="space-y-4">
      {/* Risk Alert Banner */}
      {isVulnerable && (
        <div className="relative overflow-hidden rounded-2xl border border-rose-500/40 bg-gradient-to-r from-rose-950/80 via-slate-900/90 to-rose-950/40 p-5 shadow-2xl shadow-rose-950/50">
          <div className="absolute -right-8 -top-8 w-40 h-40 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30 shrink-0">
                <Flame className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-500 text-white shadow-sm">
                    {scanResult.overallRiskLevel} RISK DETECTED
                  </span>
                  <span className="text-xs text-rose-300/80 font-mono">
                    Max CVSS: {highestCvss.toFixed(1)} / 10.0
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white mt-1">
                  Apache Log4j Vulnerabilities Identified in Project Scope
                </h3>
                <p className="text-sm text-slate-300 mt-0.5 max-w-2xl leading-relaxed">
                  Detected {scanResult.vulnerableArtifacts} vulnerable component{scanResult.vulnerableArtifacts > 1 ? 's' : ''} subject to critical exploits (Log4Shell / Remote Code Execution / DoS). Immediate version upgrade is required.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2.5 w-full md:w-auto shrink-0">
              <button
                onClick={onOpenRemediation}
                className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white font-semibold text-xs transition-all shadow-lg shadow-rose-600/30 hover:shadow-rose-600/50 active:scale-95"
              >
                <Wrench className="w-4 h-4" />
                Auto-Fix Manifest
              </button>
              <button
                onClick={onOpenReport}
                className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs transition-all active:scale-95"
              >
                <Printer className="w-4 h-4 text-rose-400" />
                Print Audit Report
              </button>
            </div>
          </div>
        </div>
      )}

      {isClean && (
        <div className="rounded-2xl border border-emerald-500/30 bg-gradient-to-r from-emerald-950/40 via-slate-900 to-emerald-950/20 p-5">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    Compliant & Hardened
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Zero Known Log4j CVEs Matched
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white mt-1">
                  All Scanned Log4j Dependencies Are Clean
                </h3>
                <p className="text-sm text-slate-300">
                  Detected dependencies satisfy secure baseline standards. You can generate a compliance proof report.
                </p>
              </div>
            </div>

            <button
              onClick={onOpenReport}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-500/30 text-xs font-semibold"
            >
              <FileCheck className="w-4 h-4 text-emerald-400" />
              Generate Compliance Certificate
            </button>
          </div>
        </div>
      )}

      {/* Security Compliance Score with Progress Bar */}
      <div className={`rounded-2xl border ${theme.border} ${theme.bg} p-5 backdrop-blur-sm transition-all`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
          <div className="flex items-center gap-2.5">
            <div className={`p-2 rounded-xl bg-slate-950/80 border border-slate-800 ${theme.text}`}>
              <Gauge className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  Security Compliance Score
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${theme.badge}`}>
                  {theme.label}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {theme.desc}
              </p>
            </div>
          </div>

          <div className="flex items-baseline gap-2 shrink-0">
            <span className={`text-3xl font-extrabold font-mono tracking-tight ${theme.text}`}>
              {complianceScore}%
            </span>
            <span className="text-xs font-mono text-slate-400">
              ({patched}/{total} Patched)
            </span>
          </div>
        </div>

        {/* Progress Bar Container */}
        <div className="space-y-1.5 pt-1">
          <div className="relative w-full h-3.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800/80 shadow-inner">
            <div
              className={`h-full rounded-full bg-gradient-to-r ${theme.bar} shadow-sm transition-all duration-700 ease-out`}
              style={{ width: `${complianceScore}%` }}
            />
          </div>

          {/* Scale labels and breakdown */}
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-0.5 pt-1">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>Patched: <strong className="text-emerald-400 font-semibold">{patched}</strong> ({total > 0 ? Math.round((patched / total) * 100) : 100}%)</span>
            </span>

            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-400"></span>
              <span>Vulnerable: <strong className="text-rose-400 font-semibold">{vulnerable}</strong> ({total > 0 ? Math.round((vulnerable / total) * 100) : 0}%)</span>
            </span>

            <span className="hidden sm:inline text-slate-400">
              Total Audited: <strong className="text-slate-200">{total}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TOTAL SCANNED</span>
            <Layers className="w-4 h-4 text-slate-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {scanResult.totalArtifacts}
            </span>
            <span className="text-xs text-slate-400">log4j libraries</span>
          </div>
        </div>

        <div className={`p-4 rounded-xl border backdrop-blur-sm ${
          scanResult.vulnerableArtifacts > 0
            ? 'bg-rose-950/20 border-rose-500/30 text-rose-300'
            : 'bg-slate-900/60 border-slate-800 text-slate-400'
        }`}>
          <div className="flex items-center justify-between text-xs font-mono">
            <span>VULNERABLE</span>
            <ShieldAlert className={`w-4 h-4 ${scanResult.vulnerableArtifacts > 0 ? 'text-rose-400' : 'text-slate-500'}`} />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${scanResult.vulnerableArtifacts > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
              {scanResult.vulnerableArtifacts}
            </span>
            <span className="text-xs text-slate-400">requiring patch</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>HIGHEST CVSS</span>
            <Flame className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${highestCvss >= 9 ? 'text-rose-400' : highestCvss >= 7 ? 'text-amber-400' : 'text-slate-200'}`}>
              {highestCvss > 0 ? highestCvss.toFixed(1) : '0.0'}
            </span>
            <span className="text-xs text-slate-400">/ 10.0 scale</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TARGET JDK FIX</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-base font-bold font-mono text-emerald-400">
              {scanResult.targetJdk === 'Java 8+' ? 'v2.24.3 / 2.17.1' : scanResult.targetJdk === 'Java 7' ? 'v2.12.4' : 'v2.3.2'}
            </span>
            <span className="block text-[11px] text-slate-400">{scanResult.targetJdk} Runtime</span>
          </div>
        </div>
      </div>
    </div>
  );
};
