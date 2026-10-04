import React from 'react';
import {
  ShieldAlert,
  FileCode2,
  Archive,
  Database,
  Wrench,
  Printer,
  Terminal,
  Layers,
} from 'lucide-react';
import { ScanTab } from '../types/log4j';

interface NavbarProps {
  currentTab: ScanTab;
  onTabChange: (tab: ScanTab) => void;
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
  onJdkChange: (jdk: 'Java 8+' | 'Java 7' | 'Java 6') => void;
  vulnerableCount: number;
  onTriggerPrint: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onTabChange,
  targetJdk,
  onJdkChange,
  vulnerableCount,
  onTriggerPrint,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur-md sticky top-0 z-40 print:hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & title */}
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-rose-600 via-rose-500 to-amber-500 flex items-center justify-center shadow-lg shadow-rose-500/20 ring-1 ring-white/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  Log4j Shield
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-semibold uppercase tracking-wider">
                  SCA & Audit
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono hidden sm:block">
                CVE-2021-44228 / 45046 / 45105 / 44832 Detector
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-950/60 p-1 rounded-xl border border-slate-800/80">
            <button
              onClick={() => onTabChange('scanner')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'scanner'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileCode2 className="w-3.5 h-3.5" />
              Manifest Scanner
              {vulnerableCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 text-[10px] rounded-full bg-rose-950 text-rose-300 font-bold border border-rose-500/40">
                  {vulnerableCount}
                </span>
              )}
            </button>

            <button
              onClick={() => onTabChange('jar_analyzer')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'jar_analyzer'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Archive className="w-3.5 h-3.5" />
              JAR / Archive Scan
            </button>

            <button
              onClick={() => onTabChange('cve_manager')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'cve_manager'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              CVE Database & Rules
            </button>

            <button
              onClick={() => onTabChange('remediation')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'remediation'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Wrench className="w-3.5 h-3.5" />
              Auto-Fix & Patch
            </button>

            <button
              onClick={() => onTabChange('audit_report')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'audit_report'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Printer className="w-3.5 h-3.5" />
              Audit Report
            </button>

            <button
              onClick={() => onTabChange('powershell_exe')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                currentTab === 'powershell_exe'
                  ? 'bg-rose-500 text-white shadow-sm shadow-rose-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              PowerShell & EXE
            </button>
          </nav>

          {/* Right side controls: Target JDK & Print trigger */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 bg-slate-950/80 px-2.5 py-1.5 rounded-lg border border-slate-800">
              <Layers className="w-3.5 h-3.5 text-slate-400" />
              <label htmlFor="jdk-selector" className="text-[11px] text-slate-400 font-mono hidden lg:inline">
                Target JDK:
              </label>
              <select
                id="jdk-selector"
                value={targetJdk}
                onChange={(e) => onJdkChange(e.target.value as 'Java 8+' | 'Java 7' | 'Java 6')}
                className="bg-transparent text-xs font-mono font-medium text-amber-300 focus:outline-none cursor-pointer"
              >
                <option value="Java 8+" className="bg-slate-900 text-white">Java 8+ (v2.24.3 / 2.17.1)</option>
                <option value="Java 7" className="bg-slate-900 text-white">Java 7 (v2.12.4)</option>
                <option value="Java 6" className="bg-slate-900 text-white">Java 6 (v2.3.2)</option>
              </select>
            </div>

            <button
              onClick={onTriggerPrint}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/80 transition-all shadow-sm hover:border-slate-600 active:scale-95"
              title="Open Printable Security Audit Report"
            >
              <Printer className="w-3.5 h-3.5 text-rose-400" />
              <span className="hidden sm:inline">Print Report</span>
            </button>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="flex md:hidden items-center justify-around py-2 border-t border-slate-800/60 text-xs overflow-x-auto gap-2">
          <button
            onClick={() => onTabChange('scanner')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'scanner' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
          >
            Scanner
          </button>
          <button
            onClick={() => onTabChange('jar_analyzer')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'jar_analyzer' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
          >
            JAR Archive
          </button>
          <button
            onClick={() => onTabChange('cve_manager')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'cve_manager' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
          >
            CVE Rules
          </button>
          <button
            onClick={() => onTabChange('remediation')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'remediation' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
          >
            Auto-Fix
          </button>
          <button
            onClick={() => onTabChange('audit_report')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'audit_report' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
          >
            Print Report
          </button>
          <button
            onClick={() => onTabChange('powershell_exe')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap ${currentTab === 'powershell_exe' ? 'text-amber-400 font-bold' : 'text-slate-400'}`}
          >
            PS1 / EXE
          </button>
        </div>
      </div>
    </header>
  );
};
