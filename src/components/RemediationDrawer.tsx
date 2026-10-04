import React, { useState } from 'react';
import {
  Wrench,
  Check,
  Copy,
  Download,
  Terminal,
  ShieldCheck,
  FileCode,
  ArrowRight,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';
import { DetectedArtifact } from '../types/log4j';
import { generateRemediationPlan, autoPatchContent } from '../utils/remediator';

interface RemediationDrawerProps {
  originalContent: string;
  artifacts: DetectedArtifact[];
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
  onApplyPatchedContent: (newContent: string) => void;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  originalContent,
  artifacts,
  targetJdk,
  onApplyPatchedContent,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const vulnerableArtifacts = artifacts.filter((a) => a.isVulnerable);

  const { patchedContent, replacedCount } = autoPatchContent(originalContent, artifacts);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadPatchedFile = () => {
    const isGradle = originalContent.includes('dependencies') && !originalContent.includes('<project');
    const fileName = isGradle ? 'build.gradle' : 'pom.xml';
    const blob = new Blob([patchedContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `patched-${fileName}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header banner */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Wrench className="w-5 h-5 text-rose-500" />
              <h2 className="text-base font-bold text-white">
                Automated Remediation & Manifest Auto-Fixer
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Patch Generator
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Upgrades vulnerable dependencies to safe patched versions matching your {targetJdk} runtime policy.
              Directly replaces versions in your manifest or copy the individual snippets below.
            </p>
          </div>

          {replacedCount > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => onApplyPatchedContent(patchedContent)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white text-xs font-semibold shadow-lg shadow-emerald-950/40 active:scale-95 transition-all"
              >
                <Sparkles className="w-4 h-4" />
                Apply Auto-Patch ({replacedCount} updated)
              </button>
              <button
                onClick={downloadPatchedFile}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 active:scale-95"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                Download Patched Manifest
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Auto-patched Manifest Preview */}
      {originalContent && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold text-white">
                Patched Manifest Code Preview
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                {replacedCount > 0 ? `${replacedCount} Safe Version Substitutions Applied` : 'Already Secure / No Patches Needed'}
              </span>
            </div>

            <button
              onClick={() => copyToClipboard(patchedContent, 'patched-manifest')}
              className="flex items-center gap-1 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-2.5 py-1 rounded-lg border border-slate-700"
            >
              {copiedKey === 'patched-manifest' ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" /> Copied!
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3 text-slate-400" /> Copy Patched Content
                </>
              )}
            </button>
          </div>

          <pre className="p-4 rounded-xl bg-slate-950 text-xs font-mono text-slate-200 overflow-x-auto max-h-72 border border-slate-800/80">
            {patchedContent}
          </pre>
        </div>
      )}

      {/* Per-artifact Remediation Cards */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <Terminal className="w-4 h-4 text-rose-400" />
          Technical Remediation Directives ({vulnerableArtifacts.length})
        </h3>

        {vulnerableArtifacts.map((artifact) => {
          const plan = generateRemediationPlan(artifact, targetJdk);

          return (
            <div
              key={artifact.id}
              className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-bold text-white">
                    {artifact.name}
                  </span>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-rose-400 font-semibold">{artifact.version}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-emerald-400 font-bold">{plan.recommendedVersion}</span>
                  </div>
                </div>

                <span className="text-xs font-mono text-slate-400">
                  Target Runtime: {targetJdk}
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {plan.explanation}
              </p>

              {/* Code Snippets Tabs / Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {/* Maven Snippet */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono text-slate-400 font-bold">
                      Maven pom.xml Dependency
                    </span>
                    <button
                      onClick={() => copyToClipboard(plan.pomSnippet, `pom-${artifact.id}`)}
                      className="text-[11px] font-mono text-slate-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedKey === `pom-${artifact.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="text-xs font-mono text-emerald-400 overflow-x-auto p-2 bg-slate-900/60 rounded-lg">
                    {plan.pomSnippet}
                  </pre>
                </div>

                {/* Gradle Snippet */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono text-slate-400 font-bold">
                      Gradle build.gradle
                    </span>
                    <button
                      onClick={() => copyToClipboard(plan.gradleSnippet, `gradle-${artifact.id}`)}
                      className="text-[11px] font-mono text-slate-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedKey === `gradle-${artifact.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="text-xs font-mono text-emerald-400 overflow-x-auto p-2 bg-slate-900/60 rounded-lg">
                    {plan.gradleSnippet}
                  </pre>
                </div>
              </div>

              {/* Workaround & Class Removal */}
              {!plan.isLog4j1x && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono text-amber-400 font-bold">
                        Temporary JVM Flag (v2.10 - 2.14.1 only)
                      </span>
                      <button
                        onClick={() => copyToClipboard(plan.jvmFlagMitigation, `jvm-${artifact.id}`)}
                        className="text-[11px] font-mono text-slate-400 hover:text-white"
                      >
                        {copiedKey === `jvm-${artifact.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <pre className="text-xs font-mono text-amber-300 p-2 bg-slate-900/50 rounded-lg">
                      {plan.jvmFlagMitigation}
                    </pre>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono text-amber-400 font-bold">
                        JAR Class Strip Command (JndiLookup)
                      </span>
                      <button
                        onClick={() => copyToClipboard(plan.classRemovalCommand, `strip-${artifact.id}`)}
                        className="text-[11px] font-mono text-slate-400 hover:text-white"
                      >
                        {copiedKey === `strip-${artifact.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <pre className="text-xs font-mono text-amber-300 p-2 bg-slate-900/50 rounded-lg">
                      {plan.classRemovalCommand}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
