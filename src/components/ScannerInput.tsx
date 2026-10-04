import React, { useState, useRef } from 'react';
import {
  Upload,
  Code2,
  Play,
  RotateCcw,
  Sparkles,
  FileText,
  Search,
  CheckCircle,
} from 'lucide-react';
import { SAMPLE_MANIFESTS, SampleManifest } from '../data/sampleManifests';

interface ScannerInputProps {
  inputContent: string;
  onInputChange: (val: string) => void;
  onRunScan: () => void;
  onQuickVersionCheck: (version: string) => void;
}

export const ScannerInput: React.FC<ScannerInputProps> = ({
  inputContent,
  onInputChange,
  onRunScan,
  onQuickVersionCheck,
}) => {
  const [quickVersion, setQuickVersion] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) {
        onInputChange(text);
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const loadSample = (sample: SampleManifest) => {
    onInputChange(sample.content);
  };

  const handleQuickCheck = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickVersion.trim()) {
      onQuickVersionCheck(quickVersion.trim());
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-5 space-y-4 backdrop-blur-sm">
      {/* Top row: Section Header & Presets */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Code2 className="w-5 h-5 text-rose-500" />
            Dependency Manifest & Code Scanner
          </h2>
          <p className="text-xs text-slate-400">
            Paste Maven <code className="text-slate-300">pom.xml</code>, Gradle <code className="text-slate-300">build.gradle</code>, dependency lockfiles, or paste jar lists.
          </p>
        </div>

        {/* Sample Presets */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-slate-400 mr-1 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" /> Test Presets:
          </span>
          {SAMPLE_MANIFESTS.map((sample) => (
            <button
              key={sample.id}
              onClick={() => loadSample(sample)}
              className="px-2.5 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 font-mono transition-all hover:border-slate-500 active:scale-95"
              title={sample.description}
            >
              {sample.name.split(' - ')[0]}
              <span className={`ml-1.5 px-1.5 py-0.2 rounded text-[10px] border ${sample.badgeColor}`}>
                {sample.badge}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Drag & drop or paste area */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`relative rounded-xl border-2 transition-all ${
          isDragging
            ? 'border-rose-500 bg-rose-950/20'
            : 'border-dashed border-slate-800 hover:border-slate-700 bg-slate-950/60'
        }`}
      >
        <textarea
          value={inputContent}
          onChange={(e) => onInputChange(e.target.value)}
          placeholder={`<!-- Paste your pom.xml, build.gradle, or dependency tree here -->\n\n<dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.14.1</version>\n</dependency>`}
          className="w-full h-56 p-4 bg-transparent text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none resize-y selection:bg-rose-500/30 selection:text-white"
          spellCheck={false}
        />

        <div className="absolute right-3 bottom-3 flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
            accept=".xml,.gradle,.kts,.txt,.lock,.json"
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700/80 backdrop-blur-sm transition-all"
          >
            <Upload className="w-3.5 h-3.5 text-slate-400" />
            Upload File
          </button>
        </div>
      </div>

      {/* Action Row & Quick Version Checker */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
        {/* Ad-hoc version checker */}
        <form onSubmit={handleQuickCheck} className="flex items-center gap-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={quickVersion}
              onChange={(e) => setQuickVersion(e.target.value)}
              placeholder="Quick check version (e.g. 2.14.1)"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono text-white placeholder:text-slate-500 focus:outline-none focus:border-rose-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg border border-slate-700 active:scale-95"
          >
            Check
          </button>
        </form>

        {/* Scan & Clear Buttons */}
        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          {inputContent && (
            <button
              onClick={() => onInputChange('')}
              className="px-3 py-2 text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Clear
            </button>
          )}

          <button
            onClick={onRunScan}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-amber-500 hover:from-rose-500 hover:to-amber-400 text-white font-semibold text-xs transition-all shadow-lg shadow-rose-600/30 active:scale-95"
          >
            <Play className="w-4 h-4 fill-white" />
            Scan Dependencies
          </button>
        </div>
      </div>
    </div>
  );
};
