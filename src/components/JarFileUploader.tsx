import React, { useState, useRef } from 'react';
import {
  Archive,
  Upload,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  Info,
} from 'lucide-react';
import { CveRecord, DetectedArtifact } from '../types/log4j';
import { scanJarFile } from '../utils/jarScanner';

interface JarFileUploaderProps {
  cveDatabase: CveRecord[];
  targetJdk: 'Java 8+' | 'Java 7' | 'Java 6';
  onJarScanComplete: (artifacts: DetectedArtifact[], fileName: string) => void;
}

export const JarFileUploader: React.FC<JarFileUploaderProps> = ({
  cveDatabase,
  targetJdk,
  onJarScanComplete,
}) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [lastScannedFile, setLastScannedFile] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleProcessFile = async (file: File) => {
    setIsScanning(true);
    setScanMessage(`Unpacking and analyzing archive ${file.name} (${(file.size / (1024 * 1024)).toFixed(2)} MB)...`);

    try {
      const results = await scanJarFile(file, { cveDatabase, targetJdk });
      setLastScannedFile(file.name);
      onJarScanComplete(results, file.name);
      setScanMessage(
        results.length > 0
          ? `Analysis complete: identified ${results.length} Log4j component(s).`
          : `Scan complete: No Log4j artifacts detected in ${file.name}.`
      );
    } catch (err) {
      setScanMessage(`Failed to scan archive: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleProcessFile(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 space-y-6 backdrop-blur-sm">
      <div>
        <div className="flex items-center gap-2">
          <Archive className="w-5 h-5 text-amber-500" />
          <h2 className="text-base font-bold text-white">
            Binary JAR & WAR Archive Deep Inspector
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            Bytecode & Manifest Inspection
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Drop any compiled <code className="text-slate-300">.jar</code>, <code className="text-slate-300">.war</code>, or <code className="text-slate-300">.zip</code> archive.
          The engine unpacks the archive in-memory to verify <code className="text-slate-300">META-INF/pom.properties</code>, <code className="text-slate-300">MANIFEST.MF</code>, and crucially detects if the vulnerable bytecode class <code className="text-rose-400 font-mono">org.apache.logging.log4j.core.lookup.JndiLookup</code> is physically present or stripped.
        </p>
      </div>

      {/* Drag & Drop Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
          isDragging
            ? 'border-amber-500 bg-amber-950/20 scale-[0.99]'
            : 'border-slate-800 hover:border-slate-700 bg-slate-950/50 hover:bg-slate-950/80'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleProcessFile(e.target.files[0]);
            }
          }}
          accept=".jar,.war,.zip,.ear"
          className="hidden"
        />

        {isScanning ? (
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="w-10 h-10 text-amber-500 animate-spin" />
            <p className="text-sm font-mono text-slate-200">{scanMessage}</p>
            <span className="text-xs text-slate-500">Unpacking nested bytecode & searching JNDI lookup classes...</span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Upload className="w-8 h-8" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">
                Drag and drop your JAR, WAR, or ZIP file here
              </p>
              <p className="text-xs text-slate-400 mt-1">
                or click to browse local files (Supports Spring Boot fat JARs & multi-module archives)
              </p>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 bg-slate-900 px-3 py-1 rounded-full border border-slate-800">
              <span>Client-side verification</span>
              <span>•</span>
              <span>No files uploaded to external servers</span>
            </div>
          </div>
        )}
      </div>

      {/* Explanatory banner */}
      <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs space-y-2">
        <div className="flex items-center gap-2 font-semibold text-slate-300">
          <Info className="w-4 h-4 text-sky-400 shrink-0" />
          <span>Why inspect compiled JAR bytecode?</span>
        </div>
        <p className="text-slate-400 leading-relaxed pl-6">
          Many enterprise systems cannot recompile legacy applications immediately. The standard temporary workaround is to remove the vulnerable JNDI lookup class using <code className="text-slate-300 font-mono">zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class</code>.
          This inspector checks whether the dangerous class is actually absent, confirming whether temporary mitigation has succeeded.
        </p>
      </div>
    </div>
  );
};
