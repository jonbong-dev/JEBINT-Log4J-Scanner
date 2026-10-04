import React, { useState } from 'react';
import {
  Database,
  Edit3,
  Plus,
  RotateCcw,
  Check,
  X,
  AlertTriangle,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Save,
  Search,
} from 'lucide-react';
import { CveRecord, CveSeverity } from '../types/log4j';
import { DEFAULT_LOG4J_CVES } from '../data/cveDatabase';

interface CveDatabaseManagerProps {
  cveDatabase: CveRecord[];
  onUpdateCve: (updated: CveRecord) => void;
  onAddCve: (newCve: CveRecord) => void;
  onResetCves: () => void;
  onToggleCve: (id: string) => void;
}

export const CveDatabaseManager: React.FC<CveDatabaseManagerProps> = ({
  cveDatabase,
  onUpdateCve,
  onAddCve,
  onResetCves,
  onToggleCve,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [editingCveId, setEditingCveId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<CveRecord>>({});
  const [isAddingNew, setIsAddingNew] = useState(false);

  // New CVE template state
  const [newCve, setNewCve] = useState<Partial<CveRecord>>({
    id: `CVE-2026-${Math.floor(1000 + Math.random() * 9000)}`,
    name: 'Custom Log4j Security Advisory',
    title: 'Custom Enterprise Patch Requirement',
    cvssScore: 8.5,
    severity: 'HIGH',
    publishDate: new Date().toISOString().split('T')[0],
    affectedVersionDesc: 'Log4j >= 2.0.0 and < 2.24.3',
    minAffectedVersion: '2.0.0',
    maxAffectedVersion: '2.24.2',
    recommendedVersion: '2.24.3',
    runtimeTargetVersions: {
      java8Plus: '2.24.3',
      java7: '2.12.4',
      java6: '2.3.2',
      log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
    },
    description: 'Custom corporate rule requiring minimum baseline Log4j version.',
    impact: 'Security policy compliance failure.',
    mitigation: 'Upgrade library to specified organizational target.',
    references: ['https://logging.apache.org/log4j/2.x/'],
    enabled: true,
    isCustom: true,
  });

  const handleStartEdit = (cve: CveRecord) => {
    setEditingCveId(cve.id);
    setEditForm({
      ...cve,
      runtimeTargetVersions: { ...cve.runtimeTargetVersions },
    });
  };

  const handleSaveEdit = () => {
    if (!editingCveId) return;
    const existing = cveDatabase.find((c) => c.id === editingCveId);
    if (!existing) return;

    const updated: CveRecord = {
      ...existing,
      ...editForm,
      id: existing.id,
      runtimeTargetVersions: {
        ...existing.runtimeTargetVersions,
        ...(editForm.runtimeTargetVersions || {}),
      },
    };

    onUpdateCve(updated);
    setEditingCveId(null);
    setEditForm({});
  };

  const handleCreateNew = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCve.id) return;

    const fullCve: CveRecord = {
      id: newCve.id.trim(),
      name: newCve.name || 'Custom Advisory',
      title: newCve.title || 'Custom Security Rule',
      cvssScore: Number(newCve.cvssScore) || 7.5,
      severity: (newCve.severity as CveSeverity) || 'HIGH',
      publishDate: newCve.publishDate || new Date().toISOString().split('T')[0],
      affectedVersionDesc: newCve.affectedVersionDesc || 'Custom defined range',
      minAffectedVersion: newCve.minAffectedVersion || '',
      maxAffectedVersion: newCve.maxAffectedVersion || '',
      isAffectedPredicate: (v: string) => true,
      recommendedVersion: newCve.recommendedVersion || '2.24.3',
      runtimeTargetVersions: {
        java8Plus: newCve.recommendedVersion || '2.24.3',
        java7: '2.12.4',
        java6: '2.3.2',
        log4j1xMigration: 'ch.qos.reload4j:reload4j:1.2.25',
      },
      description: newCve.description || '',
      impact: newCve.impact || '',
      mitigation: newCve.mitigation || '',
      references: newCve.references || [],
      isCustom: true,
      enabled: true,
    };

    onAddCve(fullCve);
    setIsAddingNew(false);
  };

  const filteredCves = cveDatabase.filter(
    (c) =>
      c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-rose-500" />
              <h2 className="text-base font-bold text-white">
                Log4j CVE Database & Target Upgrade Rules
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Customizable Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Modify detection parameters, update recommended fixed versions per CVE (e.g. override to corporate standards like <code className="text-slate-300">2.24.3</code>), or register custom enterprise security policies.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setIsAddingNew(!isAddingNew)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              {isAddingNew ? 'Cancel New CVE' : 'Add Custom CVE Rule'}
            </button>
            <button
              onClick={onResetCves}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition-all"
              title="Reset all rules to official Apache Security Advisory defaults"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset to Defaults
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="mt-4 relative max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE ID (e.g. CVE-2021-44228), keywords..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950/80 border border-slate-800 rounded-xl text-xs font-mono text-white placeholder:text-slate-500 focus:outline-none focus:border-rose-500"
          />
        </div>
      </div>

      {/* Add New CVE Modal/Drawer Form */}
      {isAddingNew && (
        <form
          onSubmit={handleCreateNew}
          className="rounded-2xl border border-rose-500/40 bg-slate-900/90 p-6 space-y-4 shadow-xl"
        >
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Plus className="w-4 h-4 text-rose-400" />
              Define New Log4j Security Advisory / Policy Rule
            </h3>
            <button
              type="button"
              onClick={() => setIsAddingNew(false)}
              className="text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">CVE / Advisory Identifier</label>
              <input
                type="text"
                required
                value={newCve.id}
                onChange={(e) => setNewCve({ ...newCve, id: e.target.value })}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-rose-500"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Common Advisory Name</label>
              <input
                type="text"
                required
                value={newCve.name}
                onChange={(e) => setNewCve({ ...newCve, name: e.target.value })}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-rose-500"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Severity & CVSS Score</label>
              <div className="flex gap-2">
                <select
                  value={newCve.severity}
                  onChange={(e) => setNewCve({ ...newCve, severity: e.target.value as CveSeverity })}
                  className="px-2 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={newCve.cvssScore}
                  onChange={(e) => setNewCve({ ...newCve, cvssScore: parseFloat(e.target.value) })}
                  className="w-20 px-2 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono"
                />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Min Affected Version</label>
              <input
                type="text"
                placeholder="e.g. 2.0.0"
                value={newCve.minAffectedVersion}
                onChange={(e) => setNewCve({ ...newCve, minAffectedVersion: e.target.value })}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Max Affected Version</label>
              <input
                type="text"
                placeholder="e.g. 2.14.1"
                value={newCve.maxAffectedVersion}
                onChange={(e) => setNewCve({ ...newCve, maxAffectedVersion: e.target.value })}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Target Recommended Version</label>
              <input
                type="text"
                placeholder="e.g. 2.24.3"
                value={newCve.recommendedVersion}
                onChange={(e) => setNewCve({ ...newCve, recommendedVersion: e.target.value })}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400 font-semibold"
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">Description & Impact</label>
            <textarea
              rows={2}
              value={newCve.description}
              onChange={(e) => setNewCve({ ...newCve, description: e.target.value })}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsAddingNew(false)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
            >
              Save Rule to Engine
            </button>
          </div>
        </form>
      )}

      {/* CVE Records List */}
      <div className="grid grid-cols-1 gap-4">
        {filteredCves.map((cve) => {
          const isEditing = editingCveId === cve.id;

          return (
            <div
              key={cve.id}
              className={`rounded-2xl border transition-all ${
                cve.enabled
                  ? 'border-slate-800 bg-slate-900/60'
                  : 'border-slate-800/40 bg-slate-950/40 opacity-60'
              }`}
            >
              <div className="p-5 space-y-3">
                {/* Top bar */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => onToggleCve(cve.id)}
                      className={`p-1 rounded-md border text-xs font-mono transition-all ${
                        cve.enabled
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                      title={cve.enabled ? 'Click to disable rule in scanner' : 'Click to enable rule in scanner'}
                    >
                      {cve.enabled ? <ShieldCheck className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
                    </button>

                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-white">
                          {cve.id}
                        </span>
                        <span className="text-xs text-slate-300 font-semibold">
                          {cve.name}
                        </span>
                        {cve.isCustom && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            Custom
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-slate-400">{cve.title}</span>
                    </div>
                  </div>

                  {/* Badges & Actions */}
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                        cve.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                          : cve.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-sky-500/20 text-sky-300 border-sky-500/30'
                      }`}
                    >
                      CVSS {cve.cvssScore.toFixed(1)} {cve.severity}
                    </span>

                    {!isEditing ? (
                      <button
                        onClick={() => handleStartEdit(cve)}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700"
                        title="Edit Target Version and Parameters"
                      >
                        <Edit3 className="w-3 h-3 text-rose-400" />
                        Edit Rule
                      </button>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={handleSaveEdit}
                          className="flex items-center gap-1 px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
                        >
                          <Save className="w-3 h-3" />
                          Save
                        </button>
                        <button
                          onClick={() => setEditingCveId(null)}
                          className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Edit Form Body or Normal Display */}
                {isEditing ? (
                  <div className="pt-3 border-t border-slate-800/80 space-y-3 bg-slate-950/60 p-4 rounded-xl">
                    <p className="text-xs text-rose-400 font-mono font-semibold">
                      Configure Target Upgrade Versions & Detection Ranges for {cve.id}
                    </p>

                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          Default Recommended Version
                        </label>
                        <input
                          type="text"
                          value={editForm.recommendedVersion || ''}
                          onChange={(e) =>
                            setEditForm({ ...editForm, recommendedVersion: e.target.value })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-emerald-300 font-bold"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          Java 8+ Target Version
                        </label>
                        <input
                          type="text"
                          value={editForm.runtimeTargetVersions?.java8Plus || ''}
                          onChange={(e) =>
                            setEditForm({
                              ...editForm,
                              runtimeTargetVersions: {
                                ...editForm.runtimeTargetVersions!,
                                java8Plus: e.target.value,
                              },
                            })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-200"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          Java 7 Target Version
                        </label>
                        <input
                          type="text"
                          value={editForm.runtimeTargetVersions?.java7 || ''}
                          onChange={(e) =>
                            setEditForm({
                              ...editForm,
                              runtimeTargetVersions: {
                                ...editForm.runtimeTargetVersions!,
                                java7: e.target.value,
                              },
                            })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-200"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          CVSS Score (0 - 10)
                        </label>
                        <input
                          type="number"
                          step="0.1"
                          min="0"
                          max="10"
                          value={editForm.cvssScore || 0}
                          onChange={(e) =>
                            setEditForm({ ...editForm, cvssScore: parseFloat(e.target.value) })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-amber-300"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          Affected Version Description
                        </label>
                        <input
                          type="text"
                          value={editForm.affectedVersionDesc || ''}
                          onChange={(e) =>
                            setEditForm({ ...editForm, affectedVersionDesc: e.target.value })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] font-mono text-slate-400 block mb-1">
                          Remediation Summary / Mitigation
                        </label>
                        <input
                          type="text"
                          value={editForm.mitigation || ''}
                          onChange={(e) =>
                            setEditForm({ ...editForm, mitigation: e.target.value })
                          }
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200"
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {cve.description}
                    </p>

                    {/* Metadata chips */}
                    <div className="pt-2 flex flex-wrap items-center gap-3 text-xs font-mono">
                      <div className="bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800/80">
                        <span className="text-slate-500">AFFECTED: </span>
                        <span className="text-rose-400 font-semibold">{cve.affectedVersionDesc}</span>
                      </div>

                      <div className="bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800/80">
                        <span className="text-slate-500">TARGET PATCH: </span>
                        <span className="text-emerald-400 font-bold">{cve.recommendedVersion}</span>
                      </div>

                      <div className="bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800/80 hidden sm:block">
                        <span className="text-slate-500">RUNTIME TARGETS: </span>
                        <span className="text-slate-300">
                          Java 8+ ({cve.runtimeTargetVersions.java8Plus}) | Java 7 ({cve.runtimeTargetVersions.java7})
                        </span>
                      </div>

                      {cve.references.length > 0 && (
                        <a
                          href={cve.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px]"
                        >
                          NVD Advisory <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
