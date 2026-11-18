'use client';

import { AlertCircle, ArrowRight, FileText, Globe, Hash, Loader2, Search, Shield, ShieldCheck, UploadCloud } from 'lucide-react';
import { useMemo, useState } from 'react';
import ResultCard, { ThreatSummary } from './ResultCard';

const tabs = [
  { id: 'file', label: 'FILE', icon: FileText },
  { id: 'url', label: 'URL', icon: Globe },
  { id: 'search', label: 'SEARCH', icon: Search },
  { id: 'ip', label: 'IP', icon: Shield },
  { id: 'domain', label: 'DOMAIN', icon: Globe },
  { id: 'hash', label: 'HASH', icon: Hash },
] as const;

type SearchType = (typeof tabs)[number]['id'];

const placeholderByType: Record<SearchType, string> = {
  file: 'Choose or drag a file to scan',
  url: 'https://example.com',
  search: 'Search by domain, file hash, IP, or URL',
  ip: '8.8.8.8',
  domain: 'example.com',
  hash: '91c1d3f95d... or SHA-256 hash',
};

export default function SearchHub() {
  const [activeTab, setActiveTab] = useState<SearchType>('file');
  const [query, setQuery] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatSummary | null>(null);

  const tabLabel = useMemo(
    () => tabs.find((tab) => tab.id === activeTab)?.label ?? 'SEARCH',
    [activeTab],
  );

  const handleScan = async () => {
    if (activeTab === 'file' && !selectedFile) {
      setError('Please choose a file to scan.');
      return;
    }

    const target = activeTab === 'file' ? selectedFile?.name ?? '' : query.trim();
    if (!target) {
      setError(`Please enter a valid ${tabLabel.toLowerCase()} value.`);
      return;
    }

    setError(null);
    setIsLoading(true);
    setResult(null);

    try {
      const payload = activeTab === 'file'
        ? (() => {
            const form = new FormData();
            form.append('file', selectedFile as File);
            return form;
          })()
        : JSON.stringify({ type: activeTab, query: target });

      const response = await fetch(activeTab === 'file' ? '/api/scan-file' : '/api/search', {
        method: 'POST',
        body: activeTab === 'file' ? payload : payload,
        headers: activeTab === 'file' ? undefined : { 'Content-Type': 'application/json' },
      });

      const json = await response.json();

      if (!response.ok) {
        throw new Error(json?.error ?? 'The search request failed.');
      }

      setResult({
        target: json.target ?? target,
        verdict: json.verdict ?? 'undetected',
        malicious: json.malicious ?? 0,
        suspicious: json.suspicious ?? 0,
        harmless: json.harmless ?? 0,
        undetected: json.undetected ?? 0,
        totalEngines: json.totalEngines ?? 0,
        summary: json.summary ?? 'Threat analysis completed.',
        vendors: json.vendors ?? [],
        hashes: json.hashes ?? {},
        intelligence: json.intelligence ?? {},
      });
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'Unknown error while scanning.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div className="rounded-3xl border border-slate-700/80 bg-slate-900/70 p-3 shadow-[0_0_0_1px_rgba(14,165,233,0.14)] backdrop-blur-sm">
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 rounded-xl px-4 py-3 text-xs font-semibold uppercase tracking-[0.2em] transition ${
                activeTab === id
                  ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                  : 'bg-slate-950/60 text-slate-300 hover:text-white'
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>

        <div className="mt-5 space-y-4">
          {activeTab === 'file' ? (
            <div className="space-y-4">
              <label className="flex min-h-[110px] cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed border-slate-700 bg-slate-950/60 text-center transition hover:border-emerald-500/60 hover:bg-slate-900/80">
                <input
                  type="file"
                  className="hidden"
                  onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
                />
                <UploadCloud className="mb-3 h-9 w-9 text-emerald-400" />
                <span className="text-lg font-medium text-slate-200">{selectedFile ? selectedFile.name : 'Upload suspicious file'}</span>
                <span className="mt-2 text-sm text-slate-400">Click to choose a file or drag and drop it here.</span>
              </label>
            </div>
          ) : (
            <div className="relative">
              <Search className="pointer-events-none absolute left-5 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={placeholderByType[activeTab]}
                className="h-16 w-full rounded-2xl border border-slate-700 bg-slate-950/80 pl-12 pr-4 text-base text-white outline-none transition placeholder:text-slate-500 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>
          )}

          <button
            type="button"
            onClick={handleScan}
            disabled={isLoading || (activeTab === 'file' && !selectedFile)}
            className="inline-flex w-full items-center justify-center gap-2 rounded-2xl bg-emerald-500 px-6 py-4 text-base font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-emerald-800 disabled:text-slate-400"
          >
            {isLoading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                {activeTab === 'file' ? 'Analyze File' : `Search ${tabLabel}`}
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>

          {error ? (
            <div className="flex items-center gap-3 rounded-2xl border border-rose-500/35 bg-rose-500/10 p-4 text-sm text-rose-200">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          ) : null}
        </div>
      </div>

      <ResultCard result={result} />
    </div>
  );
}
